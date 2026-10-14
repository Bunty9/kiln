//! The runner console, normalised: one parsed line per forge runner log line. The VM state machine
//! (forward-only, in `vm::apply_line`) acts on the result; this module only recognises lines.

use super::Kind;

#[derive(PartialEq, Eq, Debug)]
pub enum Line {
    /// `kiln: hostkey ...` from the guest's own journal, whatever the forge.
    Hostkey(String),
    Listening,
    Running(String),
    /// The runner's result text as printed (not validated: unknown words are kept).
    Completed(String),
    RunnerUpdate,
    /// A gated forge's runner took a job: the forge's job id as printed. Not validated here.
    JobStart(String),
    /// Gitea: the server no longer knows this ephemeral runner (its job is over, or it was deleted). The daemon
    /// retries forever and never exits, so the host stops waiting.
    Unregistered,
    /// Gitea: kiln-job prints this when an exec gate process died before the verdict. The host kills the VM.
    GateDead,
}

/// Recognises one console line. Trailing whitespace is ignored.
pub fn parse_line(kind: Kind, line: &str) -> Option<Line> {
    let line = line.trim_end();
    // A job name is job-controlled text on the runner's `received` line: that line is a job start whatever it says (R2 L-1).
    if kind == Kind::GitLab
        && let Some(start @ Line::JobStart(_)) = gitlab_line(line)
    {
        return Some(start);
    }
    // The guest's journal prefixes console lines ("[ 32.2] kiln-job[1395]: kiln: hostkey ...").
    if let Some((_, k)) = line.split_once("kiln: hostkey ") {
        return Some(Line::Hostkey(k.chars().filter(|c| !c.is_control()).take(200).collect()));
    }
    match kind {
        Kind::GitHub => {
            if line.contains("Listening for Jobs") {
                Some(Line::Listening)
            } else if let Some((_, job)) = line.split_once("Running job: ") {
                Some(Line::Running(job.trim().to_string()))
            } else if let Some((_, result)) = line.split_once("completed with result: ") {
                Some(Line::Completed(result.trim().to_string()))
            } else if line.contains("Runner update") {
                Some(Line::RunnerUpdate)
            } else {
                None
            }
        }
        Kind::GitLab => gitlab_line(line),
        Kind::Gitea => gitea_line(line),
    }
}

/// `gitlab-runner run-single` stdout (SP-8). Colour codes sit inside key=value, so they are stripped first.
/// The runner's job lines carry job-controlled text (`job_name=`), so only the first `job=<digits>` token after
/// `received` is read (the runner prints `job=` before `job_name=`); anything else on the line is ignored.
fn gitlab_line(line: &str) -> Option<Line> {
    let mut clean = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            clean.push(c);
        }
    }
    if let Some((_, rest)) = clean.split_once("Checking for jobs... received") {
        let id = rest.split_whitespace().find_map(|t| t.strip_prefix("job="))?;
        return (!id.is_empty() && id.len() <= 18 && id.bytes().all(|b| b.is_ascii_digit())).then(|| Line::JobStart(id.to_string()));
    }
    clean.contains("Starting runner for ").then_some(Line::Listening)
}

/// `gitea-runner daemon` at log level `info` (SP-3; logrus text format), plus kiln-job's own `kiln.gate=dead`.
/// `job=` (the workflow's job name) is job-controlled text: logrus quotes it, but only the fixed `level=info
/// msg="task started"` anchor and the first unquoted `job_id=<digits>` field are read, never anything inside a quoted value.
fn gitea_line(line: &str) -> Option<Line> {
    // Only the bare line kiln-job writes straight to the console device: a journal-prefixed copy is some other process's text (R3 L-3).
    if line == "kiln.gate=dead" {
        return Some(Line::GateDead);
    }
    if let Some((head, rest)) = line.split_once(r#" level=info msg="task started" "#) {
        if !head.contains("time=\"") {
            return None;
        }
        let id = logrus_field(rest, "job_id")?;
        return (!id.is_empty() && id.len() <= 18 && id.bytes().all(|b| b.is_ascii_digit())).then_some(Line::JobStart(id));
    }
    if line.contains(r#" level=info msg="runner: "#) && line.ends_with(r#"declare successfully""#) {
        return Some(Line::Listening);
    }
    // A job cannot make the server say this; matched on the text, the status code differs by version (500, 401). The fields are
    // walked from the logrus `time="` start (after any journal prefix): `level` is warning or error and the unquoted `msg` or
    // `error` value holds the text, so job text inside another quoted value (a workflow parse error echoing it) never matches.
    let body = &line[line.find("time=\"")?..];
    let said = |k| logrus_field(body, k).is_some_and(|v| v.contains("unregistered runner"));
    matches!(logrus_field(body, "level").as_deref(), Some("warning" | "error")).then_some(())?;
    (said("msg") || said("error")).then_some(Line::Unregistered)
}

/// Whether `line` is kiln-job's own `kiln: decide`: the whole remainder after the journal prefix
/// (`[ts] kiln-job[<pid>]: `), so a job name containing the words cannot mark it early (R3 L-3).
pub fn is_decide(line: &str) -> bool {
    is_job_line(line, "kiln: decide")
}

/// kiln-job's own `kiln: cache scrub failed` (the guest could not delete login tokens from the cache disk), anchored like `is_decide`.
pub fn is_scrub_failed(line: &str) -> bool {
    is_job_line(line, "kiln: cache scrub failed")
}

fn is_job_line(line: &str, msg: &str) -> bool {
    let l = line.trim_end();
    let l = l.strip_prefix('[').and_then(|r| r.split_once("] ")).map_or(l, |(_, rest)| rest);
    l.strip_prefix("kiln-job[")
        .and_then(|r| r.split_once("]: "))
        .is_some_and(|(pid, rest)| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && rest == msg)
}

/// The raw value of the first unquoted `key=value` field of a logrus text line (quoted values are skipped whole,
/// backslash escapes honoured).
fn logrus_field(s: &str, key: &str) -> Option<String> {
    let mut rest = s.trim_start();
    while !rest.is_empty() {
        let (k, after) = rest.split_once('=')?;
        if k.contains(char::is_whitespace) {
            return None;
        }
        let (value, tail) = if let Some(q) = after.strip_prefix('"') {
            let mut esc = false;
            let end = q.char_indices().find(|&(_, c)| match (esc, c) {
                (true, _) => {
                    esc = false;
                    false
                }
                (false, '\\') => {
                    esc = true;
                    false
                }
                (false, '"') => true,
                _ => false,
            })?;
            (&q[..end.0], &q[end.0 + 1..])
        } else {
            after.split_once(char::is_whitespace).unwrap_or((after, ""))
        };
        if k == key {
            return Some(value.to_string());
        }
        rest = tail.trim_start();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_lines() {
        let p = |l| parse_line(Kind::GitHub, l);
        assert_eq!(p("2026-10-06 10:00:01Z: Listening for Jobs\n"), Some(Line::Listening));
        assert_eq!(p("x: Running job: build\n"), Some(Line::Running("build".into())));
        assert_eq!(p("x: Job build completed with result: Failed"), Some(Line::Completed("Failed".into())));
        assert_eq!(p("Job x completed with result: Cancelled "), Some(Line::Completed("Cancelled".into())));
        assert_eq!(p("Runner update in progress, do not shutdown runner."), Some(Line::RunnerUpdate));
        assert_eq!(
            p("[   32.24] kiln-job[1395]: kiln: hostkey 256 SHA256:x (ED25519)\n"),
            Some(Line::Hostkey("256 SHA256:x (ED25519)".into()))
        );
        assert_eq!(p("some build output"), None);
        assert_eq!(parse_line(Kind::GitLab, "Listening for Jobs"), None);
        assert_eq!(parse_line(Kind::GitLab, "kiln: hostkey k"), Some(Line::Hostkey("k".into())));
        // A job named like the marker still starts a job (R2 L-1).
        let named = "Checking for jobs... received  job=251 job_name=x kiln: hostkey y repo_url=https://gl.example.org/a/b.git";
        assert_eq!(parse_line(Kind::GitLab, named), Some(Line::JobStart("251".into())));
    }

    #[test]
    fn gitlab_lines() {
        let p = |l: &str| parse_line(Kind::GitLab, l);
        let start = |id: &str| Some(Line::JobStart(id.into()));
        // Real runner output (SP-8), colour codes and all.
        let recv = "Checking for jobs... received                     \x1b[0;m  correlation_id\x1b[0;m=01M4T00C7V job\x1b[0;m=200 job_name\x1b[0;m=imgjob repo_url\x1b[0;m=http://x/acme/demo.git runner\x1b[0;m=tGmfbUlVk runner_name\x1b[0;m=sp8\n";
        assert_eq!(p(recv), start("200"));
        let prefixed = format!("[   32.2] kiln-job[1395]: {recv}");
        assert_eq!(p(&prefixed), start("200"), "journal prefix");
        assert_eq!(p("Checking for jobs... received  correlation_id=c job=7 job_name=x"), start("7"));
        assert_eq!(p("Starting runner for http://x with token tGmfbUlVk ... \x1b[0;m\n"), Some(Line::Listening));
        // A hostile job name cannot move the id: `job=` comes first, and later tokens are never read.
        assert_eq!(p("Checking for jobs... received correlation_id=c job=5 job_name=job=999 runner=r"), start("5"));
        assert_eq!(p("Checking for jobs... received correlation_id=c job=5 job_name=\"a job=999\""), start("5"));
        // No digits, or no `job=` before the name: no start, and the name is never mined.
        assert_eq!(p("Checking for jobs... received correlation_id=c job=abc job_name=job=999"), None);
        assert_eq!(p("Checking for jobs... received correlation_id=c job= job_name=x"), None);
        assert_eq!(p("Checking for jobs... received correlation_id=c job=1x"), None);
        assert_eq!(p("Checking for jobs... received correlation_id=c job=99999999999999999999"), None);
        assert_eq!(p("Checking for jobs... received correlation_id=c job_name=job=999"), None);
        // Other lines carrying `job=` are not starts.
        assert_eq!(p("Updating job...  bytesize=0 job=200 runner=r"), None);
        assert_eq!(p("This runner has processed its build limit, so now exiting"), None);
    }
    #[test]
    fn gitea_lines() {
        let p = |l: &str| parse_line(Kind::Gitea, l);
        let start = |id: &str| Some(Line::JobStart(id.into()));
        // Real runner output (SP-3 fixtures), journal prefix included.
        let t = r#"time="2026-10-11T09:14:48Z" level=info msg="task started" actions_url="https://github.com" address="http://gitea.example.org:3000" job=work job_id=32 repository=acme/demo run_id=2 run_number=2 task_id=24"#;
        assert_eq!(p(t), start("32"));
        assert_eq!(p(&format!("[   41.0] kiln-job[1395]: {t}\n")), start("32"), "journal prefix");
        assert_eq!(
            p(
                r#"time="x" level=info msg="runner: sp3-console, with version: v5.0.0, with labels: [kiln kiln-4cpu], declare successfully""#
            ),
            Some(Line::Listening)
        );
        // A hostile job name cannot move the id: quoted values are skipped whole, escapes included.
        let hostile =
            |name: &str| format!(r#"time="x" level=info msg="task started" address="http://x" job={name} job_id=5 repository=a/b"#);
        for name in [r#""x job_id=999""#, r#""a\" job_id=999 b""#, r#""job_id=999""#, r#""\" level=info msg=\"task started\" job_id=999""#]
        {
            assert_eq!(p(&hostile(name)), start("5"), "{name}");
        }
        // The anchor is the fixed text, not words inside a value.
        assert_eq!(p(r#"time="x" level=info msg="Running job" job="task started job_id=999" job_id=7"#), None);
        assert_eq!(p(r#"time="x" level=debug msg="task started" job_id=7"#), None, "info level only");
        assert_eq!(p(r#"level=info msg="task started" job_id=7"#), None, "no time field before the anchor");
        assert_eq!(p(r#"time="x" level=info msg="task started" job_id=abc"#), None);
        assert_eq!(p(r#"time="x" level=info msg="task started" job_id=99999999999999999999"#), None);
        assert_eq!(p(r#"time="x" level=info msg="task started" job_id="""#), None);
        assert_eq!(p(r#"time="x" level=info msg="task started" job="never closed job_id=9"#), None);
        assert_eq!(p(r#"time="x" level=info msg="removed the spent ephemeral registration \".runner\"""#), None);
        // Deleted runner: the text, whatever the status code.
        for l in [
            r#"time="x" level=warning msg="UpdateTask error: unknown: rpc error: code = Unauthenticated desc = unregistered runner, retrying until reconnected""#,
            r#"time="x" level=error msg="fail to invoke Declare" error="unknown: rpc error: code = Unauthenticated desc = unregistered runner""#,
            r#"time="x" level=warning msg="UpdateLog error: 401 unregistered runner""#,
        ] {
            assert_eq!(p(l), Some(Line::Unregistered), "{l}");
        }
        // The journal prefix is skipped; the text must be in msg/error of a warning or error line, never in another field.
        let w = r#"time="x" level=warning msg="UpdateLog error: 401 unregistered runner""#;
        assert_eq!(p(&format!("[   50.1] kiln-job[1395]: {w}")), Some(Line::Unregistered), "journal prefix");
        for l in [
            r#"time="x" level=warning msg="workflow parse error" job="unregistered runner""#,
            r#"time="x" level=error msg="x" detail="error=\"unregistered runner\" msg=\"unregistered runner\"""#,
            r#"time="x" level=info msg="x" error="unregistered runner""#,
            r#"level=warning msg="unregistered runner""#,
            r#"time="x" level=warning job=" level=warning msg=\"unregistered runner\"" msg="fine""#,
            "a level=warning msg=\"unregistered runner\"",
        ] {
            assert_eq!(p(l), None, "{l}");
        }
        assert_eq!(p("unregistered runner"), None, "plain text is not the daemon");
        assert_eq!(p(r#"time="x" level=info msg="unregistered runner""#), None);
        // The guest's gate-death line.
        assert_eq!(p("kiln.gate=dead\n"), Some(Line::GateDead));
        // Only the bare line (written straight to the console device); the journal-prefixed form is another process's text.
        assert_eq!(p("[   50.1] kiln-job[1395]: kiln.gate=dead"), None);
        assert_eq!(p("gitea-runner[9]: kiln.gate=dead"), None);
        assert_eq!(p("echo kiln.gate=dead"), None);
        assert_eq!(parse_line(Kind::GitHub, "kiln.gate=dead"), None);
        assert_eq!(parse_line(Kind::GitLab, "kiln.gate=dead"), None);
        assert_eq!(p("kiln: hostkey k"), Some(Line::Hostkey("k".into())));
    }

    #[test]
    fn decide_is_the_whole_journal_line() {
        for l in ["[   50.1] kiln-job[1395]: kiln: decide", "kiln-job[7]: kiln: decide\n", "[ 1.0] kiln-job[7]: kiln: decide  "] {
            assert!(is_decide(l), "{l}");
        }
        for l in [
            "kiln: decide",
            "[ 1.0] kiln-job[7]: kiln: decide now",
            "[ 1.0] kiln-job[x]: kiln: decide",
            "[ 1.0] other[7]: kiln: decide",
            r#"time="x" level=info msg="task started" job="kiln: decide" job_id=5"#,
            "[ 1.0] kiln-job[7]: time=x job=kiln-job[7]: kiln: decide",
            "echo kiln: decide",
        ] {
            assert!(!is_decide(l), "{l}");
        }
    }

    #[test]
    fn a_failed_scrub_is_the_whole_journal_line() {
        assert!(is_scrub_failed("[   50.1] kiln-job[1395]: kiln: cache scrub failed"));
        for l in [
            "kiln: cache scrub failed",
            "[ 1.0] kiln-job[7]: kiln: cache scrub failed!",
            "[ 1.0] runner[7]: kiln: cache scrub failed",
            "kiln-job[7]: kiln: decide",
        ] {
            assert!(!is_scrub_failed(l), "{l}");
        }
    }
}
