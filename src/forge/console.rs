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
        // ponytail: the Gitea runner console arrives with its forge task.
        Kind::Gitea => None,
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
}
