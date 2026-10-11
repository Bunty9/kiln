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
}

/// Recognises one console line. Trailing whitespace is ignored.
pub fn parse_line(kind: Kind, line: &str) -> Option<Line> {
    let line = line.trim_end();
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
        // ponytail: the GitLab and Gitea runner consoles arrive with their forge tasks.
        Kind::Gitea | Kind::GitLab => None,
    }
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
    }
}
