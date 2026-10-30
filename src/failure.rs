//! The failure summary of a job's steps log: the step that was running at the first error, and
//! the first few error lines. Run when a job ends failed (stored in the VM record) and by
//! `kiln logs --failed` as a fallback for records without one.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::BufRead;
use std::path::Path;

const MAX_LINES: usize = 20;
const MAX_LINE: usize = 300;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Failure {
    /// The step's `Run ...` group title; empty when the log names none.
    pub step: String,
    pub lines: Vec<String>,
}

/// Drops a byte order mark and ANSI escape sequences (colors, cursor moves, OSC).
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(ch) = it.next() {
        match ch {
            '\u{feff}' => {}
            '\x1b' => match it.peek() {
                Some('[') => {
                    it.next();
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(c) = it.next() {
                        if c == '\x07' || (c == '\x1b' && it.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {
                    it.next();
                }
            },
            c => out.push(c),
        }
    }
    out
}

/// `lines` of a steps log (GitHub's `##[group]` and Gitea's `::group::` shapes, optionally
/// timestamped). With `##[error]` lines the step is the `Run ...` group open at the first one and
/// the lines are the `FAIL`/`Error:` lines of that group after the errors; without, the step is
/// the group of the first `FAIL`/`Error:` line. None when nothing matches. A repeated line (the
/// runner preamble printed twice, the second time behind a BOM) counts once.
pub fn summarize(lines: impl Iterator<Item = String>) -> Option<Failure> {
    let (mut run, mut any) = (None::<String>, None::<String>);
    let mut n = 0; // Run groups seen so far
    let mut seen = HashSet::new();
    let mut errs: Vec<String> = vec![];
    let mut err_step = None::<(usize, String)>;
    let mut other: Vec<(usize, String, String)> = vec![]; // (run group, its title, line)
    for raw in lines {
        let l = clean(&raw);
        let l = l.trim_end_matches('\r');
        let body = match l.split_once(' ') {
            Some((ts, rest)) if ts.len() > 19 && ts.as_bytes()[4] == b'-' && ts.ends_with('Z') => rest,
            _ => l,
        };
        if let Some(t) = body.strip_prefix("##[group]").or_else(|| body.strip_prefix("::group::")) {
            let t = t.trim().to_string();
            if t.starts_with("Run ") {
                n += 1;
                run = Some(t.clone());
            }
            any = Some(t);
            continue;
        }
        let is_err = body.contains("##[error]");
        if !(is_err || body.contains("FAIL") || body.contains("Error:")) || !seen.insert(body.to_string()) {
            continue;
        }
        let step = || run.clone().or(any.clone()).unwrap_or_default();
        let text: String = body.trim().chars().take(MAX_LINE).collect();
        if is_err {
            err_step.get_or_insert_with(|| (n, step()));
            if errs.len() < MAX_LINES {
                errs.push(text);
            }
        } else if other.len() < 1000 {
            // ponytail: the first 1000 candidates only, so a huge noisy log stays bounded.
            other.push((n, step(), text));
        }
    }
    let (g, step) = match err_step {
        Some(e) => e,
        None => other.first().map(|(g, s, _)| (*g, s.clone()))?,
    };
    errs.extend(other.into_iter().filter(|(x, ..)| *x == g).map(|(.., t)| t));
    errs.truncate(MAX_LINES);
    Some(Failure { step, lines: errs })
}

/// The summary of a steps log on disk; None when it is missing or has no match.
pub fn from_file(path: &Path) -> Option<Failure> {
    let f = std::io::BufReader::new(std::fs::File::open(path).ok()?);
    summarize(f.split(b'\n').map_while(Result::ok).map(|b| String::from_utf8_lossy(&b).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(log: &str) -> Option<Failure> {
        summarize(log.lines().map(String::from))
    }

    #[test]
    fn finds_step_and_lines() {
        let log = "2026-10-11T09:14:47.1Z ::group::Run npm test\nok\n\x1b[31;1m2026-10-11T09:14:47.2Z ##[error]boom\x1b[0m\nFAIL pkg/x\n";
        // The ANSI escape sits before the timestamp here: still stripped first.
        assert_eq!(sum(log), Some(Failure { step: "Run npm test".into(), lines: vec!["##[error]boom".into(), "FAIL pkg/x".into()] }));
    }

    #[test]
    fn step_is_the_run_group_before_the_first_error() {
        let log = "##[group]Run a\n##[group]Run make\n##[group]inner\nError: bad\n##[group]Run later\nok";
        assert_eq!(sum(log).unwrap().step, "Run make");
    }

    #[test]
    fn bom_duplicate_preamble_counts_once() {
        let log = "##[group]Run x\nError: preamble\n\u{feff}Error: preamble\nError: real";
        assert_eq!(sum(log).unwrap().lines, vec!["Error: preamble", "Error: real"]);
    }

    #[test]
    fn caps_lines_and_length() {
        let log: String = (0..40).map(|i| format!("FAIL t{i}\n")).collect::<String>() + &format!("Error: {}", "x".repeat(500));
        let f = sum(&log).unwrap();
        assert_eq!(f.lines.len(), 20);
        let long = sum(&format!("Error: {}", "x".repeat(500))).unwrap();
        assert_eq!(long.lines[0].chars().count(), 300);
        assert_eq!(long.step, "");
    }

    #[test]
    fn passing_step_error_does_not_pick_the_step() {
        let log = "##[group]Run lint\nError: expected, ignored\n##[group]Run test\n##[error]Process completed with exit code 1.";
        let f = sum(log).unwrap();
        assert_eq!(f.step, "Run test");
        assert_eq!(f.lines, vec!["##[error]Process completed with exit code 1."]);
    }

    #[test]
    fn noise_does_not_hide_the_final_error() {
        let log: String = "##[group]Run t\n".to_string() + &(0..30).map(|i| format!("FAIL n{i}\n")).collect::<String>() + "##[error]real";
        let f = sum(&log).unwrap();
        assert_eq!(f.lines.len(), 20);
        assert_eq!(f.lines[0], "##[error]real");
    }

    #[test]
    fn no_match() {
        assert_eq!(sum("all\nfine\n##[group]Run x"), None);
    }
}
