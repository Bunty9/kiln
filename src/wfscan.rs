//! Workflow timeouts that kiln would cut short. About once a day per GitHub repo, the workflow files on the
//! default branch are read and scanned (a line scan, no YAML parser) for `timeout-minutes` above `job_timeout_mins`
//! on jobs that run on kiln's label. Each one raises a `workflow_timeout` health item until it is fixed.

use crate::App;
use base64::Engine;
use std::{collections::HashMap, sync::Arc, time::Duration};

const DAY: u64 = 86400;
/// Larger workflow files are skipped.
const MAX_FILE: u64 = 256 * 1024;

/// A `timeout-minutes` found in a workflow file.
#[derive(Clone, Debug, PartialEq)]
pub struct Ask {
    pub file: String,
    pub job: String,
    pub name: Option<String>,
    pub minutes: u64,
    pub step: bool,
    /// False when `runs-on` is a matrix or an expression: the job may or may not run on kiln.
    pub certain: bool,
}

#[derive(Default)]
struct Job {
    id: String,
    name: Option<String>,
    runs: String,
    job_t: Option<u64>,
    step_t: Option<u64>,
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

fn strip_comment(l: &str) -> &str {
    let mut prev = ' ';
    for (i, c) in l.char_indices() {
        if c == '#' && prev.is_whitespace() {
            return &l[..i];
        }
        prev = c;
    }
    l
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// Does a `runs-on` text name kiln's label (`label`, `label-4cpu`, `label-arm64`)?
fn on_kiln(runs: &str, label: &str) -> bool {
    runs.split(|c: char| !(c.is_ascii_alphanumeric() || "_.-".contains(c)))
        .any(|t| t == label || t.strip_prefix(label).is_some_and(|r| r.starts_with('-')))
}

/// `timeout-minutes: N` in the jobs of a workflow file that run on `label` (or may).
pub fn scan(file: &str, text: &str, label: &str) -> Vec<Ask> {
    let mut out = vec![];
    let (mut in_jobs, mut job_ind, mut body_ind) = (false, None::<usize>, None::<usize>);
    let mut cur: Option<Job> = None;
    let mut in_runs = false;
    let finish = |j: Option<Job>, out: &mut Vec<Ask>| {
        let Some(j) = j else { return };
        let on = on_kiln(&j.runs, label);
        if !on && !j.runs.contains("${{") {
            return;
        }
        for (m, step) in [(j.job_t, false), (j.step_t, true)] {
            if let Some(minutes) = m {
                out.push(Ask { file: file.into(), job: j.id.clone(), name: j.name.clone(), minutes, step, certain: on });
            }
        }
    };
    for raw in text.lines() {
        let l = strip_comment(raw).trim_end();
        if l.trim().is_empty() {
            continue;
        }
        let ind = indent(l);
        let t = l.trim_start();
        if ind == 0 {
            finish(cur.take(), &mut out);
            in_jobs = t == "jobs:";
            job_ind = None;
            body_ind = None;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let ji = *job_ind.get_or_insert(ind);
        if ind == ji {
            finish(cur.take(), &mut out);
            body_ind = None;
            in_runs = false;
            if let Some((k, _)) = t.split_once(':') {
                cur = Some(Job { id: unquote(k).to_string(), ..Default::default() });
            }
            continue;
        }
        let Some(j) = cur.as_mut() else { continue };
        let bi = *body_ind.get_or_insert(ind);
        let key = t.split_once(':').map(|(k, v)| (k.trim_start_matches("- ").trim(), v.trim()));
        if ind == bi {
            in_runs = false;
            match key {
                Some(("runs-on", v)) => {
                    j.runs = v.to_string();
                    in_runs = true;
                }
                Some(("name", v)) => j.name = Some(unquote(v).to_string()),
                Some(("timeout-minutes", v)) => j.job_t = v.parse().ok().or(j.job_t),
                _ => {}
            }
        } else if in_runs {
            // The lines under a bare `runs-on:` (a list, or `labels:`/`group:`).
            j.runs.push(' ');
            j.runs.push_str(t);
        } else if let Some(("timeout-minutes", v)) = key
            && let Ok(m) = v.parse::<u64>()
        {
            j.step_t = Some(j.step_t.map_or(m, |s| s.max(m)));
        }
    }
    finish(cur, &mut out);
    out
}

fn due(app: &App, repo: &str) -> bool {
    app.wf_asks.lock().unwrap().get(&repo.to_ascii_lowercase()).is_none_or(|(at, _)| crate::now().saturating_sub(*at) >= DAY)
}

/// Reads and scans every workflow file of `repo`; Err = could not read the directory.
async fn scan_repo(app: &App, repo: &str, label: &str) -> anyhow::Result<Vec<Ask>> {
    let dir = match app.gh.get(&format!("repos/{repo}/contents/.github/workflows")).await {
        Ok(d) => d,
        // No workflows directory: nothing to warn about.
        Err(e) if e.to_string().contains("404") => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = vec![];
    for f in dir.as_array().into_iter().flatten() {
        let (Some(name), Some(path)) = (f["name"].as_str(), f["path"].as_str()) else { continue };
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) || f["size"].as_u64().unwrap_or(0) > MAX_FILE {
            continue;
        }
        let Ok(v) = app.gh.get(&format!("repos/{repo}/contents/{path}")).await else { continue };
        let b64: String = v["content"].as_str().unwrap_or("").split_whitespace().collect();
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.extend(scan(name, &String::from_utf8_lossy(&bytes), label));
        }
    }
    Ok(out)
}

/// Raises one health item per ask above the current `job_timeout_mins`; clears the ones that are fixed.
fn raise(app: &App) {
    let limit = app.cfg().job_timeout_mins;
    let mut n = app.notices.lock().unwrap();
    n.retain(|k, _| !k.starts_with("wf:"));
    for (repo, (_, asks)) in app.wf_asks.lock().unwrap().iter() {
        for a in asks.iter().filter(|a| a.minutes > limit) {
            let on = if a.certain { "" } else { " (may run on kiln)" };
            let at = if a.step { "a step of job" } else { "job" };
            n.insert(
                format!("wf:{repo}:{}:{}:{}", a.file, a.job, a.step),
                (
                    "workflow_timeout",
                    format!(
                        "{repo} .github/workflows/{}: {at} {} asks timeout-minutes: {}{on}, but kiln stops jobs after job_timeout_mins: {limit}. Lower it in the workflow or raise job_timeout_mins.",
                        a.file, a.job, a.minutes
                    ),
                ),
            );
        }
    }
}

/// " The workflow asked for N min." when the scan knows this job's `timeout-minutes` exceeded the limit.
pub fn asked_note(app: &App, repo: &str, job: Option<&str>) -> String {
    let (limit, Some(job)) = (app.cfg().job_timeout_mins, job) else { return String::new() };
    let m = app.wf_asks.lock().unwrap();
    let asks = m.get(&repo.to_ascii_lowercase()).map(|(_, a)| a.as_slice()).unwrap_or_default();
    let hit = asks.iter().filter(|a| a.minutes > limit && !a.step).filter(|a| {
        let j = job.to_ascii_lowercase();
        j.starts_with(&a.job.to_ascii_lowercase()) || a.name.as_ref().is_some_and(|n| j.starts_with(&n.to_ascii_lowercase()))
    });
    match hit.map(|a| a.minutes).max() {
        Some(m) => format!("; the workflow asked for timeout-minutes: {m}"),
        None => String::new(),
    }
}

pub async fn supervise(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        let label = app.cfg().label;
        let repos: HashMap<_, _> = app.repos().into_iter().map(|r| (r.to_ascii_lowercase(), r)).collect();
        for r in repos.values().filter(|r| due(&app, r)) {
            if app.gh.repo_paused(r).is_some() || app.gh.paused_until().is_some() {
                continue;
            }
            match scan_repo(&app, r, &label).await {
                Ok(a) => {
                    app.wf_asks.lock().unwrap().insert(r.to_ascii_lowercase(), (crate::now(), a));
                }
                Err(e) => {
                    tracing::debug!("workflow scan of {r}: {e}");
                    // Try again in about an hour rather than every round.
                    let mut m = app.wf_asks.lock().unwrap();
                    let asks = m.remove(&r.to_ascii_lowercase()).map(|(_, a)| a).unwrap_or_default();
                    m.insert(r.to_ascii_lowercase(), (crate::now().saturating_sub(DAY - 3600), asks));
                }
            }
        }
        app.wf_asks.lock().unwrap().retain(|k, _| repos.contains_key(k));
        raise(&app);
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str) -> Vec<(String, u64, bool, bool)> {
        scan("ci.yml", t, "kiln").into_iter().map(|a| (a.job, a.minutes, a.step, a.certain)).collect()
    }

    #[test]
    fn job_and_step_timeouts_on_kiln() {
        let y = "name: ci\non: push\njobs:\n  build:\n    runs-on: [self-hosted, kiln-4cpu]\n    timeout-minutes: 120 # long\n    steps:\n      - run: x\n        timeout-minutes: 90\n      - uses: a/b\n  lint:\n    runs-on: kiln\n    steps:\n      - run: y\n";
        assert_eq!(s(y), vec![("build".into(), 120, false, true), ("build".into(), 90, true, true)]);
    }

    #[test]
    fn other_runners_and_comments_are_ignored() {
        let y = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 500\n  b:\n    # runs-on: kiln\n    runs-on: macos-14\n    timeout-minutes: 500\n  c:\n    runs-on: kilnish\n    timeout-minutes: 500\n";
        assert!(s(y).is_empty());
        // A commented-out timeout is not one.
        assert!(s("jobs:\n  a:\n    runs-on: kiln\n    # timeout-minutes: 500\n").is_empty());
    }

    #[test]
    fn expressions_and_block_lists() {
        let y = "jobs:\n  m:\n    runs-on: ${{ matrix.os }}\n    timeout-minutes: 200\n  l:\n    runs-on:\n      - self-hosted\n      - kiln-arm64\n    timeout-minutes: 70\n  g:\n    runs-on:\n      labels: kiln\n    timeout-minutes: '80'\n";
        assert_eq!(s(y), vec![("m".into(), 200, false, false), ("l".into(), 70, false, true)]);
    }

    #[test]
    fn asks_raise_and_clear() {
        let app = crate::test_app("wfscan");
        let ask =
            Ask { file: "ci.yml".into(), job: "build".into(), name: Some("Build it".into()), minutes: 120, step: false, certain: false };
        app.wf_asks.lock().unwrap().insert("acme/demo".into(), (1, vec![ask]));
        raise(&app);
        let n = app.notices.lock().unwrap().values().map(|v| v.1.clone()).collect::<Vec<_>>();
        assert!(
            n.len() == 1
                && n[0].contains("acme/demo")
                && n[0].contains("ci.yml")
                && n[0].contains("build")
                && n[0].contains("120")
                && n[0].contains("60")
                && n[0].contains("may run on kiln"),
            "{n:?}"
        );
        assert!(asked_note(&app, "Acme/Demo", Some("Build it (x)")).contains("120"));
        assert_eq!(asked_note(&app, "acme/demo", Some("test")), "");
        app.wf_asks.lock().unwrap().clear();
        raise(&app);
        assert!(app.notices.lock().unwrap().is_empty());
    }
}
