//! The GitHub forge: a thin face over `Gh` (which keeps the ETag cache, rate counters, App tokens).

use std::sync::Arc;

use super::{
    Caps, Demand, Dereg, EventKind, ForgeCfg, ForgeId, JobRef, JobSummary, Links, LogPage, Outcome, RepoRef, RunDetail, RunPage, RunQuery,
    RunStatus, RunSummary, RunnerReg, StepSummary, Workflow,
};
use crate::github::Gh;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;

pub struct GitHub {
    /// Shared with `App.gh`, so code that has not moved to the registry yet sees the same client state.
    pub gh: Arc<Gh>,
}

impl GitHub {
    /// What stops this forge polling at all: no credential, or the rate limit.
    pub fn health(&self) -> Option<String> {
        if !self.gh.has_token() {
            return Some("no GitHub token: set one in the dashboard, export KILN_GITHUB_TOKEN, or `gh auth login`".into());
        }
        self.gh.paused_until().map(|t| format!("GitHub rate limit: paused until {t}"))
    }

    /// App mode: the installations' repos, else the configured list.
    pub fn repos(&self, cfg: &ForgeCfg) -> Vec<RepoRef> {
        let names = match self.gh.app() {
            Some(a) => a.names.read().unwrap().clone(),
            None => cfg.repos.clone(),
        };
        // Not `RepoRef::parse`: App names come from GitHub and were never re-validated.
        names.into_iter().map(|path| RepoRef { forge: ForgeId::github(), path }).collect()
    }

    pub async fn demand(&self, repo: &RepoRef, label: &str, default_cpus: u32) -> Result<Demand> {
        let (by_size, claimed, refused_forks) = self.gh.queued_jobs(&repo.path, label, default_cpus).await?;
        Ok(Demand { by_size, claimed, refused_forks })
    }

    pub async fn register(&self, repo: &RepoRef, name: &str, labels: &[String]) -> Result<RunnerReg> {
        let (runner_id, jit) = self.gh.jit_config(&repo.path, name, labels).await?;
        Ok(RunnerReg { runner_id, guest_secret: format!("kiln.jit={jit}") })
    }

    /// 204/404 = Gone (404: the ephemeral runner already deregistered itself), 422 = Busy (it got a job).
    pub async fn deregister(&self, repo: &RepoRef, runner_id: u64) -> Dereg {
        match self.gh.delete_runner_status(&repo.path, runner_id).await {
            Ok(s) if s.is_success() || s == 404 => Dereg::Gone,
            Ok(s) if s == 422 => Dereg::Busy,
            Ok(s) => Dereg::Err(anyhow::anyhow!("delete runner {runner_id}: {s}")),
            Err(e) => Dereg::Err(e),
        }
    }

    pub async fn cache_trust(&self, job: &JobRef, writers: &[String]) -> Result<(String, String, String, String)> {
        let id = job.id.parse().context("bad job id")?;
        self.gh.cache_trust(&job.repo.path, id, writers).await
    }
}

pub const CAPS: Caps = Caps { rerun: true, rerun_failed: true, cancel: true, dispatch: true, workflows: true, live_steps: true };
const PER_PAGE: usize = 30;
/// Most log bytes returned per request; the caller continues from `next`.
const LOG_CAP: usize = 1 << 20;

impl GitHub {
    pub fn auth(&self) -> Value {
        json!({ "source": self.gh.source(), "expires": *self.gh.expires.lock().unwrap() })
    }

    pub async fn runs(&self, repo: &RepoRef, q: &RunQuery) -> Result<RunPage> {
        let p = &repo.path;
        let mut pairs = vec![("per_page", PER_PAGE.to_string()), ("page", q.page.max(1).to_string())];
        match q.status.as_deref() {
            None => {}
            Some("queued") => pairs.push(("status", "queued".into())),
            Some("running") => pairs.push(("status", "in_progress".into())),
            Some("completed") => pairs.push(("status", "completed".into())),
            Some(s) => bail!("status must be queued, running or completed, not {s:?}"),
        }
        if let Some(b) = &q.branch {
            pairs.push(("branch", b.clone()));
        }
        let v = self.gh.get(&format!("repos/{p}/actions/runs?{}", query(&pairs))).await?;
        let runs: Vec<_> = v["workflow_runs"].as_array().into_iter().flatten().filter_map(|r| run_summary(p, r)).collect();
        let total = v["total_count"].as_u64().unwrap_or(0);
        let next = (total > u64::from(q.page.max(1)) * PER_PAGE as u64).then(|| q.page.max(1) + 1);
        Ok(RunPage { runs, next })
    }

    pub async fn run(&self, repo: &RepoRef, id: u64) -> Result<RunDetail> {
        let p = &repo.path;
        let r = self.gh.get(&format!("repos/{p}/actions/runs/{id}")).await?;
        let run = run_summary(p, &r).context("malformed run")?;
        let j = self.gh.get(&format!("repos/{p}/actions/runs/{id}/jobs?per_page=100")).await?;
        let jobs = j["jobs"].as_array().into_iter().flatten().filter_map(|j| job_summary(p, id, j)).collect();
        Ok(RunDetail { run, jobs })
    }

    /// GitHub serves a job's log only once the job has finished, so a page is `complete` when it reaches the end.
    pub async fn job_log(&self, repo: &RepoRef, id: u64, from: usize) -> Result<LogPage> {
        let r = self.gh.raw(reqwest::Method::GET, &format!("repos/{}/actions/jobs/{id}/logs", repo.path), None).await?;
        if !(200..300).contains(&r.status) {
            bail!("job log: GitHub answered {}", r.status);
        }
        let b = &r.body;
        let start = from.min(b.len());
        let mut end = (start + LOG_CAP).min(b.len());
        // Do not cut a UTF-8 sequence in half.
        while end > start && end < b.len() && b[end] & 0xC0 == 0x80 {
            end -= 1;
        }
        Ok(LogPage { text: String::from_utf8_lossy(&b[start..end]).into_owned(), next: end, complete: end == b.len() })
    }

    pub async fn workflows(&self, repo: &RepoRef) -> Result<Vec<Workflow>> {
        let v = self.gh.get(&format!("repos/{}/actions/workflows?per_page=100", repo.path)).await?;
        Ok(v["workflows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|w| {
                let file = w["path"].as_str()?.rsplit('/').next()?.to_string();
                Some(Workflow { id: w["id"].as_u64()?, name: w["name"].as_str()?.into(), file })
            })
            .collect())
    }

    pub async fn rerun(&self, repo: &RepoRef, id: u64, failed_only: bool) -> Result<()> {
        let what = if failed_only { "rerun-failed-jobs" } else { "rerun" };
        self.post(&format!("repos/{}/actions/runs/{id}/{what}", repo.path), None).await
    }

    pub async fn cancel(&self, repo: &RepoRef, id: u64) -> Result<()> {
        self.post(&format!("repos/{}/actions/runs/{id}/cancel", repo.path), None).await
    }

    pub async fn dispatch(&self, repo: &RepoRef, workflow: Option<&str>, git_ref: &str, inputs: &HashMap<String, String>) -> Result<()> {
        let wf = workflow.context("GitHub needs a workflow (file name or id) to dispatch")?;
        let mut body = json!({ "ref": git_ref });
        if !inputs.is_empty() {
            body["inputs"] = json!(inputs);
        }
        self.post(&format!("repos/{}/actions/workflows/{wf}/dispatches", repo.path), Some(body)).await
    }

    async fn post(&self, path: &str, body: Option<Value>) -> Result<()> {
        let r = self.gh.raw(reqwest::Method::POST, path, body).await?;
        if !(200..300).contains(&r.status) {
            // GitHub's own message is safe to show; it never echoes the credential.
            let msg =
                serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v["message"].as_str().map(String::from)).unwrap_or_default();
            bail!("GitHub answered {}: {msg}", r.status);
        }
        Ok(())
    }
}

fn query(pairs: &[(&str, String)]) -> String {
    let mut u = reqwest::Url::parse("http://x/").expect("static url");
    u.query_pairs_mut().extend_pairs(pairs);
    u.query().unwrap_or("").to_string()
}

fn status(s: &str) -> RunStatus {
    match s {
        "completed" => RunStatus::Completed,
        "in_progress" => RunStatus::Running,
        _ => RunStatus::Queued,
    }
}

fn outcome(v: &Value) -> Option<Outcome> {
    Some(match v.as_str()? {
        "success" | "neutral" => Outcome::Succeeded,
        "failure" | "timed_out" | "startup_failure" => Outcome::Failed,
        "cancelled" => Outcome::Canceled,
        "skipped" => Outcome::Skipped,
        _ => Outcome::Abandoned,
    })
}

fn event(s: &str) -> EventKind {
    match s {
        "push" => EventKind::Push,
        "pull_request" | "pull_request_target" => EventKind::PullRequest,
        "workflow_dispatch" => EventKind::Manual,
        "schedule" => EventKind::Schedule,
        "release" => EventKind::Release,
        _ => EventKind::Other,
    }
}

fn plain(s: &str, extra: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c) || extra.contains(c))
}

/// Links are built from validated parts, never taken from the response.
fn run_links(repo: &str, run: u64, job: Option<u64>, sha: &str, branch: &str, pr: Option<u64>) -> Links {
    let base = format!("https://github.com/{repo}");
    Links {
        run: Some(format!("{base}/actions/runs/{run}")),
        job: job.map(|j| format!("{base}/actions/runs/{run}/job/{j}")),
        commit: sha.chars().all(|c| c.is_ascii_hexdigit()).then(|| format!("{base}/commit/{sha}")).filter(|_| !sha.is_empty()),
        pr: pr.map(|n| format!("{base}/pull/{n}")),
        branch: plain(branch, "/").then(|| format!("{base}/tree/{branch}")),
    }
}

fn run_summary(repo: &str, r: &Value) -> Option<RunSummary> {
    let id = r["id"].as_u64()?;
    let (branch, sha) = (r["head_branch"].as_str().unwrap_or(""), r["head_sha"].as_str().unwrap_or(""));
    let pr = r["pull_requests"][0]["number"].as_u64();
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    Some(RunSummary {
        id,
        name: s("name"),
        title: s("display_title"),
        number: r["run_number"].as_u64().unwrap_or(0),
        attempt: r["run_attempt"].as_u64().unwrap_or(1),
        status: status(r["status"].as_str().unwrap_or("")),
        outcome: outcome(&r["conclusion"]),
        event: event(r["event"].as_str().unwrap_or("")),
        branch: branch.into(),
        sha: sha.into(),
        actor: r["actor"]["login"].as_str().map(String::from),
        created_at: s("created_at"),
        updated_at: s("updated_at"),
        links: run_links(repo, id, None, sha, branch, pr),
    })
}

fn job_summary(repo: &str, run: u64, j: &Value) -> Option<JobSummary> {
    let id = j["id"].as_u64()?;
    let steps = j["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| StepSummary {
            number: s["number"].as_u64().unwrap_or(0),
            name: s["name"].as_str().unwrap_or("").into(),
            status: status(s["status"].as_str().unwrap_or("")),
            outcome: outcome(&s["conclusion"]),
        })
        .collect();
    Some(JobSummary {
        id,
        name: j["name"].as_str().unwrap_or("").into(),
        status: status(j["status"].as_str().unwrap_or("")),
        outcome: outcome(&j["conclusion"]),
        started_at: j["started_at"].as_str().map(String::from),
        completed_at: j["completed_at"].as_str().map(String::from),
        runner: j["runner_name"].as_str().map(String::from),
        steps,
        links: Links { job: run_links(repo, run, Some(id), "", "", None).job, ..Links::default() },
    })
}
