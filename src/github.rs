//! Thin GitHub REST client: just the calls the scheduler needs, plus a raw
//! passthrough the dashboard uses for everything else.

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

pub struct Gh {
    http: reqwest::Client,
    token: std::sync::RwLock<String>,
    /// Where the token came from: "env" | "file" | "gh" | "none".
    source: std::sync::RwLock<&'static str>,
    /// Last seen (remaining, limit, reset) from x-ratelimit-* headers.
    pub rate: std::sync::Mutex<Option<(u64, u64, u64)>>,
    /// Unix time until which GitHub told us to back off (0 = not paused).
    paused_until: AtomicU64,
    /// (latest runner release, don't refetch before this unix time).
    latest: std::sync::Mutex<(Option<String>, u64)>,
    // URL -> (etag, body). Conditional GETs that return 304 are free against
    // the rate limit, which is what makes 5s polling of several repos viable.
    etags: Mutex<HashMap<String, (String, Value)>>,
    /// repo -> (default branch, fetched at unix time); renames are rare, so 1h.
    defaults: std::sync::Mutex<HashMap<String, (String, u64)>>,
}

pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub body: bytes::Bytes,
}

impl Gh {
    pub fn new(token: String, source: &'static str) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("kiln-ci")
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("http client");
        Self {
            http,
            token: std::sync::RwLock::new(token),
            source: std::sync::RwLock::new(source),
            rate: Default::default(),
            paused_until: AtomicU64::new(0),
            latest: Default::default(),
            etags: Mutex::default(),
            defaults: Default::default(),
        }
    }

    pub fn set_token(&self, t: String, source: &'static str) {
        *self.token.write().unwrap() = t;
        *self.source.write().unwrap() = source;
    }

    pub fn source(&self) -> &'static str {
        *self.source.read().unwrap()
    }

    pub fn paused_until(&self) -> Option<u64> {
        Some(self.paused_until.load(Ordering::Relaxed)).filter(|&t| t > crate::now())
    }

    pub fn has_token(&self) -> bool {
        !self.token.read().unwrap().is_empty()
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.request_with(&self.token.read().unwrap(), method, path)
    }

    fn request_with(&self, token: &str, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("https://api.github.com/{}", path.trim_start_matches('/'));
        self.http
            .request(method, url)
            .bearer_auth(token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    /// Every call goes through here so the rate-limit state stays current.
    async fn exec(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let r = rb.send().await?;
        let num = |k: &str| r.headers().get(k).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        let (remaining, reset) = (num("x-ratelimit-remaining"), num("x-ratelimit-reset"));
        if let (Some(rem), Some(lim), Some(reset)) = (remaining, num("x-ratelimit-limit"), reset) {
            *self.rate.lock().unwrap() = Some((rem, lim, reset));
        }
        if let Some(t) = pause_until(r.status().as_u16(), remaining, reset, num("retry-after"), crate::now()) {
            self.paused_until.fetch_max(t, Ordering::Relaxed);
        }
        Ok(r)
    }

    /// Secondary limits come as a 403 whose only marker is the body text.
    fn note_body(&self, status: u16, body: &str) {
        if secondary_limit(status, body) {
            self.paused_until.fetch_max(crate::now() + 60, Ordering::Relaxed);
        }
    }

    /// GET with an explicit token, for validating one before saving it.
    /// Returns (status, X-OAuth-Scopes, body). A candidate token's rate
    /// limits are not ours, so this bypasses `exec`'s global state.
    pub async fn probe(&self, token: &str, path: &str) -> Result<(u16, Option<String>, Value)> {
        let r = self.request_with(token, Method::GET, path).send().await?;
        let status = r.status().as_u16();
        let scopes = r.headers().get("x-oauth-scopes").and_then(|v| v.to_str().ok()).map(String::from);
        Ok((status, scopes, r.json().await.unwrap_or(Value::Null)))
    }

    pub fn latest_cached(&self) -> Option<String> {
        self.latest.lock().unwrap().0.clone()
    }

    /// Refresh the latest actions/runner release tag (6h TTL; 5 min after a failure).
    pub async fn refresh_latest(&self) {
        if crate::now() < self.latest.lock().unwrap().1 {
            return;
        }
        let r = tokio::time::timeout(std::time::Duration::from_secs(10), self.get("repos/actions/runner/releases/latest")).await;
        let mut l = self.latest.lock().unwrap();
        match r {
            Ok(Ok(v)) if v["tag_name"].is_string() => {
                *l = (v["tag_name"].as_str().map(|t| t.trim_start_matches('v').to_string()), crate::now() + 6 * 3600)
            }
            _ => l.1 = crate::now() + 300,
        }
    }

    /// Raw call for the dashboard proxy. Follows redirects (job logs redirect
    /// to a signed blob URL; reqwest drops the auth header cross-origin).
    pub async fn raw(&self, method: Method, path: &str, body: Option<Value>) -> Result<Resp> {
        let mut rb = self.request(method, path);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = self.exec(rb).await?;
        let status = r.status().as_u16();
        let content_type = r
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let body = r.bytes().await?;
        self.note_body(status, &String::from_utf8_lossy(&body));
        Ok(Resp { status, content_type, body })
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let cached = {
            let mut c = self.etags.lock().await;
            // ponytail: ceiling of 500 cached URLs, dropped wholesale; an LRU if the clear ever hurts the 304 hit rate.
            if c.len() > 500 {
                c.clear();
            }
            c.get(path).cloned()
        };
        let mut rb = self.request(Method::GET, path);
        if let Some((etag, _)) = &cached {
            rb = rb.header(header::IF_NONE_MATCH, etag);
        }
        let r = self.exec(rb).await?;
        if r.status() == StatusCode::NOT_MODIFIED
            && let Some((_, v)) = cached {
                return Ok(v);
            }
        if !r.status().is_success() {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            self.note_body(status.as_u16(), &body);
            bail!("GET {path}: {status} {body}");
        }
        let etag = r.headers().get(header::ETAG).and_then(|v| v.to_str().ok()).map(String::from);
        let v: Value = r.json().await?;
        if let Some(e) = etag {
            self.etags.lock().await.insert(path.to_string(), (e, v.clone()));
        }
        Ok(v)
    }

    async fn send(&self, method: Method, path: &str, body: Value) -> Result<Value> {
        let r = self.exec(self.request(method.clone(), path).json(&body)).await?;
        if !r.status().is_success() {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            self.note_body(status.as_u16(), &body);
            bail!("{method} {path}: {status} {body}");
        }
        Ok(r.json().await.unwrap_or(Value::Null))
    }

    /// (event, head branch, default branch, job conclusion) of the run behind a job, to
    /// decide whether its cache may be committed. The conclusion is GitHub's, not the console's.
    pub async fn cache_trust(&self, repo: &str, job: u64) -> Result<(String, String, String, String)> {
        // The VM powers off a moment before GitHub records the job's conclusion;
        // without waiting, trusted saves on the default branch would be lost to the race.
        let mut j = self.get(&format!("repos/{repo}/actions/jobs/{job}")).await?;
        for _ in 0..6 {
            if j["status"] == "completed" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            j = self.get(&format!("repos/{repo}/actions/jobs/{job}")).await?;
        }
        let run_id = j["run_id"].as_u64().context("job has no run_id")?;
        let run = self.get(&format!("repos/{repo}/actions/runs/{run_id}")).await?;
        let branch = j["head_branch"].as_str().or(run["head_branch"].as_str()).unwrap_or("").to_string();
        let event = run["event"].as_str().unwrap_or("").to_string();
        let conclusion = j["conclusion"].as_str().unwrap_or("none").to_string();
        let key = repo.to_ascii_lowercase();
        let cached = self.defaults.lock().unwrap().get(&key).filter(|(_, at)| crate::now() < at + 3600).map(|(b, _)| b.clone());
        let default = match cached {
            Some(b) => b,
            None => {
                let b = self.get(&format!("repos/{repo}")).await?["default_branch"].as_str().context("no default_branch")?.to_string();
                self.defaults.lock().unwrap().insert(key, (b.clone(), crate::now()));
                b
            }
        };
        // A pushed *tag* named like the default branch also arrives as
        // event=push, head_branch=main. Only trust it if the commit is really
        // on the default branch (identical to it or an ancestor of it).
        if event == "push" && branch == default {
            let sha = run["head_sha"].as_str().context("run has no head_sha")?;
            let cmp = self.get(&format!("repos/{repo}/compare/{default}...{sha}")).await?;
            if !matches!(cmp["status"].as_str(), Some("identical" | "behind")) {
                return Ok((event, format!("{branch} (commit {:.7} not on {default})", sha), default, conclusion));
            }
        }
        Ok((event, branch, default, conclusion))
    }

    /// Queued jobs per VM size (see `job_size`), counted once per job id.
    /// Sizes above the host's CPU count are not ours and not counted.
    /// Also returns, for jobs picked up by one of our runners (`kiln-*`),
    /// runner name -> (job page, queued-at unix time).
    pub async fn queued_jobs(&self, repo: &str, label: &str, default_cpus: u32) -> Result<(HashMap<u32, usize>, HashMap<String, (String, u64)>)> {
        let host = crate::host_threads();
        let mut queued: HashMap<u64, u32> = HashMap::new();
        let mut ours = HashMap::new();
        // A run is "in_progress" while later jobs of it still wait in the queue,
        // so both statuses have to be scanned.
        for status in ["queued", "in_progress"] {
            let runs = self.get(&format!("repos/{repo}/actions/runs?status={status}&per_page=30")).await?;
            for run in runs["workflow_runs"].as_array().into_iter().flatten() {
                let id = run["id"].as_u64().context("run id")?;
                let jobs = self.get(&format!("repos/{repo}/actions/runs/{id}/jobs?per_page=100")).await?;
                for j in jobs["jobs"].as_array().into_iter().flatten() {
                    if j["status"] == "queued"
                        && let Some(n) = job_size(&j["labels"], label, default_cpus).filter(|&n| n <= host)
                    {
                        queued.insert(j["id"].as_u64().unwrap_or_default(), n);
                    }
                    if let Some(name) = j["runner_name"].as_str().filter(|n| n.starts_with("kiln-"))
                        && let Some(url) = j["html_url"].as_str()
                        && let Some(at) = j["created_at"].as_str().and_then(parse_rfc3339)
                    {
                        ours.insert(name.to_string(), (url.to_string(), at));
                    }
                }
            }
        }
        let mut by_size = HashMap::new();
        for n in queued.into_values() {
            *by_size.entry(n).or_default() += 1;
        }
        Ok((by_size, ours))
    }

    /// Delete offline, idle `kiln-*` runners left behind by a crash.
    pub async fn sweep_runners(&self, repo: &str) -> Result<usize> {
        let v = self.get(&format!("repos/{repo}/actions/runners?per_page=100")).await?;
        let mut n = 0;
        for r in v["runners"].as_array().into_iter().flatten() {
            if let Some(id) = r["id"].as_u64()
                && r["name"].as_str().is_some_and(|n| n.starts_with("kiln-"))
                && r["status"] == "offline"
                && r["busy"] == false
            {
                self.delete_runner(repo, id).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// (status, JSON body) of one call with the stored token; the token never reaches an error.
    async fn api(&self, method: Method, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let r = self.raw(method, path, body).await.map_err(|_| anyhow::anyhow!("could not reach GitHub"))?;
        Ok((r.status, serde_json::from_slice(&r.body).unwrap_or(Value::Null)))
    }

    /// Onboarding: open a PR that adds a hello workflow for `label`. Returns (pr_url, branch).
    // ponytail: a branch left behind by a failed later step is not deleted.
    pub async fn hello_pr(&self, repo: &str, label: &str, t: u64) -> Result<(String, String)> {
        let (st, v) = self.api(Method::GET, &format!("repos/{repo}"), None).await?;
        if st != 200 {
            bail!("{}", hello_err(st, &v, "reading the repo"));
        }
        let default = v["default_branch"].as_str().context("repo has no default_branch")?.to_string();
        let (st, v) = self.api(Method::GET, &format!("repos/{repo}/git/ref/heads/{default}"), None).await?;
        if st != 200 {
            bail!("{}", hello_err(st, &v, "reading the default branch"));
        }
        let base = v["object"]["sha"].as_str().context("default branch has no sha")?.to_string();
        // Build the commit first and point a new branch at it, so the repo sees one
        // push (with the workflow) instead of a bare branch push plus a file push.
        let (st, v) = self.api(Method::GET, &format!("repos/{repo}/git/commits/{base}"), None).await?;
        if st != 200 {
            bail!("{}", hello_err(st, &v, "reading the default branch"));
        }
        let base_tree = v["tree"]["sha"].as_str().context("commit has no tree")?.to_string();
        let file = json!({ "path": ".github/workflows/kiln-hello.yml", "mode": "100644", "type": "blob", "content": hello_workflow(label) });
        let (st, v) = self.api(Method::POST, &format!("repos/{repo}/git/trees"), Some(json!({ "base_tree": base_tree, "tree": [file] }))).await?;
        if st != 201 {
            bail!("{}", hello_err(st, &v, "adding the workflow"));
        }
        let tree = v["sha"].as_str().context("tree has no sha")?.to_string();
        let commit = json!({ "message": "Add kiln hello workflow", "tree": tree, "parents": [base] });
        let (st, v) = self.api(Method::POST, &format!("repos/{repo}/git/commits"), Some(commit)).await?;
        if st != 201 {
            bail!("{}", hello_err(st, &v, "adding the workflow"));
        }
        let sha = v["sha"].as_str().context("commit has no sha")?.to_string();
        let mut branch = format!("kiln-hello-{t}");
        for retry in [true, false] {
            let body = json!({ "ref": format!("refs/heads/{branch}"), "sha": sha });
            let (st, v) = self.api(Method::POST, &format!("repos/{repo}/git/refs"), Some(body)).await?;
            match st {
                201 => break,
                422 if retry => branch = format!("kiln-hello-{}", t + 1),
                _ => bail!("{}", hello_err(st, &v, "creating the branch")),
            }
        }
        let body = json!({ "title": "Try kiln: run a job on your own hardware", "head": branch, "base": default, "body": HELLO_PR_BODY });
        let (st, v) = self.api(Method::POST, &format!("repos/{repo}/pulls"), Some(body)).await?;
        if st != 201 {
            bail!("{}", hello_err(st, &v, "opening the pull request"));
        }
        Ok((v["html_url"].as_str().context("PR has no html_url")?.to_string(), branch))
    }

    /// Returns (runner_id, encoded_jit_config).
    pub async fn jit_config(&self, repo: &str, name: &str, labels: &[String]) -> Result<(u64, String)> {
        let v = self
            .send(
                Method::POST,
                &format!("repos/{repo}/actions/runners/generate-jitconfig"),
                json!({ "name": name, "runner_group_id": 1, "labels": labels, "work_folder": "_work" }),
            )
            .await?;
        let id = v["runner"]["id"].as_u64().context("runner.id missing")?;
        let jit = v["encoded_jit_config"].as_str().context("encoded_jit_config missing")?;
        Ok((id, jit.to_string()))
    }

    /// Unused JIT registrations linger as offline runners; clean them up.
    pub async fn delete_runner(&self, repo: &str, id: u64) -> Result<()> {
        let r = self.exec(self.request(Method::DELETE, &format!("repos/{repo}/actions/runners/{id}"))).await?;
        // 404 = the ephemeral runner already deregistered itself after its job.
        if !r.status().is_success() && r.status() != StatusCode::NOT_FOUND {
            bail!("delete runner {id}: {}", r.status());
        }
        Ok(())
    }
}

const HELLO_PR_BODY: &str = "This adds `.github/workflows/kiln-hello.yml`, a tiny workflow that runs on kiln.\n\n\
kiln is a self-hosted CI that runs each GitHub Actions job in a fresh VM on your own hardware. \
The workflow runs when this PR opens and on demand (workflow_dispatch), prints the VM's size and Docker version, and does nothing else.\n\n\
It is safe to close this PR and delete the branch.";

/// Plain-text reason for a failed onboarding call.
fn hello_err(status: u16, body: &Value, what: &str) -> String {
    match status {
        403 | 404 if what != "reading the repo" => "GitHub refused: the token needs write access to this repo's contents and workflows (classic: repo + workflow scopes; fine-grained: Contents and Workflows: read & write)".into(),
        404 => "repo not found, or the token cannot see it".into(),
        _ => format!("GitHub: {status} while {what}: {}", body["message"].as_str().unwrap_or("no message")),
    }
}

fn hello_workflow(label: &str) -> String {
    format!(
        "name: kiln hello
on:
  pull_request:
  workflow_dispatch:
jobs:
  hello:
    runs-on: [self-hosted, {label}]
    steps:
      - name: Hello from kiln
        run: |
          echo \"Running in a fresh kiln VM on your own hardware\"
          echo \"vCPUs: $(nproc)  RAM: $(free -g | awk '/Mem:/{{print $2}}') GB\"
          docker --version
          uname -r
"
    )
}

/// Allowed `<label>-<N>cpu` sizes.
pub const SIZES: [u32; 4] = [2, 4, 8, 16];

/// RAM for a size label; the default size uses the configured memory instead.
pub fn size_mem_mb(cpus: u32) -> u32 {
    (cpus * 2048).min(24576)
}

/// The VM size a job asks for, if it is ours: every label must be implicit
/// (GitHub adds `self-hosted`, `linux`, `x64` to self-hosted runners) or one
/// of ours, and exactly one of ours must be present. `<label>` is the default
/// size, `<label>-Ncpu` size N. A plain `self-hosted` job is someone else's.
fn job_size(job_labels: &Value, label: &str, default_cpus: u32) -> Option<u32> {
    let label = label.to_ascii_lowercase();
    let mut size = None;
    let mut found = 0;
    for l in job_labels.as_array()? {
        let l = l.as_str()?.to_ascii_lowercase();
        if ["self-hosted", "linux", "x64"].contains(&l.as_str()) {
            continue;
        }
        found += 1;
        size = Some(if l == label {
            default_cpus
        } else {
            // Round-trip so `kiln-04cpu` (which no runner label matches) is not ours.
            let digits = l.strip_prefix(&label)?.strip_prefix('-')?.strip_suffix("cpu")?;
            digits.parse::<u32>().ok().filter(|n| SIZES.contains(n) && n.to_string() == digits)?
        });
    }
    if found == 1 { size } else { None }
}

/// When to stop calling GitHub after a 403/429: until the rate-limit reset if
/// the budget is spent, or for `retry-after` seconds (secondary limits).
fn pause_until(status: u16, remaining: Option<u64>, reset: Option<u64>, retry_after: Option<u64>, now: u64) -> Option<u64> {
    if status != 403 && status != 429 {
        return None;
    }
    match (retry_after, remaining) {
        (Some(s), _) => Some(now + s),
        (None, Some(0)) => reset,
        // A 429 with budget left and no hint is a secondary limit: wait a minute.
        _ if status == 429 => Some(now + 60),
        _ => None,
    }
}

fn secondary_limit(status: u16, body: &str) -> bool {
    status == 403 && body.to_ascii_lowercase().contains("secondary rate limit")
}

/// "2026-10-06T10:51:50Z" -> unix seconds (UTC only, which is all GitHub sends).
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, sec) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // days since 1970-01-01 (Howard Hinnant's days_from_civil)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    u64::try_from(days * 86400 + h * 3600 + mi * 60 + sec).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-10-06T10:51:50Z"), Some(1791283910));
        assert_eq!(parse_rfc3339("2024-02-29T23:59:59Z"), Some(1709251199));
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[test]
    fn rate_pause() {
        assert_eq!(pause_until(403, Some(0), Some(500), None, 100), Some(500));
        assert_eq!(pause_until(429, Some(7), Some(500), Some(60), 100), Some(160));
        assert_eq!(pause_until(403, Some(7), Some(500), None, 100), None);
        assert_eq!(pause_until(200, Some(0), Some(500), None, 100), None);
        assert_eq!(pause_until(429, Some(7), Some(500), None, 100), Some(160));
        assert!(secondary_limit(403, "You have exceeded a Secondary Rate Limit."));
        assert!(!secondary_limit(403, "Resource not accessible"));
        assert!(!secondary_limit(404, "secondary rate limit"));
    }

    #[test]
    fn label_matching() {
        let size = |v: Value| job_size(&v, "kiln", 4);
        assert_eq!(size(json!(["self-hosted", "kiln"])), Some(4));
        assert_eq!(size(json!(["kiln"])), Some(4));
        assert_eq!(size(json!(["Self-Hosted", "Linux", "KILN"])), Some(4));
        assert_eq!(size(json!(["self-hosted", "linux", "x64", "kiln-16cpu"])), Some(16));
        assert_eq!(size(json!(["kiln-8cpu"])), Some(8));
        assert_eq!(size(json!(["self-hosted", "Kiln-2CPU"])), Some(2));
        assert_eq!(size(json!(["kiln-4cpu"])), Some(4));
        assert_eq!(job_size(&json!(["kiln"]), "kiln", 6), Some(6));
        assert_eq!(size(json!(["ubuntu-latest"])), None);
        assert_eq!(size(json!(["self-hosted"])), None);
        assert_eq!(size(json!(["self-hosted", "linux"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln", "gpu"])), None);
        assert_eq!(size(json!(["kiln", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["kiln-8cpu", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["kiln-3cpu"])), None);
        assert_eq!(size(json!(["kiln-04cpu"])), None);
        assert_eq!(size(json!(["kiln-32cpu"])), None);
        assert_eq!(size(json!(["kiln-"])), None);
        assert_eq!(size(json!(["kilnx-8cpu"])), None);
        assert_eq!(size(json!([])), None);
        assert_eq!(size(json!(null)), None);
    }

    #[test]
    fn hello() {
        let w = hello_workflow("kiln");
        assert!(w.contains("runs-on: [self-hosted, kiln]\n") && w.contains("awk '/Mem:/{print $2}'") && w.contains("echo \"vCPUs: $(nproc)"));
        let m = json!({ "message": "Nope" });
        assert!(hello_err(404, &m, "creating the branch").contains("Contents and Workflows"));
        assert!(hello_err(403, &m, "adding the workflow").starts_with("GitHub refused"));
        assert_eq!(hello_err(404, &m, "reading the repo"), "repo not found, or the token cannot see it");
        assert_eq!(hello_err(422, &m, "creating the branch"), "GitHub: 422 while creating the branch: Nope");
    }

    #[test]
    fn size_memory() {
        assert_eq!(size_mem_mb(2), 4096);
        assert_eq!(size_mem_mb(8), 16384);
        assert_eq!(size_mem_mb(16), 24576);
    }
}
