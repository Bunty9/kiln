//! The Gitea forge (5.3 of the forge design): demand from the queued-jobs listing with labels
//! matched client-side, each job joined to its run for event, path and fork status, and the
//! server version that gates what Gitea can do, runner registration over the connect-RPC JSON
//! `Register` call, retire and sweep. All HTTP goes through `net` with the forge's network mode.
//! Verdict facts and logs arrive with GT-3 and fail closed until then.

use super::{
    Caps, Credential, Demand, Dereg, EventKind, ForgeCfg, ForgeId, JobInfo, Kind, Links, Network, RepoRef, RunnerReg, env_name, net,
    read_token_file,
};
use anyhow::{Context, Result, bail};
use base64::Engine;
use reqwest::Method;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Jobs per page of the queue listing, and pages read before kiln gives up (fail closed).
const PAGE: usize = 50;
const MAX_PAGES: usize = 10;
const BODY_CAP: usize = 8 << 20;
const VERSION_TTL: Duration = Duration::from_secs(600);
const RUN_CACHE_MAX: usize = 1000;
/// What `Register` is told the runner is; the server stores it and shows it.
const RUNNER_VERSION: &str = "v5.0.0";
const NOT_OWNER: &str =
    "Gitea refused the runner registration token: the service account must be the repo owner or a member of the organisation's Owners team";

/// Registration works (GT-2), but no VM launches for Gitea until the guest side and the verdict
/// gate land (GT-5 `kiln-gate`, GT-3 facts): demand reports the queue, fork jobs and claims, but
/// no launchable jobs.
const LAUNCH_READY: bool = false;

/// A Gitea server version, compared numerically. The 28.x line is newer than 1.x, so never test `major == 1`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Ver(pub u32, pub u32, pub u32);

impl Ver {
    /// `28.1.0`, `1.25.2+rc1`, `1.26.0-dev-12-gabc`, `v1.25`: the leading dotted numbers.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('v');
        let end = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
        let mut n = s[..end].split('.').map(|p| p.parse::<u32>());
        let major = n.next()?.ok()?;
        let minor = n.next()?.ok()?;
        let patch = n.next().map_or(Some(0), Result::ok)?;
        Some(Self(major, minor, patch))
    }
    /// Below this there is no jobs/runs listing, so no demand query.
    pub fn supported(self) -> bool {
        self >= Self(1, 25, 0)
    }
    /// Rerun, rerun-failed-jobs and the runner `PATCH disabled` (pause, retire).
    pub fn rerun(self) -> bool {
        self >= Self(1, 26, 0)
    }
    pub fn pause(self) -> bool {
        self.rerun()
    }
    /// Cancel, force-cancel and approve.
    pub fn cancel(self) -> bool {
        self >= Self(28, 0, 0)
    }
    pub fn approve(self) -> bool {
        self.cancel()
    }
}

/// What kiln keeps of a run: whether its code may be a fork's, and the dashboard's view of it.
struct RunRec {
    fork: bool,
    run: crate::vm::Run,
}

pub struct Gitea {
    id: ForgeId,
    /// The web origin as configured (no trailing slash): links are same-origin checked against it.
    url: String,
    /// `{url}/api/v1`, the only place requests go.
    api: String,
    mode: net::Mode,
    client: reqwest::Client,
    /// False only in tests, whose mock forge sits on loopback.
    guard: bool,
    cred: Credential,
    /// The install's id (`<data>/install_id`): runner names are `<install>-<vm id>`.
    install: String,
    token: RwLock<Option<String>>,
    version: Mutex<Option<(Ver, Instant)>>,
    runs: Mutex<HashMap<(String, u64), Arc<RunRec>>>,
    /// Runner id -> VM id, filled when GT-2 registers a runner; claims are looked up by it.
    tracked: Mutex<HashMap<u64, String>>,
}

impl Gitea {
    pub fn new(cfg: &ForgeCfg, data: &Path) -> Result<Self> {
        let network = cfg.network.unwrap_or(Network::Public);
        let url = cfg.url.as_deref().with_context(|| format!("forge {:?}: Gitea needs a url", cfg.id.as_str()))?;
        net::check_forge_url(url, network)?;
        let url = url.trim_end_matches('/').to_string();
        let mode = net::Mode::from(network);
        Ok(Self {
            id: cfg.id.clone(),
            api: format!("{url}/api/v1"),
            url,
            mode,
            client: net::client(mode),
            guard: true,
            cred: cfg.credential.unwrap_or(Credential::File),
            install: super::gitlab::install_id(data)?,
            token: RwLock::new(None),
            version: Mutex::new(None),
            runs: Mutex::default(),
            tracked: Mutex::default(),
        })
    }

    /// A forge whose API is the mock on loopback, with `web` as the origin links are checked against.
    #[cfg(test)]
    pub fn for_mock(web: &str, mock: &str, token: &str) -> Self {
        let cfg: ForgeCfg = serde_json::from_value(json!({ "id": "gitea", "kind": "gitea", "url": web })).unwrap();
        let mut g = Self::new(&cfg, &std::env::temp_dir()).unwrap();
        g.install = "a1b2c3".into();
        g.api = format!("{mock}/api/v1");
        g.client = net::base().build().unwrap();
        g.guard = false;
        *g.token.write().unwrap() = Some(token.into());
        g
    }

    pub fn id(&self) -> ForgeId {
        self.id.clone()
    }

    pub fn web_url(&self) -> &str {
        &self.url
    }

    pub fn auth(&self) -> Value {
        json!({ "source": if self.cred == Credential::Env { "env" } else { "file" }, "expires": null })
    }

    /// The dashboard actions (rerun, cancel, dispatch) arrive with their own task; until then no
    /// control is offered. `Ver::rerun` and `Ver::cancel` say when they may be turned on.
    pub fn caps(&self) -> Caps {
        Caps { rerun: false, rerun_failed: false, cancel: false, dispatch: false, workflows: false, live_steps: false }
    }

    /// The credential: the environment variable, or what `load_token` read from the data dir.
    fn token(&self) -> Option<String> {
        let t = match self.cred {
            Credential::Env => std::env::var(env_name(&self.id)).ok(),
            Credential::File => self.token.read().unwrap().clone(),
        };
        // It goes into a header: visible ASCII only.
        t.map(|t| t.trim().to_string()).filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
    }

    pub fn has_credential(&self) -> bool {
        self.token().is_some()
    }

    /// Reads `<data>/forges/<id>.token` for a `file` credential; a missing file means none.
    pub fn load_token(&self, data: &Path) {
        if self.cred != Credential::File {
            return;
        }
        *self.token.write().unwrap() = read_token_file(data, &self.id);
    }

    /// What keeps this forge from polling: no credential, or a server older than 1.25.
    pub fn health(&self) -> Option<String> {
        if !self.has_credential() {
            return Some(match self.cred {
                Credential::Env => format!("no Gitea token: export {}", env_name(&self.id)),
                Credential::File => "no Gitea token: set one in the dashboard".into(),
            });
        }
        match self.cached_version() {
            Some(v) if !v.supported() => Some(unsupported(v)),
            _ => None,
        }
    }

    pub fn repos(&self, cfg: &ForgeCfg) -> Vec<RepoRef> {
        cfg.repos
            .iter()
            .filter_map(|p| RepoRef::parse(&format!("{}:{p}", self.id.as_str())).ok())
            .filter(|r| r.check_kind(Kind::Gitea).is_ok())
            .collect()
    }

    /// Checks the server version now and then; a failure shows in the next `demand`.
    pub async fn refresh(&self) {
        if let Err(e) = self.version().await {
            tracing::debug!("forge {}: version: {e:#}", self.id.as_str());
        }
    }

    fn cached_version(&self) -> Option<Ver> {
        self.version.lock().unwrap().map(|(v, _)| v)
    }

    /// The server version from `GET /version`, cached for ten minutes.
    pub async fn version(&self) -> Result<Ver> {
        if let Some((v, at)) = *self.version.lock().unwrap()
            && at.elapsed() < VERSION_TTL
        {
            return Ok(v);
        }
        let v = self.get("version").await?;
        let s = v["version"].as_str().unwrap_or_default();
        let ver =
            Ver::parse(s).with_context(|| format!("Gitea reported an unreadable version {:?}", s.chars().take(40).collect::<String>()))?;
        *self.version.lock().unwrap() = Some((ver, Instant::now()));
        Ok(ver)
    }

    /// One authenticated API request: the status and the body as JSON (`Null` if it is not).
    async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        let token = self.token().context("no Gitea token")?;
        let mut auth = HeaderValue::from_str(&format!("token {token}"))?;
        auth.set_sensitive(true);
        let mut rb =
            self.client.request(method, format!("{}/{path}", self.api)).header(AUTHORIZATION, auth).header(ACCEPT, "application/json");
        if let Some(b) = body {
            rb = rb.json(b);
        }
        self.finish(rb).await
    }

    async fn finish(&self, rb: reqwest::RequestBuilder) -> Result<(u16, Value)> {
        let r = if self.guard { net::send(&self.client, self.mode, rb).await? } else { rb.send().await? };
        let status = r.status().as_u16();
        let body = net::read_capped(r, BODY_CAP).await?;
        Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    }

    /// Gitea's own message from an error body, one line and cut. It never echoes a credential.
    fn message(v: &Value) -> String {
        v["message"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect()
    }

    /// GET `{api}/{path}` as JSON. A non-2xx answer is an error carrying Gitea's own message,
    /// never the credential.
    async fn get(&self, path: &str) -> Result<Value> {
        let (status, v) = self.call(Method::GET, path, None).await?;
        if !(200..300).contains(&status) {
            bail!("Gitea answered {status} for {path}: {}", Self::message(&v));
        }
        if v.is_null() {
            bail!("Gitea answered {path} with something that is not JSON");
        }
        Ok(v)
    }

    /// Every job of `repo` in `status`, all pages (more than `MAX_PAGES` is an error: a partial
    /// view could hide a fork job).
    async fn jobs(&self, repo: &RepoRef, status: &str) -> Result<Vec<Value>> {
        let mut out: Vec<Value> = vec![];
        let mut seen = HashSet::new();
        for page in 1..=MAX_PAGES {
            let v = self.get(&format!("repos/{}/actions/jobs?status={status}&limit={PAGE}&page={page}", repo.path)).await?;
            let jobs = v["jobs"].as_array().context("jobs listing has no jobs")?;
            let total = v["total_count"].as_u64().unwrap_or(0) as usize;
            // A job can move between pages while we read: count each id once.
            out.extend(jobs.iter().filter(|j| seen.insert(j["id"].as_u64())).cloned());
            if jobs.is_empty() || seen.len() >= total {
                return Ok(out);
            }
        }
        bail!("more than {} {status} jobs: not reading further", MAX_PAGES * PAGE)
    }

    /// The run behind a job (event, path, pull request), fetched once per id.
    async fn run(&self, repo: &RepoRef, id: u64) -> Result<Arc<RunRec>> {
        let key = (repo.path.clone(), id);
        if let Some(r) = self.runs.lock().unwrap().get(&key) {
            return Ok(r.clone());
        }
        let v = self.get(&format!("repos/{}/actions/runs/{id}", repo.path)).await?;
        let rec = Arc::new(run_rec(&self.url, &repo.path, &v));
        let mut c = self.runs.lock().unwrap();
        if c.len() >= RUN_CACHE_MAX {
            c.clear();
        }
        c.insert(key, rec.clone());
        Ok(rec)
    }

    /// Records which VM a registered runner belongs to, so its job is found among the running ones.
    pub fn track(&self, runner_id: u64, vm: &str) {
        self.tracked.lock().unwrap().insert(runner_id, vm.into());
    }

    /// Registers a single-use runner for `repo` and returns what the guest gets: only the
    /// per-runner `.runner` file. The reusable registration token stays in this function.
    ///
    /// `labels` are GitHub-style (`runner_labels`); Gitea has no implicit labels, so those are
    /// dropped. `Register` takes plain names, the `.runner` file the `:host` form (a literal
    /// `kiln:host` registered would match no task until the daemon's `Declare`).
    pub async fn register(&self, repo: &RepoRef, vm: &str, labels: &[String]) -> Result<RunnerReg> {
        repo.check_kind(Kind::Gitea)?;
        let plain: Vec<&str> = labels
            .iter()
            .map(String::as_str)
            .filter(|l| !["self-hosted", "linux", "x64", "arm64"].contains(&l.to_ascii_lowercase().as_str()))
            .collect();
        if plain.is_empty() {
            bail!("no runner labels to register");
        }
        let (status, v) = self.call(Method::POST, &format!("repos/{}/actions/runners/registration-token", repo.path), None).await?;
        match status {
            200..=299 => {}
            403 => bail!(NOT_OWNER),
            _ => bail!("Gitea answered {status} for the registration token of {}: {}", repo.path, Self::message(&v)),
        }
        let reg_token = v["token"].as_str().filter(|t| !t.is_empty()).context("Gitea sent no registration token")?;
        let name = format!("{}-{vm}", self.install);
        let body = json!({ "name": name, "token": reg_token, "version": RUNNER_VERSION, "labels": plain, "ephemeral": true });
        // Connect-RPC over JSON, no auth header: the registration token in the body is the credential.
        // `self.api` is `{origin}/api/v1`; the RPC lives at `{origin}/api/actions/...`.
        let rpc = format!("{}/actions/runner.v1.RunnerService/Register", self.api.strip_suffix("/v1").context("api url")?);
        let (status, v) = self.finish(self.client.post(rpc).json(&body)).await?;
        if !(200..300).contains(&status) {
            bail!("Gitea answered {status} for runner registration of {name}: {}", Self::message(&v));
        }
        let r = &v["runner"];
        let id = r["id"].as_str().and_then(|i| i.parse::<u64>().ok()).or(r["id"].as_u64()).filter(|&i| i > 0);
        let (Some(id), Some(uuid), Some(token)) = (id, r["uuid"].as_str(), r["token"].as_str().filter(|t| !t.is_empty())) else {
            bail!("Gitea's registration answer for {name} has no runner id, uuid or token");
        };
        let dot_runner = json!({
            "id": id, "uuid": uuid, "name": name, "token": token, "address": self.url,
            "labels": plain.iter().map(|l| format!("{l}:host")).collect::<Vec<_>>(), "ephemeral": true,
        });
        self.track(id, vm);
        let cred = base64::engine::general_purpose::STANDARD.encode(dot_runner.to_string());
        Ok(RunnerReg { runner_id: id, guest_secret: format!("kiln.forge=gitea\nkiln.cred={cred}") })
    }

    /// Drops a runner kiln registered (retire, 3.3 of the forge design). The `busy` field is never
    /// consulted: it stays false while a task is assigned.
    /// - 1.26+: disable (no new task), see whether a job is in progress on it, delete only if not.
    ///   A job in progress: leave it, the entry deletes itself when the job ends (`Busy`).
    /// - 1.25: no disable, so a delete could strand a job being assigned. The runner idles out
    ///   (`Busy`) unless it is already gone.
    pub async fn deregister(&self, repo: &RepoRef, runner_id: u64) -> Dereg {
        let r = async {
            repo.check_kind(Kind::Gitea)?;
            if self.version().await?.rerun() {
                return self.retire(repo, runner_id, true).await;
            }
            let (status, v) = self.call(Method::GET, &format!("repos/{}/actions/runners/{runner_id}", repo.path), None).await?;
            match status {
                404 => Ok(Dereg::Gone),
                200..=299 => Ok(Dereg::Busy),
                _ => bail!("Gitea answered {status} for runner {runner_id}: {}", Self::message(&v)),
            }
        };
        let d = r.await.unwrap_or_else(Dereg::Err);
        if matches!(d, Dereg::Gone) {
            self.tracked.lock().unwrap().remove(&runner_id);
        }
        d
    }

    /// Disable (when the server can), check for a job, delete. 404 at any step: already gone.
    async fn retire(&self, repo: &RepoRef, runner_id: u64, disable: bool) -> Result<Dereg> {
        let path = format!("repos/{}/actions/runners/{runner_id}", repo.path);
        if disable {
            let (status, v) = self.call(Method::PATCH, &path, Some(&json!({ "disabled": true }))).await?;
            match status {
                404 => return Ok(Dereg::Gone),
                200..=299 => {}
                _ => bail!("Gitea answered {status} disabling runner {runner_id}: {}", Self::message(&v)),
            }
        }
        // An unreadable listing is an error, not "no job": a delete here could strand one.
        if self.jobs(repo, "in_progress").await?.iter().any(|j| j["runner_id"].as_u64() == Some(runner_id)) {
            return Ok(Dereg::Busy);
        }
        let (status, v) = self.call(Method::DELETE, &path, None).await?;
        match status {
            200..=299 | 404 => Ok(Dereg::Gone),
            _ => bail!("Gitea answered {status} deleting runner {runner_id}: {}", Self::message(&v)),
        }
    }

    /// Removes this install's offline runners (a crashed kiln leaves them), by the same
    /// check-then-delete sequence. Returns how many were deleted.
    pub async fn sweep(&self, repo: &RepoRef) -> Result<usize> {
        repo.check_kind(Kind::Gitea)?;
        let disable = self.version().await?.rerun();
        let prefix = format!("{}-", self.install);
        // Listed in full before anything is deleted, so a delete cannot shift the pages.
        let mut stale = vec![];
        let mut seen = HashSet::new();
        'pages: {
            for page in 1..=MAX_PAGES {
                let v = self.get(&format!("repos/{}/actions/runners?limit={PAGE}&page={page}", repo.path)).await?;
                let runners = v["runners"].as_array().context("runner listing has no runners")?;
                for r in runners {
                    let Some(id) = r["id"].as_u64().filter(|&id| seen.insert(id)) else { continue };
                    if r["name"].as_str().is_some_and(|n| n.starts_with(&prefix)) && r["status"] == "offline" {
                        stale.push(id);
                    }
                }
                if runners.is_empty() || seen.len() >= v["total_count"].as_u64().unwrap_or(0) as usize {
                    break 'pages;
                }
            }
            bail!("more than {} runners: not reading further", MAX_PAGES * PAGE)
        }
        let mut n = 0;
        for id in stale {
            match self.retire(repo, id, disable).await {
                Ok(Dereg::Gone) => n += 1,
                Ok(_) => {}
                Err(e) => tracing::warn!("{}: stale runner {id}: {e:#}", repo.path),
            }
        }
        Ok(n)
    }

    pub async fn demand(&self, repo: &RepoRef, label: &str, default_cpus: u32) -> Result<Demand> {
        let mut d = self.demand_with(repo, label, default_cpus, crate::host_threads()).await?;
        if !LAUNCH_READY {
            d.by_size.clear();
        }
        Ok(d)
    }

    async fn demand_with(&self, repo: &RepoRef, label: &str, default_cpus: u32, host: u32) -> Result<Demand> {
        repo.check_kind(Kind::Gitea)?;
        let ver = self.version().await?;
        if !ver.supported() {
            bail!("{}", unsupported(ver));
        }
        let mut d = Demand::default();
        // `queued` is ready to run. The status is checked again here: `waiting` (a fork run
        // awaiting approval) and `requested` (blocked by `needs`) are never demand.
        for j in self.jobs(repo, "queued").await?.iter().filter(|j| j["status"] == "queued") {
            // The server ignores a `labels` filter, so the job's labels are judged here.
            let Some(n) = super::job_size(&j["labels"], label, default_cpus, crate::platform::host_arm64()) else { continue };
            let run = self.run(repo, j["run_id"].as_u64().context("job has no run_id")?).await?;
            if run.fork {
                d.refused_forks += 1;
                d.fork_queued = true;
            } else if n <= host {
                *d.by_size.entry(n).or_default() += 1;
            }
        }
        let tracked = self.tracked.lock().unwrap().clone();
        if !tracked.is_empty() {
            for j in self.jobs(repo, "in_progress").await? {
                let Some(vm) = j["runner_id"].as_u64().and_then(|r| tracked.get(&r)) else { continue };
                let run = self.run(repo, j["run_id"].as_u64().context("job has no run_id")?).await?;
                let mut r = run.run.clone();
                r.links.job = j["html_url"].as_str().filter(|u| net::same_origin(&self.url, u) && net::link_safe(u)).map(String::from);
                d.claimed.insert(
                    vm.clone(),
                    JobInfo {
                        id: j["id"].as_u64().context("job id")?.to_string(),
                        url: r.links.job.clone().unwrap_or_default(),
                        queued_at: j["created_at"].as_str().and_then(crate::github::parse_rfc3339).unwrap_or(0),
                        fork: run.fork,
                        run: r,
                    },
                );
            }
        }
        Ok(d)
    }
}

fn unsupported(v: Ver) -> String {
    format!("Gitea {}.{}.{} is older than 1.25: it has no jobs listing, so kiln cannot see the queue", v.0, v.1, v.2)
}

/// Would this run's code come from outside the repo? Fails closed: a missing or different head
/// repository, or a run whose source cannot be told, is a fork.
///
/// - A fork PR run has `head_branch` null; the signal is `pull_requests[0].head.repo` against
///   `base.repo` (repo ids).
/// - `pull_request_target` counts: it runs with no approval, on a fork author's say.
/// - Every `workflow_run` counts: the run names neither the triggering run nor its head repo.
/// - Approval status is not consulted. A fork run that is `queued` because its poster has a
///   merged PR is still a fork.
fn is_fork(run: &Value) -> bool {
    let (event, path) = (run["event"].as_str().unwrap_or(""), run["path"].as_str().unwrap_or(""));
    if event.is_empty() || event == "workflow_run" {
        return true;
    }
    if !(event.starts_with("pull_request") || path.contains("@refs/pull/")) {
        return false;
    }
    let pr = &run["pull_requests"][0];
    let id = |side: &str| pr[side]["repo"]["id"].as_u64().filter(|&i| i > 0);
    !matches!((id("head"), id("base")), (Some(h), Some(b)) if h == b)
}

fn event_kind(event: &str, path: &str) -> EventKind {
    match event {
        "push" if path.contains("@refs/tags/") => EventKind::Tag,
        "push" => EventKind::Push,
        "pull_request" | "pull_request_target" => EventKind::PullRequest,
        "workflow_dispatch" => EventKind::Manual,
        "schedule" => EventKind::Schedule,
        "release" => EventKind::Release,
        _ => EventKind::Other,
    }
}

fn run_rec(web: &str, repo: &str, r: &Value) -> RunRec {
    let s = |v: &Value| v.as_str().unwrap_or("").chars().take(200).collect::<String>();
    let (event, path) = (s(&r["event"]), s(&r["path"]));
    // `t.yml@refs/heads/main`: the file is before the `@`.
    let file = path.split('@').next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
    let pr = &r["pull_requests"][0];
    // A fork PR run has no head_branch; the PR's head ref is shown instead (display only).
    let branch = Some(s(&r["head_branch"])).filter(|b| !b.is_empty()).unwrap_or_else(|| s(&pr["head"]["ref"]));
    let sha = s(&r["head_sha"]);
    let pr_n = pr["number"].as_u64();
    let base = format!("{web}/{repo}");
    let ok_branch = !branch.is_empty()
        && branch.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
        && !branch.split('/').any(|p| p.is_empty() || p == "." || p == "..");
    let links = Links {
        run: r["html_url"].as_str().filter(|u| net::same_origin(web, u) && net::link_safe(u)).map(String::from),
        job: None,
        commit: (!sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("{base}/commit/{sha}")),
        pr: pr_n.map(|n| format!("{base}/pulls/{n}")),
        branch: ok_branch.then(|| format!("{base}/src/branch/{branch}")),
    };
    RunRec {
        fork: is_fork(r),
        run: crate::vm::Run {
            branch,
            sha,
            pr: pr_n,
            title: s(&r["display_title"]),
            // Gitea's run record has no workflow name; the file name stands in.
            workflow: file.clone(),
            number: r["run_number"].as_u64().unwrap_or_default(),
            file,
            kind: event_kind(&event, &path),
            event,
            links,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge_test_mock::{Mock, fixture_in};

    const WEB: &str = "https://gitea.example.org";
    const API: &str = "/api/v1/repos/acme/demo/actions";

    fn fx(name: &str) -> String {
        fixture_in("gitea", name)
    }

    fn repo() -> RepoRef {
        RepoRef::parse("gitea:acme/demo").unwrap()
    }

    fn jobs_q(status: &str) -> String {
        format!("GET {API}/jobs?status={status}&limit=50&page=1")
    }

    /// The mock with `/version` and the run records every fixture job refers to.
    async fn mock() -> (Mock, Gitea) {
        let m = Mock::start().await;
        m.route("GET", "/api/v1/version", 200, fx("version.json"));
        for (id, f) in [
            (70, "run_70"),
            (71, "run_71"),
            (72, "run_72"),
            (73, "run_73"),
            (74, "run_74"),
            (75, "run_75"),
            (76, "run_76"),
            (77, "run_77"),
            (78, "run_78"),
        ] {
            m.route("GET", &format!("{API}/runs/{id}"), 200, fx(&format!("{f}.json")));
        }
        let g = Gitea::for_mock(WEB, &m.base, "tok");
        (m, g)
    }

    fn serve(m: &Mock, status: &str, file: &str) {
        let (method, path) = jobs_q(status).split_once(' ').map(|(a, b)| (a.to_string(), b.to_string())).unwrap();
        m.route(&method, &path, 200, fx(file));
    }

    fn sizes(d: &Demand) -> Vec<(u32, usize)> {
        let mut v: Vec<_> = d.by_size.iter().map(|(k, n)| (*k, *n)).collect();
        v.sort();
        v
    }

    #[test]
    fn versions_compare_numerically() {
        fn p(s: &str) -> Ver {
            Ver::parse(s).unwrap()
        }
        assert_eq!(p("28.1.0"), Ver(28, 1, 0));
        assert_eq!(p("1.25.2+rc1"), Ver(1, 25, 2));
        assert_eq!(p("1.26.0-dev-12-gabc"), Ver(1, 26, 0));
        assert_eq!(p("v1.25"), Ver(1, 25, 0));
        for bad in ["", "dev", "1", "1.x.0", "1..0"] {
            assert_eq!(Ver::parse(bad), None, "{bad:?}");
        }
        // 28 is newer than 1.x, and 1.100 is newer than 1.25, which string order gets wrong.
        assert!(p("28.0.0") > p("1.100.0") && p("1.100.0") > p("1.25.0") && p("1.25.0") > p("1.9.0"));
        let gates = |v: &str| {
            let v = p(v);
            [v.supported(), v.rerun(), v.pause(), v.cancel(), v.approve()]
        };
        assert_eq!(gates("1.24.6"), [false; 5]);
        assert_eq!(gates("1.25.0"), [true, false, false, false, false]);
        assert_eq!(gates("1.26.0"), [true, true, true, false, false]);
        assert_eq!(gates("1.26.3"), [true, true, true, false, false]);
        assert_eq!(gates("1.27.0"), [true, true, true, false, false]);
        assert_eq!(gates("28.0.0"), [true; 5]);
        assert_eq!(gates("28.1.0"), [true; 5]);
    }

    #[tokio::test]
    async fn version_is_read_once_and_gates_demand() {
        let (m, g) = mock().await;
        assert_eq!(g.version().await.unwrap(), Ver(28, 1, 0));
        assert_eq!(g.version().await.unwrap(), Ver(28, 1, 0));
        assert_eq!(m.requests(), ["GET /api/v1/version"]);
        assert_eq!(g.health(), None);
        // Below the floor: health says so and demand refuses before listing anything.
        let (m, g) = mock().await;
        m.route("GET", "/api/v1/version", 200, r#"{"version":"1.24.6"}"#);
        g.refresh().await;
        assert!(g.health().unwrap().contains("older than 1.25"));
        let e = g.demand(&repo(), "kiln", 2).await.unwrap_err();
        assert!(e.to_string().contains("older than 1.25"), "{e:#}");
        assert_eq!(m.requests(), ["GET /api/v1/version"]);
        m.route("GET", "/api/v1/version", 200, r#"{"version":"garbage"}"#);
        *g.version.lock().unwrap() = None;
        assert!(g.version().await.unwrap_err().to_string().contains("unreadable version"));
    }

    #[tokio::test]
    async fn waiting_and_blocked_jobs_are_not_demand_and_labels_match_client_side() {
        let (m, g) = mock().await;
        // The recorded queue while a fork PR awaits approval (job 90 is `waiting`, so the
        // server leaves it out). Same-repo: jobs 76 (kiln), 77 (kiln-4cpu), 81-84 PR checks, 85 and 86
        // the tag run's. Not ours: 78 ubuntu-latest, 79 [kiln, gpu]. Job 91 is a queued
        // pull_request_target fork job.
        serve(&m, "queued", "jobs_queued_a.json");
        let d = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert_eq!(sizes(&d), [(2, 6), (4, 2)]);
        assert_eq!((d.refused_forks, d.fork_queued), (1, true));
        // Even if a server returned `waiting` and `requested` jobs here, they are not counted.
        let (m2, g2) = mock().await;
        serve(&m2, "queued", "jobs_all_a.json");
        let d2 = g2.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert_eq!((sizes(&d2), d2.refused_forks, d2.fork_queued), (sizes(&d), 1, true));
        // A size the host cannot run is not demand (still a fork if it is one).
        let d = g.demand_with(&repo(), "kiln", 2, 2).await.unwrap();
        assert_eq!(sizes(&d), [(2, 6)]);
        // Another label prefix matches only its own jobs.
        let d = g.demand_with(&repo(), "gpu", 2, 16).await.unwrap();
        assert_eq!((sizes(&d), d.refused_forks, d.fork_queued), (vec![], 0, false));
        let _ = m;
    }

    #[tokio::test]
    async fn a_waiting_fork_alone_is_not_fork_queued_but_approval_makes_it_so() {
        let (m, g) = mock().await;
        // Fork PR run 76 `waiting` (job 90): the queue has no fork job at all. Drop the
        // pull_request_target fork job (91) from the recorded listing.
        let mut v: Value = serde_json::from_str(&fx("jobs_queued_a.json")).unwrap();
        v["jobs"].as_array_mut().unwrap().retain(|j| j["id"] != 91);
        v["total_count"] = json!(12);
        m.route("GET", jobs_q("queued").strip_prefix("GET ").unwrap(), 200, v.to_string());
        let d = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert_eq!((d.refused_forks, d.fork_queued), (0, false));
        assert_eq!(sizes(&d), [(2, 6), (4, 2)]);
        // After approval (and with the poster maybe holding a merged PR, which changes nothing
        // here: the rule is the head repo): queued fork PR job 90, pull_request_target job 91
        // and the workflow_run job 92 are all fork.
        let (m, g) = mock().await;
        serve(&m, "queued", "jobs_queued_b.json");
        let d = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert_eq!(sizes(&d), [(2, 5), (4, 1)]);
        assert_eq!((d.refused_forks, d.fork_queued), (3, true));
    }

    #[tokio::test]
    async fn runs_are_fetched_once_and_requests_are_authenticated() {
        let (m, g) = mock().await;
        serve(&m, "queued", "jobs_queued_b.json");
        g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        // Runs 71-75 (the tag run 75 has two ours jobs) and 76-78; 79 and the hosted job are skipped as not ours.
        let reqs = m.requests();
        let mut want = vec!["GET /api/v1/version".to_string(), jobs_q("queued")];
        want.extend((71..=78).map(|n| format!("GET {API}/runs/{n}")));
        assert_eq!(reqs, want);
        assert!(m.log().iter().all(|r| r.auth.as_deref() == Some("token tok")));
        m.clear_log();
        g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert_eq!(m.requests(), [jobs_q("queued")], "version and runs come from the cache");
    }

    #[tokio::test]
    async fn claimed_jobs_are_found_by_the_runner_id_kiln_recorded() {
        let (m, g) = mock().await;
        serve(&m, "queued", "jobs_queued_b.json");
        serve(&m, "in_progress", "jobs_in_progress.json");
        m.route("GET", &format!("{API}/runs/70"), 200, fx("run_70_in_progress.json"));
        // Nothing recorded: the running list is not even read.
        assert!(g.demand_with(&repo(), "kiln", 2, 16).await.unwrap().claimed.is_empty());
        assert!(!m.requests().contains(&jobs_q("in_progress")));
        g.track(999, "kiln-5-1");
        assert!(g.demand_with(&repo(), "kiln", 2, 16).await.unwrap().claimed.is_empty());
        g.track(51, "kiln-5-0");
        let d = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        let j = &d.claimed["kiln-5-0"];
        assert_eq!((j.id.as_str(), j.fork), ("76", false));
        assert_eq!(j.url, format!("{WEB}/acme/demo/actions/runs/70/jobs/76"));
        assert!(j.queued_at > 1_700_000_000);
        let r = &j.run;
        assert_eq!((r.branch.as_str(), r.event.as_str(), r.kind, r.title.as_str()), ("main", "push", EventKind::Push, "add workflows"));
        assert_eq!((r.workflow.as_str(), r.file.as_str(), r.number, r.pr), ("push.yml", "push.yml", 1, None));
        assert_eq!(r.links.commit.as_deref(), Some(format!("{WEB}/acme/demo/commit/{}", r.sha).as_str()));
        assert_eq!(r.links.branch.as_deref(), Some(&*format!("{WEB}/acme/demo/src/branch/main")));
        assert_eq!(r.links.run.as_deref(), Some(&*format!("{WEB}/acme/demo/actions/runs/70")));
    }

    #[test]
    fn fork_rule_by_event_path_and_head_repo() {
        let rec = |f: &str| run_rec(WEB, "acme/demo", &serde_json::from_str(&fx(f)).unwrap());
        // push to a branch and to a tag: not forks; the tag run has no head_branch either.
        assert!(!rec("run_70.json").fork);
        let tag = rec("run_75.json");
        assert!(!tag.fork && tag.run.kind == EventKind::Tag && tag.run.branch.is_empty());
        // Same-repo PR, pull_request and pull_request_target: head repo id equals the base's.
        for f in ["run_71.json", "run_72.json", "run_73.json", "run_74.json"] {
            let r = rec(f);
            assert!(!r.fork && r.run.pr == Some(1) && r.run.kind == EventKind::PullRequest, "{f}");
            assert_eq!(r.run.branch, "feat-x", "head_branch is null: the PR's head ref is shown");
        }
        // Fork PR, waiting or approved, and a pull_request_target from the same fork: all fork.
        for f in ["run_76.json", "run_76_approved.json", "run_77.json"] {
            assert!(rec(f).fork, "{f}");
        }
        // Every workflow_run is refused, whatever the run record says.
        let wr = rec("run_78.json");
        assert!(wr.fork && wr.run.pr.is_none());
        // Fail closed: no pull request, a deleted head repo, a zero id, an unknown event.
        let fork = |v: Value| is_fork(&v);
        let pr = |head: Value| {
            json!({"event": "pull_request", "path": "t.yml@refs/pull/3/head",
            "pull_requests": [{"number": 3, "head": {"repo": head}, "base": {"repo": {"id": 5}}}]})
        };
        assert!(!fork(pr(json!({"id": 5}))));
        assert!(fork(pr(json!({"id": 6}))) && fork(pr(json!(null))) && fork(pr(json!({"id": 0}))));
        assert!(fork(json!({"event": "pull_request", "path": "t.yml@refs/pull/3/head", "pull_requests": []})));
        assert!(fork(
            json!({"event": "pull_request_target", "pull_requests": [{"head": {"repo": {"id": 6}}, "base": {"repo": {"id": 5}}}]})
        ));
        assert!(fork(json!({"event": "pull_request_review", "pull_requests": []})));
        assert!(fork(json!({"event": "push", "path": "t.yml@refs/pull/3/head"})), "a PR ref on a push is not trusted");
        assert!(fork(json!({})) && fork(json!({"event": ""})));
        assert!(!fork(json!({"event": "workflow_dispatch", "path": "t.yml@refs/heads/main"})));
        assert!(!fork(json!({"event": "schedule"})));
    }

    #[test]
    fn unsafe_branch_names_get_no_link() {
        let l = |b: &str| run_rec(WEB, "acme/demo", &json!({"event": "push", "head_branch": b})).run.links.branch;
        assert!(l("feat/x").is_some());
        for bad in ["a/../x", "..", "a//b", "a b", "a\"b", "a?b#c"] {
            assert_eq!(l(bad), None, "{bad}");
        }
        // A run page on another origin is not linked.
        let r = run_rec(WEB, "acme/demo", &json!({"event": "push", "html_url": "https://evil.example/acme/demo/actions/runs/1"}));
        assert_eq!(r.run.links.run, None);
    }

    #[tokio::test]
    async fn pages_are_read_to_the_end_and_a_flood_fails_closed() {
        let (m, g) = mock().await;
        let job = |id: u64| json!({"id": id, "run_id": 70, "status": "queued", "labels": ["ubuntu-latest"]});
        let page = |p: u32, ids: std::ops::Range<u64>| {
            m.route(
                "GET",
                &format!("{API}/jobs?status=queued&limit=50&page={p}"),
                200,
                json!({"jobs": ids.map(job).collect::<Vec<_>>(), "total_count": 70}).to_string(),
            )
        };
        page(1, 0..50);
        page(2, 50..70);
        let d = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap();
        assert!(d.by_size.is_empty());
        assert_eq!(m.requests().iter().filter(|r| r.contains("/jobs?")).count(), 2);
        // 10 full pages and still more: no partial view.
        for p in 1..=10 {
            m.route(
                "GET",
                &format!("{API}/jobs?status=queued&limit=50&page={p}"),
                200,
                json!({"jobs": (p as u64 * 100..p as u64 * 100 + 50).map(job).collect::<Vec<_>>(), "total_count": 9999}).to_string(),
            );
        }
        let e = g.demand_with(&repo(), "kiln", 2, 16).await.unwrap_err();
        assert!(e.to_string().contains("not reading further"), "{e:#}");
    }

    #[tokio::test]
    async fn errors_carry_gitea_text_and_never_the_token() {
        let (m, g) = mock().await;
        m.route("GET", &jobs_q("queued").replace("GET ", ""), 401, fx("err_401.json"));
        let e = format!("{:#}", g.demand_with(&repo(), "kiln", 2, 16).await.unwrap_err());
        assert!(e.contains("401") && e.contains("token is required") && !e.contains("tok\"") && !e.contains("token tok"), "{e}");
        // A job whose run is gone: the whole demand errors (no launches on a partial view).
        serve(&m, "queued", "jobs_queued_b.json");
        m.route("GET", &format!("{API}/runs/77"), 404, fx("err_404_run.json"));
        let e = format!("{:#}", g.demand_with(&repo(), "kiln", 2, 16).await.unwrap_err());
        assert!(e.contains("404") && e.contains("resource does not exist"), "{e}");
        // The repo is not Gitea's to read, or not found.
        m.route("GET", "/api/v1/repos/acme/nope/actions/jobs?status=queued&limit=50&page=1", 404, fx("err_404_repo.json"));
        let gone = RepoRef::parse("gitea:acme/nope").unwrap();
        assert!(g.demand_with(&gone, "kiln", 2, 16).await.unwrap_err().to_string().contains("404"));
        assert!(g.demand_with(&RepoRef::parse("acme/demo").unwrap(), "kiln", 2, 16).await.is_err(), "a GitHub repo is refused");
    }

    #[tokio::test]
    async fn no_launchable_demand_until_registration_exists() {
        let (m, g) = mock().await;
        serve(&m, "queued", "jobs_queued_b.json");
        let d = g.demand(&repo(), "kiln", 2).await.unwrap();
        assert!(d.by_size.is_empty());
        assert_eq!((d.refused_forks, d.fork_queued), (3, true));
    }

    const RUNNERS: &str = "/api/v1/repos/acme/demo/actions/runners";
    const REG_TOKEN: &str = "REGISTRATION-TOKEN-REDACTED";

    fn labels() -> Vec<String> {
        ["self-hosted", "linux", "x64", "kiln", "kiln-4cpu"].map(String::from).to_vec()
    }

    fn jobs_running(runner: u64) -> String {
        json!({"jobs": [{"id": 5, "status": "in_progress", "runner_id": runner}], "total_count": 1}).to_string()
    }

    /// The mock with the routes a healthy 1.26+ retire of runner 52 takes.
    async fn retire_mock(version: &str) -> (Mock, Gitea) {
        let (m, g) = mock().await;
        m.route("GET", "/api/v1/version", 200, json!({ "version": version }).to_string());
        m.route("PATCH", &format!("{RUNNERS}/52"), 200, fx("runner_disabled.json"));
        m.route("GET", &format!("{RUNNERS}/52"), 200, fx("runner_disabled.json"));
        m.route("DELETE", &format!("{RUNNERS}/52"), 204, "");
        m.route("GET", &format!("{API}/jobs?status=in_progress&limit=50&page=1"), 200, r#"{"jobs":[],"total_count":0}"#);
        (m, g)
    }

    #[tokio::test]
    async fn register_over_rpc_and_hand_the_guest_only_the_runner_file() {
        let (m, g) = mock().await;
        m.route("POST", &format!("{RUNNERS}/registration-token"), 200, fx("registration_token.json"));
        m.route("POST", "/api/actions/runner.v1.RunnerService/Register", 200, fx("register.json"));
        let reg = g.register(&repo(), "kiln-fx-1", &labels()).await.unwrap();
        assert_eq!(reg.runner_id, 52);
        let log = m.log();
        assert_eq!(
            m.requests(),
            [format!("POST {RUNNERS}/registration-token"), "POST /api/actions/runner.v1.RunnerService/Register".into()]
        );
        assert_eq!(log[0].auth.as_deref(), Some("token tok"));
        // The RPC carries no API credential, and plain label names (no `:host`, no implicit ones).
        assert_eq!(log[1].auth, None);
        assert_eq!(log[1].body, Some(serde_json::from_str(&fx("register_request.json")).unwrap()));
        // The guest gets the per-runner `.runner` file and nothing else.
        let lines: Vec<&str> = reg.guest_secret.lines().collect();
        assert_eq!(lines[0], "kiln.forge=gitea");
        let raw = base64::engine::general_purpose::STANDARD.decode(lines[1].strip_prefix("kiln.cred=").unwrap()).unwrap();
        let dot: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            dot,
            json!({"id": 52, "uuid": "00000000-0000-4000-8000-000000000000", "name": "a1b2c3-kiln-fx-1", "token": "RUNNER-TOKEN-REDACTED",
                   "address": "https://gitea.example.org", "labels": ["kiln:host", "kiln-4cpu:host"], "ephemeral": true})
        );
        assert!(!reg.guest_secret.contains(REG_TOKEN) && !String::from_utf8_lossy(&raw).contains(REG_TOKEN));
        assert_eq!(g.tracked.lock().unwrap().get(&52).map(String::as_str), Some("kiln-fx-1"));
    }

    #[tokio::test]
    async fn registration_failures_are_named_and_never_carry_the_token() {
        let (m, g) = mock().await;
        let tok = format!("{RUNNERS}/registration-token");
        m.route("POST", &tok, 403, fx("registration_token_403.json"));
        let e = g.register(&repo(), "v", &labels()).await.err().unwrap();
        assert!(e.to_string().contains("Owners team"), "{e:#}");
        m.route("POST", &tok, 200, fx("registration_token.json"));
        m.route("POST", "/api/actions/runner.v1.RunnerService/Register", 500, fx("register_bad_token.json"));
        let e = g.register(&repo(), "v", &labels()).await.err().unwrap();
        assert!(e.to_string().contains("registration token not found"), "{e:#}");
        // A 2xx without a runner is an error too; no error text holds the token.
        m.route("POST", "/api/actions/runner.v1.RunnerService/Register", 200, r#"{"runner":{"id":"0"}}"#);
        let e = g.register(&repo(), "v", &labels()).await.err().unwrap();
        assert!(!format!("{e:?}").contains(REG_TOKEN));
        // Nothing of ours to register (only GitHub's implicit labels) never reaches the server.
        m.clear_log();
        assert!(g.register(&repo(), "v", &["self-hosted".into(), "Linux".into(), "ARM64".into()]).await.is_err());
        assert!(m.requests().is_empty());
        assert!(g.tracked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retire_disables_checks_then_deletes() {
        let (m, g) = retire_mock("28.1.0").await;
        g.track(52, "vm");
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Gone));
        let log = m.log();
        assert_eq!(
            m.requests(),
            [
                "GET /api/v1/version".to_string(),
                format!("PATCH {RUNNERS}/52"),
                format!("GET {API}/jobs?status=in_progress&limit=50&page=1"),
                format!("DELETE {RUNNERS}/52")
            ]
        );
        assert_eq!(log[1].body, Some(json!({"disabled": true})));
        assert!(g.tracked.lock().unwrap().is_empty());
        // A job on the runner: it stays (disabled), is never deleted, and stays tracked. `busy` is not read.
        m.clear_log();
        m.route("GET", &format!("{API}/jobs?status=in_progress&limit=50&page=1"), 200, jobs_running(52));
        g.track(52, "vm");
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Busy));
        assert!(!m.requests().iter().any(|r| r.starts_with("DELETE")));
        assert_eq!(g.tracked.lock().unwrap().len(), 1);
        // Another runner's job does not hold this one.
        m.route("GET", &format!("{API}/jobs?status=in_progress&limit=50&page=1"), 200, jobs_running(53));
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Gone));
    }

    #[tokio::test]
    async fn retire_fails_closed() {
        let (m, g) = retire_mock("28.1.0").await;
        // Already gone: 404 on the disable (or the delete) is Gone.
        m.route("PATCH", &format!("{RUNNERS}/52"), 404, fx("runner_404.json"));
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Gone));
        m.route("PATCH", &format!("{RUNNERS}/52"), 200, fx("runner_disabled.json"));
        m.route("DELETE", &format!("{RUNNERS}/52"), 404, fx("runner_404.json"));
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Gone));
        // An unreadable job listing is an error and nothing is deleted.
        m.clear_log();
        m.route("GET", &format!("{API}/jobs?status=in_progress&limit=50&page=1"), 500, "{}");
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Err(_)));
        assert!(!m.requests().iter().any(|r| r.starts_with("DELETE")));
        // A refused disable: no check, no delete.
        m.clear_log();
        m.route("PATCH", &format!("{RUNNERS}/52"), 403, r#"{"message":"no"}"#);
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Err(_)));
        assert_eq!(m.requests(), [format!("PATCH {RUNNERS}/52")]);
    }

    #[tokio::test]
    async fn retire_on_1_25_never_deletes_a_runner_that_may_hold_a_job() {
        let (m, g) = retire_mock("1.25.3").await;
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Busy));
        assert_eq!(m.requests(), ["GET /api/v1/version".to_string(), format!("GET {RUNNERS}/52")]);
        // Gone on its own (it took a job and deleted itself).
        m.route("GET", &format!("{RUNNERS}/52"), 404, fx("runner_404.json"));
        assert!(matches!(g.deregister(&repo(), 52).await, Dereg::Gone));
        assert!(m.requests().iter().all(|r| !r.starts_with("DELETE") && !r.starts_with("PATCH")));
    }

    #[tokio::test]
    async fn sweep_removes_only_this_installs_offline_runners() {
        let (m, g) = retire_mock("28.1.0").await;
        let list = |rs: Vec<Value>| json!({"runners": rs, "total_count": rs.len()}).to_string();
        let r = |id: u64, name: &str, status: &str| json!({"id": id, "name": name, "status": status});
        let page = format!("{RUNNERS}?limit=50&page=1");
        m.route(
            "GET",
            &page,
            200,
            list(vec![
                r(52, "a1b2c3-vm-1", "offline"),
                r(60, "a1b2c3-vm-2", "online"),
                r(61, "ffffff-vm-3", "offline"),
                r(62, "a1b2c3x-vm-4", "offline"),
                r(63, "a1b2c3-vm-5", "offline"),
            ]),
        );
        m.route("PATCH", &format!("{RUNNERS}/63"), 200, fx("runner_disabled.json"));
        m.route("DELETE", &format!("{RUNNERS}/63"), 204, "");
        // 63 has a job in progress: it is left alone.
        m.route("GET", &format!("{API}/jobs?status=in_progress&limit=50&page=1"), 200, jobs_running(63));
        assert_eq!(g.sweep(&repo()).await.unwrap(), 1);
        let reqs = m.requests();
        assert!(reqs.contains(&format!("DELETE {RUNNERS}/52")), "{reqs:?}");
        assert!(!reqs.contains(&format!("DELETE {RUNNERS}/63")), "{reqs:?}");
        for other in [60, 61, 62] {
            assert!(!reqs.iter().any(|q| q.contains(&format!("/{other}"))), "{other}: {reqs:?}");
        }
        // Nothing listed, or an unreadable listing.
        m.route("GET", &page, 200, fx("runners_empty.json"));
        assert_eq!(g.sweep(&repo()).await.unwrap(), 0);
        m.route("GET", &page, 500, "{}");
        assert!(g.sweep(&repo()).await.is_err());
    }

    #[test]
    fn credentials_and_construction() {
        let cfg = |j: Value| serde_json::from_value::<ForgeCfg>(j).unwrap();
        let ok = Gitea::new(
            &cfg(json!({"id": "home-lab", "kind": "gitea", "url": "https://gitea.example.org/", "repos": ["acme/demo", "bad", "a/b/c"]})),
            &std::env::temp_dir(),
        )
        .unwrap();
        assert_eq!(ok.web_url(), WEB);
        assert_eq!(ok.api, format!("{WEB}/api/v1"));
        assert_eq!(env_name(&ok.id), "KILN_FORGE_HOME_LAB_TOKEN");
        // Only valid two-segment repos are served.
        let c = cfg(json!({"id": "home-lab", "kind": "gitea", "url": WEB, "repos": ["acme/demo", "bad", "a/b/c"]}));
        assert_eq!(ok.repos(&c).iter().map(RepoRef::key).collect::<Vec<_>>(), ["home-lab:acme/demo"]);
        assert!(ok.health().unwrap().contains("no Gitea token"));
        // A token file: read, trimmed, header-safe only; a bad one is no credential.
        let dir = std::env::temp_dir().join(format!("kiln-gitea-token-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("forges")).unwrap();
        let file = dir.join("forges/home-lab.token");
        std::fs::write(&file, "abc123\n").unwrap();
        ok.load_token(&dir);
        assert!(ok.has_credential() && ok.health().is_none());
        assert_eq!(ok.token().as_deref(), Some("abc123"));
        std::fs::write(&file, "abc\r\nX-Evil: 1").unwrap();
        ok.load_token(&dir);
        assert!(!ok.has_credential());
        std::fs::remove_file(&file).unwrap();
        ok.load_token(&dir);
        assert!(!ok.has_credential());
        let _ = std::fs::remove_dir_all(&dir);
        // Refused configs: no url, plain http on a public forge, loopback.
        for j in [
            json!({"id": "g", "kind": "gitea"}),
            json!({"id": "g", "kind": "gitea", "url": "http://gitea.example.org"}),
            json!({"id": "g", "kind": "gitea", "url": "http://127.0.0.1:3000", "network": "internal"}),
        ] {
            assert!(Gitea::new(&cfg(j.clone()), &std::env::temp_dir()).is_err(), "{j}");
        }
    }

    #[tokio::test]
    async fn the_safe_client_refuses_loopback() {
        // `Gitea::new` always builds the guarded client: even an `internal` forge never dials loopback.
        let cfg: ForgeCfg =
            serde_json::from_value(json!({"id": "g", "kind": "gitea", "url": "http://10.1.2.3:3000", "network": "internal"})).unwrap();
        let mut g = Gitea::new(&cfg, &std::env::temp_dir()).unwrap();
        g.api = "http://127.0.0.1:9/api/v1".into();
        *g.token.write().unwrap() = Some("tok".into());
        let e = g.get("version").await.unwrap_err();
        assert!(format!("{e:#}").contains("internal address"), "{e:#}");
        // The registration RPC goes through the same guard, and fails before any token is sent.
        g.api = "http://127.0.0.1:9/api/v1".into();
        let e = g.finish(g.client.post("http://127.0.0.1:9/api/actions/x")).await.unwrap_err();
        assert!(format!("{e:#}").contains("internal address"), "{e:#}");
    }
}
