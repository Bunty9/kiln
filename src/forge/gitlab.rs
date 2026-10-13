//! The GitLab forge, demand side (GL-2): which of the project's pending jobs are ours, which
//! running jobs belong to our runners, and whether a job's code came from a fork.
//!
//! Registration, retire, sweep and pause are here (GL-3), and verdict facts, cache trust and the
//! dashboard API (GL-4). The guest side arrives with GL-6: until `LAUNCH_READY`, `register`
//! refuses and demand reports no launchable jobs, so no VM boots for GitLab.
//!
//! Everything the API says is data, never instructions: fork detection reads the job's `ref`,
//! `tag` and pipeline `source` plus one MR or branch lookup, never a `CI_*` value (a job's own
//! config can overwrite those). Any doubt is a fork. All HTTP goes through `net.rs` (no
//! redirects, address guard, size cap), and a `Link` URL is only compared, never fetched.

use super::{
    Caps, Credential, Demand, Dereg, EventKind, ForgeCfg, ForgeId, JobInfo, JobRef, JobSummary, Kind, Links, LogPage, Network, Outcome,
    Reason, RepoRef, RunDetail, RunPage, RunQuery, RunStatus, RunSummary, RunnerReg, VerdictFacts, Workflow, env_name, net,
    read_token_file, token_path,
};
use crate::github::MintError;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

/// GitLab has no workflow list (a project has one `.gitlab-ci.yml`) and no live step list.
pub const CAPS: Caps = Caps { rerun: true, rerun_failed: true, cancel: true, dispatch: true, workflows: false, live_steps: false };
pub const LATER: &str = "GitLab runners arrive in a later version";
/// No VM launches for GitLab until GL-6 (the guest's `run_gitlab` and `kiln-exec`) lands: a VM
/// booted now would have nothing that reads its secret. Demand reports the queue, fork jobs and
/// claims but no launchable jobs, and `register` refuses (warm VMs ask for a runner without demand).
const LAUNCH_READY: bool = false;
/// After pausing, one in-flight `jobs/request` can still win for up to about 1 s (SP-7).
const PAUSE_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);
/// How long `cache_trust` waits for a job to finish: the VM powers off a moment before GitLab records the result.
const TRUST_LOOKS: usize = 7;
const TRUST_POLL: std::time::Duration = std::time::Duration::from_secs(5);
/// Pipelines per dashboard page.
const RUNS_PAGE: usize = 30;
/// A runner with no VM record is orphaned once older than the longest `job_timeout_mins` (1440,
/// the config ceiling) plus 10 minutes: whatever its status, which lies for hours (SP-7).
const ORPHAN_SECS: u64 = (1440 + 10) * 60;
/// A runner that never polled belongs to a VM that died before its runner started.
const NEVER_CONTACTED_SECS: u64 = 600;
/// Labels the GitHub-shaped runner label list carries that GitLab has no use for.
const IMPLICIT_LABELS: [&str; 4] = ["self-hosted", "linux", "x64", "ARM64"];
/// A 403 on `POST /user/runners` cannot be told apart by the response (SP-6).
const REGISTER_403: &str = "the token's user must be at least Maintainer on the project, the instance setting \
valid_runner_registrars (Admin > Settings > CI/CD > Runner registration) must include `project`, and runner \
registration must be enabled for the project and its group (a toggle with no API field); one of these is not met";
const PER_PAGE: usize = 100;
/// 100 pages of 100 jobs; a longer queue is an error, not a silent undercount.
const MAX_PAGES: usize = 100;
const BODY_CAP: usize = 16 << 20;
/// Pipeline sources kiln knows. Anything else (external PR events, security policies, ...) is
/// treated as a fork: the code origin is unclear.
const SOURCES: [&str; 8] = ["push", "web", "api", "trigger", "schedule", "pipeline", "parent_pipeline", "merge_request_event"];

/// (is a fork, MR source branch).
type Origin = (bool, Option<String>);

pub struct GitLab {
    id: ForgeId,
    /// Configured origin, no trailing slash.
    url: String,
    mode: net::Mode,
    client: reqwest::Client,
    cred: Credential,
    token_file: PathBuf,
    /// Empty = none. Never logged or put in an error.
    token: RwLock<String>,
    /// Runner descriptions are `<install>-<vm id>`; ours are the ones with this prefix.
    install: String,
    per_page: usize,
    /// Wait between pausing a runner and listing its jobs.
    settle: std::time::Duration,
    /// Unix time before which GitLab told us to back off (429), 0 = no.
    paused: Mutex<u64>,
    /// How long `cache_trust` waits between looks for a job that has not finished.
    poll: std::time::Duration,
    /// repo path -> (default branch, unix time read); an hour is plenty.
    defaults: Mutex<HashMap<String, (String, u64)>>,
    /// repo path -> numeric project id.
    projects: Mutex<HashMap<String, u64>>,
    /// Runners this process registered and has not retired: kiln's own VM records, which a sweep
    /// never touches.
    mine: Mutex<HashSet<u64>>,
    /// (project, pipeline, ref) -> (fork, MR source branch). Only answers, never lookup errors.
    origins: Mutex<HashMap<(u64, u64, String), Origin>>,
    /// Tests dial a mock on loopback, which the address guard refuses.
    #[cfg(test)]
    unguarded: bool,
}

struct Resp {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).context("GitLab sent a body that is not JSON")
    }
}

/// What pausing a runner found.
enum Hold {
    Gone,
    /// The ids of the running jobs it holds.
    Held(Vec<String>),
}

/// GitLab's own `message` or `error`, cut and stripped of control characters (it never echoes the credential).
fn message(v: &Value) -> String {
    // A refused `POST /pipeline` answers `{"message": {"base": [...]}}`: show it as text.
    let m = &v["message"];
    let text = m.as_str().map(String::from).or_else(|| (!m.is_null()).then(|| m.to_string()));
    text.or(v["error"].as_str().map(String::from)).unwrap_or_default().chars().filter(|c| !c.is_control()).take(200).collect()
}

impl GitLab {
    pub fn new(cfg: &ForgeCfg, data: &Path) -> Result<Self> {
        let network = cfg.network.unwrap_or(Network::Public);
        let url = net::check_forge_url(cfg.url.as_deref().context("a GitLab forge needs a url")?, network)?;
        let id = cfg.id.clone();
        let g = Self {
            url: url.as_str().trim_end_matches('/').to_string(),
            mode: network.into(),
            client: net::client(network.into()),
            cred: cfg.credential.unwrap_or(Credential::File),
            token_file: token_path(data, &id),
            token: RwLock::new(String::new()),
            install: install_id(data)?,
            per_page: PER_PAGE,
            settle: PAUSE_SETTLE,
            paused: Mutex::new(0),
            poll: TRUST_POLL,
            defaults: Mutex::default(),
            projects: Mutex::default(),
            mine: Mutex::default(),
            origins: Mutex::default(),
            #[cfg(test)]
            unguarded: false,
            id,
        };
        g.load_token(data);
        Ok(g)
    }

    /// Re-reads the credential (the dashboard writes the file; the environment is fixed).
    pub fn load_token(&self, data: &Path) {
        let t = match self.cred {
            Credential::File => read_token_file(data, &self.id).unwrap_or_default(),
            Credential::Env => std::env::var(env_name(&self.id)).unwrap_or_default(),
        };
        *self.token.write().unwrap() = t.trim().to_string();
    }

    pub fn id(&self) -> ForgeId {
        self.id.clone()
    }

    pub fn has_credential(&self) -> bool {
        !self.token.read().unwrap().is_empty()
    }

    pub fn web_url(&self) -> &str {
        &self.url
    }

    pub fn auth(&self) -> Value {
        let source = match (self.has_credential(), self.cred) {
            (false, _) => "none",
            (true, Credential::File) => "file",
            (true, Credential::Env) => "env",
        };
        json!({ "source": source, "expires": null })
    }

    /// What stops this forge polling at all: no credential, or GitLab asked us to slow down.
    pub fn health(&self) -> Option<String> {
        if !self.has_credential() {
            return Some(match self.cred {
                Credential::File => format!("no token for GitLab forge {}: put one in {}", self.id.as_str(), self.token_file.display()),
                Credential::Env => format!("no token for GitLab forge {}: export {}", self.id.as_str(), env_name(&self.id)),
            });
        }
        self.paused_until().map(|t| format!("GitLab rate limit: paused until {t}"))
    }

    fn paused_until(&self) -> Option<u64> {
        Some(*self.paused.lock().unwrap()).filter(|&t| t > crate::now())
    }

    pub fn repos(&self, cfg: &ForgeCfg) -> Vec<RepoRef> {
        cfg.repos.iter().filter_map(|r| RepoRef::parse(&format!("{}:{r}", self.id.as_str())).ok()).collect()
    }

    /// Registers a single-use project runner for the VM `name` and returns its guest secret.
    /// A refusal or an unreachable GitLab is a `MintError`.
    pub async fn register(&self, repo: &RepoRef, name: &str, labels: &[String]) -> Result<RunnerReg> {
        if !LAUNCH_READY {
            bail!(LATER);
        }
        self.mint(repo, name, labels).await
    }

    async fn mint(&self, repo: &RepoRef, name: &str, labels: &[String]) -> Result<RunnerReg> {
        repo.check_kind(Kind::GitLab)?;
        let err = |status, message: String| anyhow::Error::from(MintError { forge: "GitLab", status, endpoint: "user/runners", message });
        let unreachable = |e: anyhow::Error| match e.chain().any(|c| c.is::<reqwest::Error>()) {
            true => err(None, format!("{e:#}")),
            false => e,
        };
        let pid = self.project_id(&repo.path, false).await.map_err(unreachable)?;
        // The label list is GitHub-shaped; GitLab matches `kiln-Ncpu` and `kiln` only (`runner_tags`).
        let tags: Vec<&String> = labels.iter().filter(|l| !IMPLICIT_LABELS.contains(&l.as_str())).collect();
        // ponytail: no `maximum_timeout` (the runner's job cap): kiln stops the VM at job_timeout_mins itself.
        let body = json!({
            "runner_type": "project_type", "project_id": pid, "description": format!("{}-{name}", self.install),
            "tag_list": tags, "run_untagged": false, "locked": true, "access_level": "not_protected",
        });
        let r = self.send(Method::POST, "user/runners", Some(body)).await.map_err(|e| err(None, format!("{e:#}")))?;
        if r.status != 201 {
            let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            let why = match (r.status, v["error"].as_str()) {
                (401, _) => "the token was rejected (expired, revoked or wrong)".to_string(),
                (403, Some("insufficient_scope")) => "the token lacks the create_runner scope".to_string(),
                (403, _) => format!("403: {REGISTER_403}"),
                _ => message(&v),
            };
            return Err(err(Some(r.status), why));
        }
        let v = r.json()?;
        let (Some(id), Some(token)) =
            (v["id"].as_u64(), v["token"].as_str().filter(|t| t.starts_with("glrt-") && t.bytes().all(|b| b.is_ascii_graphic())))
        else {
            bail!("GitLab runner registration answered without an id and a glrt- token");
        };
        self.mine.lock().unwrap().insert(id);
        // The URL passed `check_forge_url`; the token is encoded so no byte of it is shell-significant.
        let b64 = base64::engine::general_purpose::STANDARD.encode(token);
        Ok(RunnerReg { runner_id: id, guest_secret: format!("kiln.forge=gitlab\nkiln.url={}\nkiln.cred={b64}", self.url) })
    }

    /// Stops the runner taking another job, waits out the one request that may be in flight, and
    /// lists the jobs it holds. `Gone`: the runner no longer exists.
    async fn hold(&self, id: u64) -> Result<Hold> {
        let r = self.send(Method::PUT, &format!("runners/{id}"), Some(json!({ "paused": true }))).await?;
        match r.status {
            200 => {}
            404 => return Ok(Hold::Gone),
            _ => return Err(self.fail("pause runner", &r)),
        }
        if r.json()?["paused"] != true {
            bail!("GitLab did not pause runner {id}");
        }
        tokio::time::sleep(self.settle).await;
        let j = self.get(&format!("runners/{id}/jobs?status=running")).await?;
        match j.status {
            200 => {}
            404 => return Ok(Hold::Gone),
            _ => return Err(self.fail("runner jobs", &j)),
        }
        let Value::Array(a) = j.json()? else { bail!("GitLab runner job list is not an array") };
        // A job without an id is a job we cannot name: fail closed.
        a.iter()
            .map(|j| j["id"].as_u64().map(|n| n.to_string()).context("GitLab runner job without an id"))
            .collect::<Result<_>>()
            .map(Hold::Held)
    }

    /// The gate's pause: the ids of the jobs the paused runner holds (needs `manage_runner` only).
    pub async fn pause(&self, runner_id: u64) -> Result<Vec<String>> {
        match self.hold(runner_id).await? {
            Hold::Held(ids) => Ok(ids),
            Hold::Gone => bail!("GitLab runner {runner_id} is gone"),
        }
    }

    async fn unpause(&self, id: u64) {
        match self.send(Method::PUT, &format!("runners/{id}"), Some(json!({ "paused": false }))).await {
            Ok(r) if r.status == 200 || r.status == 404 => {}
            Ok(r) => tracing::warn!("GitLab runner {id} stays paused: {:#}", self.fail("unpause", &r)),
            Err(e) => tracing::warn!("GitLab runner {id} stays paused: {e:#}"),
        }
    }

    /// Pause, check, delete (3.3): `Busy` (and unpaused again) when the runner holds a job. A stale
    /// policy never waits for the job: the VM is killed either way, and a job that raced in fails
    /// and is retried (security beats availability). The caller's VM record already names the
    /// runner id and job id, so deleting the runner loses nothing.
    pub async fn deregister(&self, repo: &RepoRef, runner_id: u64, reason: Reason) -> Dereg {
        if let Err(e) = repo.check_kind(Kind::GitLab) {
            return Dereg::Err(e);
        }
        let stale = reason == Reason::StalePolicy;
        match self.hold(runner_id).await {
            Ok(Hold::Gone) => {}
            Ok(Hold::Held(jobs)) if !jobs.is_empty() && !stale => {
                self.unpause(runner_id).await;
                return Dereg::Busy;
            }
            Err(e) if !stale => {
                self.unpause(runner_id).await;
                return Dereg::Err(e);
            }
            _ => match self.send(Method::DELETE, &format!("runners/{runner_id}"), None).await {
                Ok(r) if r.status == 204 || r.status == 404 => {}
                Ok(r) => return Dereg::Err(self.fail("delete runner", &r)),
                Err(e) => return Dereg::Err(e),
            },
        }
        self.mine.lock().unwrap().remove(&runner_id);
        Dereg::Gone
    }

    /// Deletes this install's runners that no VM can own, never by status (a killed runner stays
    /// `online` for hours): the `<install>-` prefix, not registered by this process, and older than
    /// `ORPHAN_SECS`; or never contacted and older than 10 minutes.
    pub async fn sweep(&self, repo: &RepoRef) -> Result<usize> {
        repo.check_kind(Kind::GitLab)?;
        let pid = self.project_id(&repo.path, false).await?;
        let prefix = format!("{}-", self.install);
        let now = crate::now();
        let mut n = 0;
        for page in 1..=MAX_PAGES {
            let r = self.get(&format!("projects/{pid}/runners?type=project_type&per_page={}&page={page}", self.per_page)).await?;
            if r.status != 200 {
                return Err(self.fail("runner list", &r));
            }
            let Value::Array(runners) = r.json()? else { bail!("GitLab runner list is not an array") };
            for x in &runners {
                let (Some(id), Some(desc), Some(at)) =
                    (x["id"].as_u64(), x["description"].as_str(), x["created_at"].as_str().and_then(crate::github::parse_rfc3339))
                else {
                    continue;
                };
                let age = now.saturating_sub(at);
                let stale = age > ORPHAN_SECS || (x["status"] == "never_contacted" && age > NEVER_CONTACTED_SECS);
                if x["runner_type"] != "project_type" || !desc.starts_with(&prefix) || !stale || self.mine.lock().unwrap().contains(&id) {
                    continue;
                }
                let d = self.send(Method::DELETE, &format!("runners/{id}"), None).await?;
                match d.status {
                    204 | 404 => n += 1,
                    _ => return Err(self.fail("delete runner", &d)),
                }
            }
            if runners.len() < self.per_page {
                break;
            }
        }
        Ok(n)
    }

    /// The doctor's checks for this forge: version, token scopes and expiry, and the role on each
    /// served project. No runner is created.
    pub async fn doctor(&self, repos: &[RepoRef]) -> Vec<(String, bool, String)> {
        let name = format!("gitlab {}", self.id.as_str());
        if let Some(why) = self.health() {
            return vec![(name, false, why)];
        }
        let mut out = vec![];
        out.push(match self.get("version").await {
            Ok(r) if r.status == 200 => {
                let v = r.json().ok().and_then(|v| v["version"].as_str().map(String::from)).unwrap_or_default();
                let major = v.split('.').next().and_then(|m| m.parse::<u32>().ok());
                match major {
                    Some(m) if m >= 16 => (name.clone(), true, format!("version {v}")),
                    _ => (name.clone(), false, format!("version {v:?}: kiln needs GitLab 16.0 or newer")),
                }
            }
            Ok(r) => (name.clone(), false, self.fail("version", &r).to_string()),
            Err(e) => (name.clone(), false, format!("{e:#}")),
        });
        let tok = format!("{name} token");
        out.push(match self.get("personal_access_tokens/self").await {
            Ok(r) if r.status == 200 => {
                let v = r.json().unwrap_or(Value::Null);
                let scopes: Vec<&str> = v["scopes"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                let has = |s: &str| scopes.contains(&s) || scopes.contains(&"api");
                let missing: Vec<&str> = ["create_runner", "manage_runner", "read_api"].into_iter().filter(|s| !has(s)).collect();
                if v["active"] != true || v["revoked"] == true {
                    (tok, false, "the token is revoked or expired".into())
                } else if !missing.is_empty() {
                    (tok, false, format!("missing scope(s): {}", missing.join(", ")))
                } else {
                    (tok, true, format!("scopes ok, expires {}", v["expires_at"].as_str().unwrap_or("never")))
                }
            }
            Ok(r) => (tok, false, self.fail("token check", &r).to_string()),
            Err(e) => (tok, false, format!("{e:#}")),
        });
        for repo in repos {
            let n = format!("{name} {}", repo.path);
            out.push(match self.project_role(&repo.path).await {
                Ok(l) if l >= 40 => (n, true, "Maintainer or above. If registering a runner still gets 403, check the instance setting valid_runner_registrars and the project's runner registration toggle".into()),
                Ok(l) => (n, false, format!("access level {l} is below Maintainer, which creating a project runner needs; also check the instance setting valid_runner_registrars (Admin > Settings > CI/CD > Runner registration) and the project's runner registration toggle")),
                Err(e) => (n, false, format!("{e:#}")),
            });
        }
        out
    }

    /// The token user's access level on the project: the higher of its project and group membership.
    async fn project_role(&self, path: &str) -> Result<u64> {
        let r = self.get(&format!("projects/{}", enc(path))).await?;
        match r.status {
            200 => {}
            404 => bail!("GitLab project {path} not found, or the token cannot see it"),
            _ => return Err(self.fail("project lookup", &r)),
        }
        let p = &r.json()?["permissions"];
        Ok(p["project_access"]["access_level"].as_u64().unwrap_or(0).max(p["group_access"]["access_level"].as_u64().unwrap_or(0)))
    }

    /// GET `api/v4/<path>`.
    async fn get(&self, path: &str) -> Result<Resp> {
        self.send(Method::GET, path, None).await
    }

    /// One API call, answered but not yet read. The token only ever goes to the configured origin.
    async fn request(&self, method: Method, path: &str, body: Option<Value>) -> Result<(u16, HeaderMap, reqwest::Response)> {
        if let Some(t) = self.paused_until() {
            bail!("GitLab rate limit: paused until {t}");
        }
        let mut tok = HeaderValue::from_str(&self.token.read().unwrap()).map_err(|_| anyhow!("the GitLab token has invalid characters"))?;
        if tok.is_empty() {
            bail!("no GitLab token");
        }
        tok.set_sensitive(true);
        let mut rb = self.client.request(method, format!("{}/api/v4/{path}", self.url)).header("PRIVATE-TOKEN", tok);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        #[cfg(test)]
        let r = if self.unguarded { self.client.execute(rb.build()?).await? } else { net::send(&self.client, self.mode, rb).await? };
        #[cfg(not(test))]
        let r = net::send(&self.client, self.mode, rb).await?;
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        if status == 429 {
            let secs = headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
            *self.paused.lock().unwrap() = crate::now() + secs.unwrap_or(60).clamp(1, 3600);
        }
        Ok((status, headers, r))
    }

    async fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<Resp> {
        let (status, headers, r) = self.request(method, path, body).await?;
        Ok(Resp { status, headers, body: net::read_capped(r, BODY_CAP).await? })
    }

    /// An error for a response that was not the one we wanted. GitLab's own message is shown
    /// (it never echoes the credential), cut and stripped of control characters.
    fn fail(&self, what: &str, r: &Resp) -> anyhow::Error {
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let why = match (r.status, v["error"].as_str()) {
            (401, _) => "the token was rejected (expired, revoked or wrong)".to_string(),
            (403, Some("insufficient_scope")) => "the token lacks a scope (it needs create_runner, manage_runner and read_api)".to_string(),
            (429, _) => "rate limited; backing off".to_string(),
            _ => message(&v),
        };
        anyhow!("GitLab {what}: HTTP {}{}{why}", r.status, if why.is_empty() { "" } else { ": " })
    }

    /// The numeric id of `path`, cached per forge; `fresh` skips the cache (a 404 on the id).
    async fn project_id(&self, path: &str, fresh: bool) -> Result<u64> {
        if !fresh && let Some(&id) = self.projects.lock().unwrap().get(path) {
            return Ok(id);
        }
        let r = self.get(&format!("projects/{}", enc(path))).await?;
        if r.status == 404 {
            bail!("GitLab project {path} not found, or the token cannot see it");
        }
        if r.status != 200 {
            return Err(self.fail("project lookup", &r));
        }
        let v = r.json()?;
        // The API answers 301 for a moved project (not followed); a 200 must be the project asked for.
        match (v["id"].as_u64(), v["path_with_namespace"].as_str()) {
            (Some(id), Some(p)) if p.eq_ignore_ascii_case(path) => {
                self.projects.lock().unwrap().insert(path.to_string(), id);
                Ok(id)
            }
            _ => bail!("GitLab answered a different project for {path}"),
        }
    }

    /// All pending and running jobs of the project, newest first, across keyset pages. `None`:
    /// the project id is gone (404). The cursor is rebuilt from `X-Next-Cursor`; the `Link` URL
    /// is only checked to be on our origin and is never fetched. A page error (a bad cursor is
    /// a 500) fails the whole read: the next tick starts again from page 1.
    async fn pending_jobs(&self, pid: u64) -> Result<Option<Vec<Value>>> {
        let first = format!("projects/{pid}/jobs?scope%5B%5D=pending&scope%5B%5D=running&per_page={}&pagination=keyset", self.per_page);
        let (mut path, mut jobs, mut seen) = (first.clone(), vec![], HashSet::new());
        for _ in 0..MAX_PAGES {
            let r = self.get(&path).await?;
            if r.status == 404 && jobs.is_empty() {
                return Ok(None);
            }
            if r.status != 200 {
                return Err(self.fail("job list", &r));
            }
            match r.json()? {
                Value::Array(a) => jobs.extend(a),
                _ => bail!("GitLab job list is not an array"),
            }
            let Some(cursor) = self.next_cursor(&r.headers)? else { return Ok(Some(jobs)) };
            if !seen.insert(cursor.clone()) {
                bail!("GitLab job list repeats a page cursor");
            }
            path = format!("{first}&{}", query(&[("cursor", &cursor)]));
        }
        bail!("more than {} pending jobs", MAX_PAGES * self.per_page)
    }

    /// The next page's cursor, or `None` on the last page (it has no `Link`).
    fn next_cursor(&self, h: &HeaderMap) -> Result<Option<String>> {
        let Some(link) = h.get_all("link").iter().filter_map(|v| v.to_str().ok()).find_map(next_link) else { return Ok(None) };
        if !net::same_origin(&self.url, link) {
            bail!("GitLab's pagination link is on another origin than the forge url: set the url to GitLab's external_url");
        }
        let from_link = || reqwest::Url::parse(link).ok()?.query_pairs().find(|(k, _)| k == "cursor").map(|(_, v)| v.into_owned());
        h.get("x-next-cursor")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .or_else(from_link)
            .filter(|c| !c.is_empty() && c.len() < 512)
            .map(Some)
            .context("GitLab's pagination link has no cursor")
    }

    pub async fn demand(&self, repo: &RepoRef, label: &str, default_cpus: u32) -> Result<Demand> {
        let mut d = self.demand_for(repo, label, default_cpus, crate::host_threads()).await?;
        if !LAUNCH_READY {
            d.by_size.clear();
        }
        Ok(d)
    }

    async fn demand_for(&self, repo: &RepoRef, label: &str, default_cpus: u32, host: u32) -> Result<Demand> {
        let (pid, jobs) = {
            let pid = self.project_id(&repo.path, false).await?;
            match self.pending_jobs(pid).await? {
                Some(j) => (pid, j),
                None => {
                    let pid = self.project_id(&repo.path, true).await?;
                    (pid, self.pending_jobs(pid).await?.with_context(|| format!("GitLab project {} has no jobs endpoint", repo.path))?)
                }
            }
        };
        let (mut by_size, mut claimed, mut refused_forks) = (HashMap::new(), HashMap::new(), 0);
        let prefix = format!("{}-", self.install);
        // arm64 hosts tag their runners `<label>-arm64[-Ncpu]`, so x64 jobs never match them.
        let label = &super::arch_label(label, crate::platform::host_arm64());
        for j in &jobs {
            match j["status"].as_str() {
                Some("pending") => {
                    let tags: Vec<&str> = j["tag_list"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                    let Some(n) = job_size(&tags, label, default_cpus).filter(|&n| n <= host) else { continue };
                    if self.origin(pid, j).await.0 {
                        refused_forks += 1;
                    } else {
                        *by_size.entry(n).or_default() += 1;
                    }
                }
                // A runner kiln deleted leaves `runner: null`; GL-3 counts those from its own record.
                Some("running") => {
                    if let Some(vm) = j["runner"]["description"].as_str().and_then(|d| d.strip_prefix(&prefix)).filter(|v| !v.is_empty()) {
                        claimed.insert(vm.to_string(), self.job_info(repo, pid, j).await);
                    }
                }
                _ => {}
            }
        }
        Ok(Demand { by_size, claimed, refused_forks, ..Default::default() })
    }

    /// Whether the job's code came from a fork (true on any doubt), and the MR's source branch
    /// for display. Cached per (project, pipeline, ref); a failed lookup counts as a fork now
    /// and is asked again next tick.
    async fn origin(&self, pid: u64, j: &Value) -> Origin {
        let key = (pid, j["pipeline"]["id"].as_u64().unwrap_or(0), j["ref"].as_str().unwrap_or("").to_string());
        if let Some(o) = self.origins.lock().unwrap().get(&key) {
            return o.clone();
        }
        match self.origin_lookup(pid, j).await {
            Ok(o) => {
                let mut c = self.origins.lock().unwrap();
                // ponytail: wholesale reset keeps this bounded; an LRU if refetching ever shows in the rate limit.
                if c.len() >= 4096 {
                    c.clear();
                }
                c.insert(key, o.clone());
                o
            }
            Err(e) => {
                tracing::warn!("GitLab {}: treating job {} as a fork: {e:#}", self.id.as_str(), j["id"]);
                (true, None)
            }
        }
    }

    async fn origin_lookup(&self, pid: u64, j: &Value) -> Result<Origin> {
        if j["pipeline"]["id"].as_u64().is_none() || !SOURCES.contains(&j["pipeline"]["source"].as_str().context("no pipeline source")?) {
            return Ok((true, None));
        }
        let r = j["ref"].as_str().filter(|r| !r.is_empty()).context("no ref")?;
        if j["tag"] == true {
            return Ok((false, None));
        }
        if r.starts_with("refs/merge-requests/") {
            // refs/merge-requests/<iid>/{head,merge,train}: a fork MR run in this project, merged results, a train.
            let Some(iid) = mr_iid(r) else { return Ok((true, None)) };
            let m = self.get(&format!("projects/{pid}/merge_requests/{iid}")).await?;
            if m.status != 200 {
                return Err(self.fail("merge request lookup", &m));
            }
            let m = m.json()?;
            let fork =
                !matches!((m["source_project_id"].as_u64(), m["target_project_id"].as_u64()), (Some(s), Some(t)) if s == t && t == pid);
            return Ok((fork, m["source_branch"].as_str().map(String::from)));
        }
        if r.starts_with("refs/") {
            return Ok((true, None)); // refs/pipelines/<id> and other refs that are no branch
        }
        // A plain ref of a job in this project's own list is a branch of it, if it still exists.
        let b = self.get(&format!("projects/{pid}/repository/branches/{}", enc(r))).await?;
        match b.status {
            200 => Ok((false, Some(r.to_string()))),
            404 => Ok((true, None)),
            _ => Err(self.fail("branch lookup", &b)),
        }
    }

    async fn job_info(&self, repo: &RepoRef, pid: u64, j: &Value) -> JobInfo {
        let (fork, mr_branch) = self.origin(pid, j).await;
        let s = |v: &Value| v.as_str().unwrap_or("").chars().take(200).collect::<String>();
        let (id, r, sha, source) = (j["id"].as_u64().unwrap_or_default(), s(&j["ref"]), s(&j["commit"]["id"]), s(&j["pipeline"]["source"]));
        let pr = mr_iid(&r);
        let kind = kind_of(j["tag"] == true, &source, &r);
        let branch = mr_branch.filter(|_| pr.is_some()).unwrap_or_else(|| r.clone());
        let base = format!("{}/{}", self.url, repo.path);
        let links = links(&base, j["pipeline"]["id"].as_u64(), Some(id), &sha, &r);
        JobInfo {
            id: id.to_string(),
            url: format!("{base}/-/jobs/{id}"),
            queued_at: j["created_at"].as_str().and_then(crate::github::parse_rfc3339).unwrap_or_else(crate::now),
            fork,
            run: crate::vm::Run {
                branch: branch.chars().take(200).collect(),
                sha,
                pr,
                event: source,
                title: s(&j["commit"]["title"]),
                workflow: "pipeline".into(),
                number: j["pipeline"]["iid"].as_u64().unwrap_or_default(),
                file: ".gitlab-ci.yml".into(),
                kind,
                links,
            },
        }
    }
}

impl GitLab {
    /// The job the console named, read through the repo's own project (another project's job is a
    /// 404), and that project's id. The id is digits only and must come back as the same id.
    async fn job(&self, repo: &RepoRef, job_id: &str) -> Result<(u64, Value)> {
        repo.check_kind(Kind::GitLab)?;
        let id: u64 = job_id.parse().ok().filter(|_| job_id.bytes().all(|b| b.is_ascii_digit())).context("bad job id")?;
        let pid = self.project_id(&repo.path, false).await?;
        let r = self.get(&format!("projects/{pid}/jobs/{id}")).await?;
        if r.status != 200 {
            return Err(self.fail("job lookup", &r));
        }
        let j = r.json()?;
        if j["id"].as_u64() != Some(id) {
            bail!("GitLab answered for another job than {id}");
        }
        Ok((pid, j))
    }

    /// What the API says about the job the console named (4.2): `pipeline.source`, the job's `ref`
    /// and `tag`, and the MR or branch lookup. Never a `CI_*` value, which the job's own config can
    /// overwrite, and nothing from the guest. A read error is the caller's refusal.
    pub async fn verdict_facts(&self, repo: &RepoRef, job_id: &str) -> Result<VerdictFacts> {
        let (pid, j) = self.job(repo, job_id).await?;
        Ok(VerdictFacts {
            ours: j["pipeline"]["project_id"].as_u64() == Some(pid),
            // Not `origin`: that counts a failed lookup as a fork, this one must say it failed.
            fork: self.origin_lookup(pid, &j).await?.0,
            unknown_source: !SOURCES.contains(&j["pipeline"]["source"].as_str().unwrap_or("")),
            tag: j["tag"] == true,
            ..Default::default()
        })
    }

    /// (event, branch, default branch, conclusion) of the job that ran, for `cache_verdict`. The
    /// event is `push` only for a pipeline sourced `push` on a branch of this project; a fork is
    /// `fork`, a tag `tag`, any other source is itself (so `pipeline`, `web`, ... never write). A
    /// writer branch must also be protected. The conclusion is `success` or GitLab's own status.
    pub async fn cache_trust(&self, job: &JobRef, writers: &[String]) -> Result<(String, String, String, String)> {
        let (pid, mut j) = self.job(&job.repo, &job.id).await?;
        for _ in 1..TRUST_LOOKS {
            if stat(j["status"].as_str().unwrap_or("")).0 == RunStatus::Completed {
                break;
            }
            tokio::time::sleep(self.poll).await;
            j = self.job(&job.repo, &job.id).await?.1;
        }
        if j["pipeline"]["project_id"].as_u64() != Some(pid) {
            bail!("job {} is not for {}", job.id, job.repo.key());
        }
        let default = self.default_branch(&job.repo.path).await?;
        let (fork, mr_branch) = self.origin_lookup(pid, &j).await?;
        let (r, source) = (j["ref"].as_str().unwrap_or(""), j["pipeline"]["source"].as_str().unwrap_or(""));
        let (event, mut branch) = match kind_of(j["tag"] == true, source, r) {
            _ if fork => ("fork", r.to_string()),
            EventKind::Tag => ("tag", r.to_string()),
            EventKind::PullRequest => ("merge_request_event", mr_branch.unwrap_or_else(|| r.to_string())),
            _ => (source, r.to_string()),
        };
        if event == "push" && (branch == default || writers.contains(&branch)) {
            if !crate::valid_branch(&branch) {
                branch = format!("{branch} (not a plain branch name)");
            } else if branch != default && !self.branch(pid, &branch).await?["protected"].as_bool().unwrap_or(false) {
                branch = format!("{branch} (not protected)");
            }
        }
        let status = j["status"].as_str().unwrap_or("none");
        let conclusion = if stat(status).1 == Some(Outcome::Succeeded) { "success" } else { status };
        Ok((event.to_string(), branch, default, conclusion.to_string()))
    }

    async fn branch(&self, pid: u64, name: &str) -> Result<Value> {
        let r = self.get(&format!("projects/{pid}/repository/branches/{}", enc(name))).await?;
        match r.status {
            200 => r.json(),
            _ => Err(self.fail("branch lookup", &r)),
        }
    }

    /// The project's default branch, read at most once an hour.
    async fn default_branch(&self, path: &str) -> Result<String> {
        let key = path.to_ascii_lowercase();
        if let Some((b, at)) = self.defaults.lock().unwrap().get(&key)
            && crate::now() < at + 3600
        {
            return Ok(b.clone());
        }
        let r = self.get(&format!("projects/{}", enc(path))).await?;
        if r.status != 200 {
            return Err(self.fail("project lookup", &r));
        }
        let b = r.json()?["default_branch"].as_str().context("no default_branch")?.to_string();
        self.defaults.lock().unwrap().insert(key, (b.clone(), crate::now()));
        Ok(b)
    }

    pub async fn runs(&self, repo: &RepoRef, q: &RunQuery) -> Result<RunPage> {
        repo.check_kind(Kind::GitLab)?;
        let pid = self.project_id(&repo.path, false).await?;
        let page = q.page.max(1);
        let (per, pg) = (RUNS_PAGE.to_string(), page.to_string());
        let mut pairs = vec![("per_page", per.as_str()), ("page", pg.as_str())];
        match q.status.as_deref() {
            None => {}
            Some("queued") => pairs.push(("scope", "pending")),
            Some("running") => pairs.push(("scope", "running")),
            Some("completed") => pairs.push(("scope", "finished")),
            Some(s) => bail!("status must be queued, running or completed, not {s:?}"),
        }
        if let Some(b) = &q.branch {
            pairs.push(("ref", b));
        }
        let r = self.get(&format!("projects/{pid}/pipelines?{}", query(&pairs))).await?;
        if r.status != 200 {
            return Err(self.fail("pipeline list", &r));
        }
        let Value::Array(a) = r.json()? else { bail!("GitLab pipeline list is not an array") };
        let base = format!("{}/{}", self.url, repo.path);
        let runs = a.iter().filter_map(|p| run_summary(&base, p)).collect();
        let more = r.headers.get("x-next-page").and_then(|v| v.to_str().ok()).is_some_and(|n| !n.is_empty());
        Ok(RunPage { runs, next: more.then_some(page + 1) })
    }

    pub async fn run(&self, repo: &RepoRef, id: u64) -> Result<RunDetail> {
        repo.check_kind(Kind::GitLab)?;
        let pid = self.project_id(&repo.path, false).await?;
        let r = self.get(&format!("projects/{pid}/pipelines/{id}")).await?;
        if r.status != 200 {
            return Err(self.fail("pipeline lookup", &r));
        }
        let p = r.json()?;
        let base = format!("{}/{}", self.url, repo.path);
        let mut run = run_summary(&base, &p).filter(|s| s.id == id).context("malformed pipeline")?;
        let r = self.get(&format!("projects/{pid}/pipelines/{id}/jobs?per_page=100")).await?;
        if r.status != 200 {
            return Err(self.fail("pipeline jobs", &r));
        }
        let Value::Array(a) = r.json()? else { bail!("GitLab pipeline job list is not an array") };
        // The pipeline has no title of its own; its commit's is on every job.
        if let Some(t) = a.first().and_then(|j| j["commit"]["title"].as_str()) {
            run.title = t.chars().take(200).collect();
        }
        let jobs = a.iter().filter_map(|j| job_summary(&base, j)).collect();
        Ok(RunDetail { run, jobs })
    }

    /// The trace, cut like GitHub's: the download is capped (a longer one is truncated, not
    /// refused) and a page is at most `LOG_CAP`. A running job's trace is not final, so only a
    /// finished job's last page is `complete`. `section_start:` markers and ANSI stay in the text.
    pub async fn job_log(&self, repo: &RepoRef, id: u64, from: usize) -> Result<LogPage> {
        repo.check_kind(Kind::GitLab)?;
        let pid = self.project_id(&repo.path, false).await?;
        let (status, _, r) = self.request(Method::GET, &format!("projects/{pid}/jobs/{id}/trace"), None).await?;
        let (body, truncated) = net::read_prefix(r, super::LOG_DOWNLOAD_CAP).await?;
        if status != 200 {
            bail!("job log: GitLab answered {status}");
        }
        let mut page = LogPage::slice(&body, from, truncated);
        if page.complete {
            let j = self.get(&format!("projects/{pid}/jobs/{id}")).await?;
            page.complete = j.status == 200 && stat(j.json()?["status"].as_str().unwrap_or("")).0 == RunStatus::Completed;
        }
        Ok(page)
    }

    /// A project has one `.gitlab-ci.yml`, so there is nothing to list.
    pub async fn workflows(&self, _repo: &RepoRef) -> Result<Vec<Workflow>> {
        Ok(vec![])
    }

    /// `retry` re-runs the pipeline's failed and canceled jobs, which is both the dashboard's rerun
    /// and its rerun-failed. ponytail: no `play` of manual jobs; add when a "Run" button asks for it.
    pub async fn rerun(&self, repo: &RepoRef, id: u64, _failed_only: bool) -> Result<()> {
        self.act(repo, "retry", &format!("pipelines/{id}/retry"), None).await
    }

    pub async fn cancel(&self, repo: &RepoRef, id: u64) -> Result<()> {
        self.act(repo, "cancel", &format!("pipelines/{id}/cancel"), None).await
    }

    /// A new pipeline on `git_ref`. No variables in v1, and no workflow: there is one file.
    pub async fn dispatch(&self, repo: &RepoRef, _workflow: Option<&str>, git_ref: &str, inputs: &HashMap<String, String>) -> Result<()> {
        if !inputs.is_empty() {
            bail!("GitLab pipelines are started without variables for now");
        }
        self.act(repo, "run pipeline", "pipeline", Some(json!({ "ref": git_ref }))).await
    }

    /// POST `projects/<id>/<path>`. Rerun, cancel and run need the `api` scope, which the runner
    /// scopes (create_runner, manage_runner, read_api) do not include: say so.
    async fn act(&self, repo: &RepoRef, what: &str, path: &str, body: Option<Value>) -> Result<()> {
        repo.check_kind(Kind::GitLab)?;
        let pid = self.project_id(&repo.path, false).await?;
        let r = self.send(Method::POST, &format!("projects/{pid}/{path}"), body).await?;
        if (200..300).contains(&r.status) {
            return Ok(());
        }
        if r.status == 403 && serde_json::from_slice::<Value>(&r.body).is_ok_and(|v| v["error"] == "insufficient_scope") {
            bail!("GitLab {what}: the token needs the api scope for this (kiln's runner scopes only read)");
        }
        Err(self.fail(what, &r))
    }
}

fn run_summary(base: &str, p: &Value) -> Option<RunSummary> {
    let id = p["id"].as_u64()?;
    let s = |k: &str| p[k].as_str().unwrap_or("").chars().take(200).collect::<String>();
    let (r, sha, source) = (s("ref"), s("sha"), s("source"));
    let (status, outcome) = stat(&s("status"));
    // ponytail: the list has no `tag` flag, so a tag pipeline reads as a push there; the detail knows.
    let event = kind_of(p["tag"] == true, &source, &r);
    Some(RunSummary {
        id,
        name: if s("name").is_empty() { "pipeline".into() } else { s("name") },
        title: s("name"),
        number: p["iid"].as_u64().unwrap_or(0),
        attempt: 1,
        status,
        outcome,
        event,
        branch: r.clone(),
        sha: sha.clone(),
        actor: p["user"]["username"].as_str().map(|a| a.chars().take(100).collect()),
        created_at: s("created_at"),
        updated_at: s("updated_at"),
        links: links(base, Some(id), None, &sha, &r),
    })
}

fn job_summary(base: &str, j: &Value) -> Option<JobSummary> {
    let id = j["id"].as_u64()?;
    let (status, outcome) = stat(j["status"].as_str().unwrap_or(""));
    let t = |k: &str| j[k].as_str().map(|t| t.chars().take(40).collect());
    Some(JobSummary {
        id,
        name: j["name"].as_str().unwrap_or("").chars().take(200).collect(),
        status,
        outcome,
        started_at: t("started_at"),
        completed_at: t("finished_at"),
        runner: j["runner"]["description"].as_str().map(|d| d.chars().take(100).collect()),
        steps: vec![],
        links: Links { job: links(base, None, Some(id), "", "").job, ..Links::default() },
    })
}

/// What triggered a pipeline, from API data. A multi-project downstream (`pipeline`) runs the
/// target's own branch, but the caller's config controls it: Manual, never a cache writer.
fn kind_of(tag: bool, source: &str, r: &str) -> EventKind {
    if tag {
        EventKind::Tag
    } else if mr_iid(r).is_some() || source == "merge_request_event" {
        EventKind::PullRequest
    } else {
        match source {
            "push" => EventKind::Push,
            "schedule" => EventKind::Schedule,
            "web" | "api" | "trigger" | "pipeline" => EventKind::Manual,
            _ => EventKind::Other,
        }
    }
}

/// Links on the configured host, built from ids and a validated ref, never taken from a response.
fn links(base: &str, pipeline: Option<u64>, job: Option<u64>, sha: &str, r: &str) -> Links {
    let pr = mr_iid(r);
    Links {
        run: pipeline.map(|p| format!("{base}/-/pipelines/{p}")),
        job: job.map(|j| format!("{base}/-/jobs/{j}")),
        commit: (!sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("{base}/-/commit/{sha}")),
        pr: pr.map(|n| format!("{base}/-/merge_requests/{n}")),
        branch: (pr.is_none() && plain_ref(r)).then(|| format!("{base}/-/tree/{r}")),
    }
}

/// A pipeline or job status as (state, result). `canceling` is still running; `manual` waits for a person.
fn stat(s: &str) -> (RunStatus, Option<Outcome>) {
    match s {
        "success" => (RunStatus::Completed, Some(Outcome::Succeeded)),
        "success-with-warnings" => (RunStatus::Completed, Some(Outcome::SucceededWithIssues)),
        "failed" => (RunStatus::Completed, Some(Outcome::Failed)),
        "canceled" => (RunStatus::Completed, Some(Outcome::Canceled)),
        "skipped" => (RunStatus::Completed, Some(Outcome::Skipped)),
        "running" | "canceling" => (RunStatus::Running, None),
        _ => (RunStatus::Queued, None),
    }
}

/// The tags a runner of `cpus` vCPUs carries: `kiln-Ncpu`, and `kiln` too for the default size.
/// GitLab runs a job only on a runner whose tags include all the job's, so a job is ours exactly
/// when its tags are a subset of one size's set. `register` sends the same tags: the runner label list
/// minus the GitHub-only labels.
pub fn runner_tags(label: &str, cpus: u32, default_cpus: u32) -> Vec<String> {
    let mut t = vec![format!("{label}-{cpus}cpu")];
    if cpus == default_cpus {
        t.push(label.to_string());
    }
    t
}

/// The VM size a pending job asks for, if one of our runners could take it: no tags (kiln's
/// runners do not run untagged jobs), a foreign tag, a size we do not offer, or a mix of sizes
/// is someone else's.
pub fn job_size(tags: &[&str], label: &str, default_cpus: u32) -> Option<u32> {
    let mut size = None;
    let mut plain = false;
    for &t in tags {
        if t == label {
            plain = true;
        } else {
            let digits = t.strip_prefix(label)?.strip_prefix('-')?.strip_suffix("cpu")?;
            // Round-trip so `kiln-04cpu` (which no runner is tagged) is not ours.
            let n = digits.parse::<u32>().ok().filter(|n| super::SIZES.contains(n) && n.to_string() == digits)?;
            if size.replace(n).is_some_and(|s| s != n) {
                return None;
            }
        }
    }
    match (size, plain) {
        (None, true) => Some(default_cpus),
        (Some(n), false) => Some(n),
        // `kiln` rides only on the default size's runner.
        (Some(n), true) if n == default_cpus => Some(n),
        _ => None,
    }
}

/// `refs/merge-requests/<iid>/{head,merge,train}` -> iid.
fn mr_iid(r: &str) -> Option<u64> {
    let (iid, kind) = r.strip_prefix("refs/merge-requests/")?.split_once('/')?;
    (["head", "merge", "train"].contains(&kind) && iid.bytes().all(|b| b.is_ascii_digit())).then(|| iid.parse().ok())?
}

fn plain_ref(r: &str) -> bool {
    !r.is_empty()
        && r.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
        && !r.split('/').any(|p| p.is_empty() || p == "." || p == "..")
}

/// The `rel="next"` URL of a `Link` header value.
fn next_link(h: &str) -> Option<&str> {
    h.split(',').find(|p| p.contains("rel=\"next\"")).and_then(|p| p.split_once('<')?.1.split_once('>')).map(|(u, _)| u)
}

/// One path segment, percent-encoded (so `/` becomes `%2F`).
fn enc(s: &str) -> String {
    let mut u = reqwest::Url::parse("http://x/").expect("static url");
    u.path_segments_mut().expect("http url has segments").push(s);
    u.path().trim_start_matches('/').to_string()
}

fn query(pairs: &[(&str, &str)]) -> String {
    let mut u = reqwest::Url::parse("http://x/").expect("static url");
    u.query_pairs_mut().extend_pairs(pairs);
    u.query().unwrap_or("").to_string()
}

/// The install's random 6-hex id (`<data>/install_id`), created on first use. Runner
/// descriptions are `<install>-<vm id>`, so a sweep never touches another install's runners.
pub fn install_id(data: &Path) -> Result<String> {
    let p = data.join("install_id");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let s = s.trim();
        if s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Ok(s.to_string());
        }
    }
    let mut b = [0u8; 3];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).map_err(|_| anyhow!("no random bytes"))?;
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::fs::write(&p, &id).with_context(|| format!("write {}", p.display()))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::{Request, State},
        response::Response,
    };
    use std::sync::Arc;

    const SPOOF: &str = "https://gitlab.example.org";
    type Routes = Arc<Mutex<HashMap<String, (u16, Vec<(String, String)>, String)>>>;
    type Log = Arc<Mutex<Vec<(String, Option<String>)>>>;
    /// "METHOD path" and body of every request, in order.
    type Sent = Arc<Mutex<Vec<(String, String)>>>;

    /// A mock GitLab on loopback: `path?query` -> canned status, headers and body. Anything
    /// unrouted is a 404, so a changed request sequence shows up in `requests()`.
    struct Mock {
        base: String,
        routes: Routes,
        log: Log,
        sent: Sent,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        async fn start() -> Mock {
            let (routes, log, sent): (Routes, Log, Sent) = Default::default();
            async fn serve(State((routes, log, sent)): State<(Routes, Log, Sent)>, req: Request) -> Response {
                let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
                let tok = req.headers().get("private-token").and_then(|v| v.to_str().ok()).map(String::from);
                let method = req.method().to_string();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                log.lock().unwrap().push((path.clone(), tok));
                sent.lock().unwrap().push((format!("{method} {path}"), String::from_utf8_lossy(&body).into_owned()));
                // A route registered for one method wins over the method-less one.
                let r = routes.lock().unwrap();
                let (status, headers, body) = r.get(&format!("{method} {path}")).or_else(|| r.get(&path)).cloned().unwrap_or((
                    404,
                    vec![],
                    r#"{"message":"404 Not Found"}"#.into(),
                ));
                drop(r);
                let mut r = Response::builder().status(status);
                for (k, v) in headers {
                    r = r.header(k, v);
                }
                r.body(Body::from(body)).unwrap()
            }
            let app = Router::new().fallback(serve).with_state((routes.clone(), log.clone(), sent.clone()));
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let _ = axum::serve(l, app).await;
            });
            Mock { base, routes, log, sent, task }
        }

        /// `api/v4/<path>`; the fixtures' placeholder host becomes this mock's origin.
        fn route(&self, path: &str, status: u16, headers: Vec<(String, String)>, body: String) {
            let headers = headers.into_iter().map(|(k, v)| (k, v.replace(SPOOF, &self.base))).collect();
            self.routes.lock().unwrap().insert(format!("/api/v4/{path}"), (status, headers, body.replace(SPOOF, &self.base)));
        }

        /// Like `route`, for one method only (`PUT`, `DELETE`, ...), body from a fixture.
        fn on(&self, method: &str, path: &str, status: u16, body: String) {
            self.routes.lock().unwrap().insert(format!("{method} /api/v4/{path}"), (status, vec![], body.replace(SPOOF, &self.base)));
        }

        /// "METHOD path" of every request so far.
        fn calls(&self) -> Vec<String> {
            self.sent.lock().unwrap().iter().map(|(c, _)| c.replace("/api/v4/", "")).collect()
        }

        fn ok(&self, path: &str, fixture: &str) {
            self.route(path, 200, vec![], fx(fixture));
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().iter().map(|(p, _)| p.trim_start_matches("/api/v4/").to_string()).collect()
        }

        fn count(&self, needle: &str) -> usize {
            self.requests().iter().filter(|r| r.contains(needle)).count()
        }
    }

    fn fx(name: &str) -> String {
        let p = format!("{}/src/testdata/forge/gitlab/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    fn fx_headers(name: &str) -> Vec<(String, String)> {
        fx(name).lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    const TOKEN: &str = "tok-not-for-logs";

    fn cfg(url: &str) -> ForgeCfg {
        ForgeCfg {
            id: ForgeId::new("gl").unwrap(),
            kind: super::super::Kind::GitLab,
            url: Some(url.into()),
            credential: None,
            network: None,
            repos: vec!["acme/demo".into()],
            extra: Default::default(),
        }
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiln-gl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("forges")).unwrap();
        d
    }

    /// A forge talking to `m`, install `a1b2c3`, five jobs per page.
    fn gl(name: &str, m: &Mock) -> GitLab {
        let d = temp(name);
        std::fs::write(d.join("forges/gl.token"), format!("{TOKEN}\n")).unwrap();
        std::fs::write(d.join("install_id"), "a1b2c3").unwrap();
        let mut g = GitLab::new(&cfg(SPOOF), &d).unwrap();
        g.url = m.base.clone();
        g.client = net::base().build().unwrap();
        g.unguarded = true;
        g.per_page = 5;
        g
    }

    fn repo() -> RepoRef {
        RepoRef::parse("gl:acme/demo").unwrap()
    }

    fn jobs_path(per_page: usize, cursor: Option<&str>) -> String {
        let q = format!("projects/1/jobs?scope%5B%5D=pending&scope%5B%5D=running&per_page={per_page}&pagination=keyset");
        cursor.map_or(q.clone(), |c| format!("{q}&{}", query(&[("cursor", c)])))
    }

    /// The four recorded keyset pages (5 jobs each, the last exactly full and without `Link`).
    fn serve_pages(m: &Mock) {
        let mut cursor: Option<String> = None;
        for n in 1..=4 {
            let h = fx_headers(&format!("jobs_p{n}.headers"));
            m.route(&jobs_path(5, cursor.as_deref()), 200, h.clone(), fx(&format!("jobs_p{n}.json")));
            cursor = h.iter().find(|(k, _)| k == "X-Next-Cursor").map(|(_, v)| v.clone());
        }
        assert!(cursor.is_none(), "the last recorded page carries no cursor");
    }

    /// Project, branches and merge requests as the lab had them: MR 2 is same-project, MR 3 from a fork.
    fn serve_lookups(m: &Mock) {
        m.ok("projects/acme%2Fdemo", "project.json");
        for b in ["ci", "feat", "down", "long"] {
            m.ok(&format!("projects/1/repository/branches/{b}"), "branch_ci.json");
        }
        m.ok("projects/1/merge_requests/2", "mr_same.json");
        m.ok("projects/1/merge_requests/3", "mr_fork.json");
    }

    fn recorded_jobs() -> Vec<Value> {
        (1..=4).flat_map(|n| serde_json::from_str::<Vec<Value>>(&fx(&format!("jobs_p{n}.json"))).unwrap()).collect()
    }

    fn sizes(d: &Demand) -> Vec<(u32, usize)> {
        let mut v: Vec<_> = d.by_size.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn demand_over_recorded_keyset_pages() {
        let m = Mock::start().await;
        serve_lookups(&m);
        serve_pages(&m);
        let g = gl("pages", &m);
        let d = g.demand_for(&repo(), "kiln", 4, 16).await.unwrap();
        // Ours: kiln / kiln-4cpu / [kiln, kiln-4cpu] x3 in the ci push pipeline, kiln jobs of the feat branch, the same-project MR
        // and the down branch (push and downstream); kiln-2cpu children. Not ours: untagged, windows, docker+kiln, kiln-64cpu.
        assert_eq!(sizes(&d), [(2, 4), (4, 7)]);
        // The fork MR's own jobs and its child pipeline's, pipelines 120-123.
        assert_eq!(d.refused_forks, 4);
        let c = &d.claimed["kiln-7-0"];
        assert_eq!((c.id.as_str(), c.fork), ("251", false));
        assert_eq!(c.url, format!("{}/acme/demo/-/jobs/251", m.base));
        assert_eq!((c.run.branch.as_str(), c.run.event.as_str(), c.run.kind), ("long", "push", EventKind::Push));
        assert_eq!(d.claimed.len(), 1);
        // The token goes on every request and the cursor was rebuilt, not copied from the Link URL.
        assert!(m.log.lock().unwrap().iter().all(|(_, t)| t.as_deref() == Some(TOKEN)));
        assert_eq!(m.count("/jobs?"), 4);
        assert!(m.requests().contains(&jobs_path(5, Some("eyJpZCI6IjI0NSIsIl9rZCI6Im4ifQ=="))));
        // A second poll asks the jobs again but remembers the project id and every origin answer.
        m.log.lock().unwrap().clear();
        g.demand_for(&repo(), "kiln", 4, 16).await.unwrap();
        assert_eq!(m.count("/jobs?"), 4);
        assert_eq!(m.requests().len(), 4);
    }

    #[tokio::test]
    async fn pagination_link_on_another_origin_is_an_error_and_never_fetched() {
        let m = Mock::start().await;
        serve_lookups(&m);
        let mut h = fx_headers("jobs_p1.headers");
        h[0].1 = "<https://evil.example.net/api/v4/projects/1/jobs?cursor=abc>; rel=\"next\"".to_string();
        m.route(&jobs_path(5, None), 200, h, fx("jobs_p1.json"));
        let e = gl("origin", &m).demand_for(&repo(), "kiln", 4, 16).await.err().unwrap();
        assert!(format!("{e:#}").contains("another origin"), "{e:#}");
        assert_eq!(m.count("/jobs?"), 1);
    }

    #[tokio::test]
    async fn bad_cursor_500_fails_the_poll_and_the_next_one_restarts_at_page_one() {
        let m = Mock::start().await;
        serve_lookups(&m);
        serve_pages(&m);
        let second = jobs_path(5, Some("eyJpZCI6IjI0NSIsIl9rZCI6Im4ifQ=="));
        m.route(&second, 500, vec![], fx("err_500_cursor.json"));
        let g = gl("cursor", &m);
        let e = g.demand_for(&repo(), "kiln", 4, 16).await.err().unwrap();
        assert!(format!("{e:#}").contains("HTTP 500"), "{e:#}");
        assert_eq!(m.count("/jobs?"), 2);
        let e = g.demand_for(&repo(), "kiln", 4, 16).await.err().unwrap();
        assert!(e.to_string().contains("job list"));
        assert_eq!(m.requests().iter().filter(|r| **r == jobs_path(5, None)).count(), 2, "page 1 again, not a loop");
        assert_eq!(m.count("/jobs?"), 4);
    }

    #[tokio::test]
    async fn a_page_cursor_that_repeats_is_an_error() {
        let m = Mock::start().await;
        serve_lookups(&m);
        let h = fx_headers("jobs_p1.headers");
        m.route(&jobs_path(5, None), 200, h.clone(), fx("jobs_p1.json"));
        m.route(&jobs_path(5, Some("eyJpZCI6IjI0NSIsIl9rZCI6Im4ifQ==")), 200, h, fx("jobs_p2.json"));
        let e = gl("loop", &m).demand_for(&repo(), "kiln", 4, 16).await.err().unwrap();
        assert!(e.to_string().contains("repeats"), "{e:#}");
    }

    /// A pending `kiln`-tagged job built from a recorded one.
    fn job(n: u64, f: impl FnOnce(&mut Value)) -> Value {
        let mut j = recorded_jobs().into_iter().find(|j| j["id"] == 215).unwrap();
        j["id"] = (1000 + n).into();
        j["pipeline"]["id"] = (2000 + n).into();
        f(&mut j);
        j
    }

    fn set(j: &mut Value, r: &str, source: &str) {
        j["ref"] = r.into();
        j["pipeline"]["source"] = source.into();
    }

    async fn serve_one_page(m: &Mock, jobs: Vec<Value>) {
        m.route(&jobs_path(5, None), 200, vec![], Value::Array(jobs).to_string());
    }

    #[tokio::test]
    async fn fork_detection_is_by_ref_and_fails_closed() {
        let m = Mock::start().await;
        serve_lookups(&m);
        m.route("projects/1/repository/branches/gone", 404, vec![], fx("branch_404.json"));
        m.route("projects/1/merge_requests/9", 404, vec![], fx("mr_404.json"));
        m.route("projects/1/merge_requests/7", 500, vec![], "{}".into());
        let cases: Vec<(&str, Value, bool)> = vec![
            ("plain branch", job(1, |j| set(j, "ci", "push")), false),
            ("branch deleted since", job(2, |j| set(j, "gone", "push")), true),
            ("tag", job(3, |j| (set(j, "v1", "push"), j["tag"] = true.into()).1), false),
            ("same-project MR head", job(4, |j| set(j, "refs/merge-requests/2/head", "merge_request_event")), false),
            ("same-project merge train", job(5, |j| set(j, "refs/merge-requests/2/train", "merge_request_event")), false),
            ("fork MR", job(6, |j| set(j, "refs/merge-requests/3/head", "merge_request_event")), true),
            ("fork merge ref", job(7, |j| set(j, "refs/merge-requests/3/merge", "merge_request_event")), true),
            ("fork MR train", job(8, |j| set(j, "refs/merge-requests/3/train", "merge_request_event")), true),
            ("child pipeline of a fork MR", job(9, |j| set(j, "refs/merge-requests/3/head", "parent_pipeline")), true),
            ("downstream pipeline", job(10, |j| set(j, "ci", "pipeline")), false),
            ("unknown source", job(11, |j| set(j, "ci", "external_pull_request_event")), true),
            ("no source", job(12, |j| j["pipeline"]["source"] = Value::Null), true),
            ("MR not found", job(13, |j| set(j, "refs/merge-requests/9/head", "merge_request_event")), true),
            ("MR lookup fails", job(14, |j| set(j, "refs/merge-requests/7/head", "merge_request_event")), true),
            ("refs/pipelines", job(15, |j| set(j, "refs/pipelines/7", "push")), true),
            ("odd MR ref", job(16, |j| set(j, "refs/merge-requests/3/evil", "merge_request_event")), true),
            ("no pipeline id", job(17, |j| j["pipeline"]["id"] = Value::Null), true),
        ];
        let (jobs, want): (Vec<_>, Vec<_>) = cases.iter().map(|(_, j, fork)| (j.clone(), *fork)).unzip();
        serve_one_page(&m, jobs).await;
        let g = gl("forks", &m);
        let d = g.demand_for(&repo(), "kiln", 4, 16).await.unwrap();
        let (forks, ours) = (want.iter().filter(|&&f| f).count(), want.iter().filter(|&&f| !f).count());
        assert_eq!((d.refused_forks, d.by_size.get(&4).copied().unwrap_or(0)), (forks, ours));
        // One case at a time, so a swapped pair cannot hide behind equal totals.
        for (name, j, fork) in &cases {
            serve_one_page(&m, vec![j.clone()]).await;
            let d = g.demand_for(&repo(), "kiln", 4, 16).await.unwrap();
            assert_eq!(d.refused_forks == 1, *fork, "{name}");
            assert_eq!(d.by_size.get(&4).copied().unwrap_or(0) == 1, !*fork, "{name}");
        }
        // Answers are remembered (even "gone"), failed lookups are asked again.
        assert_eq!(m.count("branches/gone"), 1);
        assert_eq!(m.count("merge_requests/9"), 2);
        assert_eq!(m.count("merge_requests/7"), 2);
    }

    #[tokio::test]
    async fn claims_need_our_install_prefix_and_a_live_runner() {
        let m = Mock::start().await;
        serve_lookups(&m);
        let running = |n, desc: Value, f: fn(&mut Value)| {
            job(n, |j| {
                j["status"] = "running".into();
                j["runner"] = desc;
                f(j)
            })
        };
        let r = |d: &str| json!({"id": 5, "description": d});
        serve_one_page(
            &m,
            vec![
                running(1, r("a1b2c3-kiln-1-0"), |_| {}),
                running(2, r("zzzzzz-kiln-1-1"), |_| {}),
                running(3, Value::Null, |_| {}),
                running(4, r("a1b2c3-"), |_| {}),
                running(5, r("a1b2c3-kiln-1-4"), |j| set(j, "ci", "pipeline")),
                running(6, r("a1b2c3-kiln-1-5"), |j| set(j, "refs/merge-requests/3/head", "merge_request_event")),
                running(7, r("a1b2c3-kiln-1-6"), |j| (set(j, "v1", "push"), j["tag"] = true.into()).1),
            ],
        )
        .await;
        let d = gl("claims", &m).demand_for(&repo(), "kiln", 4, 16).await.unwrap();
        let mut ids: Vec<_> = d.claimed.keys().cloned().collect();
        ids.sort();
        assert_eq!(ids, ["kiln-1-0", "kiln-1-4", "kiln-1-5", "kiln-1-6"]);
        assert!(d.by_size.is_empty() && d.refused_forks == 0);
        // A downstream `pipeline` run is Manual, never a trusted writer.
        let down = &d.claimed["kiln-1-4"];
        assert_eq!((down.run.kind, down.fork, down.run.event.as_str()), (EventKind::Manual, false, "pipeline"));
        // A fork MR claim carries the fork flag (the kill backstop), the MR number and the source branch.
        let fork = &d.claimed["kiln-1-5"];
        assert!(fork.fork);
        assert_eq!((fork.run.kind, fork.run.pr, fork.run.branch.as_str()), (EventKind::PullRequest, Some(3), "fx"));
        assert_eq!(fork.run.links.pr.as_deref(), Some(&*format!("{}/acme/demo/-/merge_requests/3", m.base)));
        let tag = &d.claimed["kiln-1-6"];
        assert_eq!((tag.run.kind, tag.fork), (EventKind::Tag, false));
        let c = &d.claimed["kiln-1-0"];
        assert_eq!(c.run.sha.len(), 40);
        assert_eq!(c.run.links.commit.as_deref(), Some(&*format!("{}/acme/demo/-/commit/{}", m.base, c.run.sha)));
        assert_eq!((c.run.file.as_str(), c.run.workflow.as_str()), (".gitlab-ci.yml", "pipeline"));
        assert!(c.queued_at > 1_700_000_000);
    }

    #[test]
    fn job_tags_must_fit_one_of_our_runners() {
        let s = |t: &[&str], d| job_size(t, "kiln", d);
        assert_eq!(s(&[], 4), None, "untagged jobs are ignored");
        assert_eq!(s(&["kiln"], 4), Some(4));
        assert_eq!(s(&["kiln-4cpu"], 8), Some(4));
        assert_eq!(s(&["kiln-2cpu"], 4), Some(2));
        assert_eq!(s(&["kiln", "kiln-4cpu"], 4), Some(4), "the default size's runner has both tags");
        assert_eq!(s(&["kiln", "kiln-2cpu"], 4), None, "only the default size is also tagged kiln");
        assert_eq!(s(&["kiln", "kiln-2cpu"], 2), Some(2));
        assert_eq!(s(&["kiln", "docker"], 4), None, "an extra tag no runner of ours has");
        assert_eq!(s(&["docker"], 4), None);
        assert_eq!(s(&["kiln-2cpu", "kiln-4cpu"], 4), None);
        for bad in ["kiln-64cpu", "kiln-04cpu", "kiln-cpu", "kiln-4", "Kiln", "kiln-4CPU", "kiln--4cpu", "kiln-+4cpu"] {
            assert_eq!(s(&[bad], 4), None, "{bad}");
        }
        // An arm64 host's label is `kiln-arm64`: plain x64 tags are not its jobs.
        let a = |t: &[&str]| job_size(t, &crate::forge::arch_label("kiln", true), 4);
        assert_eq!((a(&["kiln-arm64"]), a(&["kiln-arm64-2cpu"]), a(&["kiln"]), a(&["kiln-2cpu"])), (Some(4), Some(2), None, None));
        assert_eq!(runner_tags("kiln", 4, 4), ["kiln-4cpu", "kiln"]);
        assert_eq!(runner_tags("kiln", 8, 4), ["kiln-8cpu"]);
        // What a runner is registered with is what the job is matched against.
        for (n, d) in [(2, 4), (4, 4), (8, 4), (2, 2)] {
            let t = runner_tags("kiln", n, d);
            assert_eq!(job_size(&t.iter().map(String::as_str).collect::<Vec<_>>(), "kiln", d), Some(n));
        }
    }

    #[tokio::test]
    async fn jobs_bigger_than_the_host_are_not_demand() {
        let m = Mock::start().await;
        serve_lookups(&m);
        serve_one_page(&m, vec![job(1, |j| j["tag_list"] = json!(["kiln-4cpu"])), job(2, |j| j["tag_list"] = json!(["kiln-2cpu"]))]).await;
        let d = gl("oversize", &m).demand_for(&repo(), "kiln", 4, 3).await.unwrap();
        assert_eq!(sizes(&d), [(2, 1)]);
        assert_eq!(m.count("repository/branches"), 1, "a job we would not run is not looked up");
    }

    #[tokio::test]
    async fn project_ids_are_resolved_once_and_checked() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        let g = gl("ids", &m);
        assert_eq!(g.project_id("acme/demo", false).await.unwrap(), 1);
        assert_eq!(g.project_id("acme/demo", false).await.unwrap(), 1);
        assert_eq!(m.count("projects/acme%2Fdemo"), 1);
        assert_eq!(g.project_id("acme/demo", true).await.unwrap(), 1);
        assert_eq!(m.count("projects/acme%2Fdemo"), 2);
        // Nested groups are one encoded segment.
        m.route("projects/acme%2Fsub%2Fdemo", 200, vec![], fx("project.json"));
        let e = g.project_id("acme/sub/demo", false).await.err().unwrap();
        assert!(e.to_string().contains("different project"), "{e:#}");
        m.route("projects/acme%2Fnope", 404, vec![], fx("project_404.json"));
        let e = g.project_id("acme/nope", false).await.err().unwrap();
        assert!(e.to_string().contains("not found"), "{e:#}");
    }

    #[tokio::test]
    async fn a_stale_project_id_is_resolved_again_once() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        m.route(&jobs_path(5, None), 404, vec![], fx("jobs_404.json"));
        let e = gl("stale", &m).demand_for(&repo(), "kiln", 4, 16).await.err().unwrap();
        assert!(e.to_string().contains("no jobs endpoint"), "{e:#}");
        assert_eq!((m.count("projects/acme%2Fdemo"), m.count("/jobs?")), (2, 2));
    }

    #[tokio::test]
    async fn errors_are_named_and_a_429_backs_the_forge_off() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        let g = gl("errors", &m);
        m.route(&jobs_path(5, None), 401, vec![], fx("err_401.json"));
        let e = format!("{:#}", g.demand_for(&repo(), "kiln", 4, 16).await.err().unwrap());
        assert!(e.contains("HTTP 401") && e.contains("token was rejected"), "{e}");
        m.route(&jobs_path(5, None), 403, vec![], fx("err_403_scope.json"));
        let e = format!("{:#}", g.demand_for(&repo(), "kiln", 4, 16).await.err().unwrap());
        assert!(e.contains("HTTP 403") && e.contains("read_api"), "{e}");
        assert!(g.health().is_none());
        m.route(&jobs_path(5, None), 429, fx_headers("err_429.headers"), fx("err_429.txt"));
        let e = format!("{:#}", g.demand_for(&repo(), "kiln", 4, 16).await.err().unwrap());
        assert!(e.contains("HTTP 429"), "{e}");
        assert!(g.health().unwrap().contains("rate limit"));
        // Paused: no more requests until Retry-After has passed.
        let n = m.requests().len();
        assert!(g.demand_for(&repo(), "kiln", 4, 16).await.is_err());
        assert_eq!(m.requests().len(), n);
        assert!(!e.contains(TOKEN) && !g.health().unwrap().contains(TOKEN));
    }

    #[test]
    fn link_headers() {
        let l = r#"<https://gl.example/a?cursor=x%3D>; rel="next""#;
        assert_eq!(next_link(l), Some("https://gl.example/a?cursor=x%3D"));
        assert_eq!(
            next_link(r#"<https://gl.example/a?page=2>; rel="next", <https://gl.example/a?page=1>; rel="first""#),
            Some("https://gl.example/a?page=2")
        );
        assert_eq!(next_link(r#"<https://gl.example/a?page=1>; rel="first""#), None);
        assert_eq!(next_link(""), None);
    }

    #[test]
    fn health_and_credentials() {
        let d = temp("cred");
        let g = GitLab::new(&cfg(SPOOF), &d).unwrap();
        assert!(!g.has_credential());
        let h = g.health().unwrap();
        assert!(h.contains("forges/gl.token"), "{h}");
        assert_eq!(g.auth()["source"], "none");
        std::fs::write(d.join("forges/gl.token"), format!("  {TOKEN}\n")).unwrap();
        g.load_token(&d);
        assert!(g.has_credential() && g.health().is_none());
        assert_eq!(g.auth()["source"], "file");
        assert_eq!(env_name(&ForgeId::new("my-gl").unwrap()), "KILN_FORGE_MY_GL_TOKEN");
        let mut c = cfg(SPOOF);
        c.credential = Some(Credential::Env);
        assert!(GitLab::new(&c, &d).unwrap().health().unwrap().contains("KILN_FORGE_GL_TOKEN"));
        // The install id is made once, then stable.
        let _ = std::fs::remove_file(d.join("install_id"));
        let id = install_id(&d).unwrap();
        assert!(id.len() == 6 && id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(install_id(&d).unwrap(), id);
        std::fs::write(d.join("install_id"), "nonsense").unwrap();
        assert_ne!(install_id(&d).unwrap(), "nonsense");
        assert_eq!(g.repos(&cfg(SPOOF)), [repo()]);
    }

    #[test]
    fn urls_are_checked_before_any_request() {
        let d = temp("urls");
        assert!(GitLab::new(&cfg("http://gitlab.example.org"), &d).is_err(), "public forges are https only");
        assert!(GitLab::new(&cfg("https://u:p@gitlab.example.org"), &d).is_err());
        let mut c = cfg(SPOOF);
        c.url = None;
        assert!(GitLab::new(&c, &d).is_err());
    }

    #[tokio::test]
    async fn launches_stay_off_and_the_tokenless_forge_fails_closed() {
        use super::super::{Forge, Kind};
        let gh = Arc::new(crate::github::Gh::new(String::new(), "none"));
        let f = Forge::new(&cfg(SPOOF), &gh, &temp("stubs")).unwrap();
        assert_eq!(f.kind(), Kind::GitLab);
        assert!(f.gated());
        let e = f.register(&repo(), "kiln-1-0", &["kiln-4cpu".into()]).await.err().unwrap();
        assert!(e.to_string().contains("later version"), "{e:#}");
        assert!(matches!(f.deregister(&repo(), 1, Reason::Surplus).await, Dereg::Err(_)));
        assert!(f.pause(&repo(), 1).await.is_err());
        assert!(f.verdict_facts(&repo(), "1").await.is_err());
        assert!(f.sweep(&repo()).await.is_err());
        assert!(f.runs(&repo(), &Default::default()).await.is_err());
        assert_eq!(f.repo_paused(&repo()), None);
        assert!(f.health().unwrap().contains("no token"));
    }

    #[tokio::test]
    async fn demand_reports_no_launchable_jobs_while_launches_are_off() {
        let m = Mock::start().await;
        serve_lookups(&m);
        serve_one_page(&m, vec![job(1, |_| {})]).await;
        let g = gl("off", &m);
        assert_eq!(sizes(&g.demand_for(&repo(), "kiln", 4, 16).await.unwrap()), [(4, 1)], "the queue is read");
        assert!(g.demand(&repo(), "kiln", 4).await.unwrap().by_size.is_empty(), "but nothing is launchable");
    }

    fn mint_error(e: &anyhow::Error) -> &MintError {
        e.downcast_ref::<MintError>().unwrap_or_else(|| panic!("not a MintError: {e:#}"))
    }

    /// A forge that has the project's id cached, talking to `m`.
    fn gl_ready(name: &str, m: &Mock) -> GitLab {
        m.ok("projects/acme%2Fdemo", "project.json");
        let mut g = gl(name, m);
        g.settle = std::time::Duration::ZERO;
        g
    }

    const LABELS: [&str; 6] = ["self-hosted", "linux", "x64", "kiln-2cpu", "kiln", "ARM64"];

    #[tokio::test]
    async fn register_posts_the_runner_and_hands_the_guest_only_its_own_token() {
        let m = Mock::start().await;
        m.on("POST", "user/runners", 201, fx("runner_register.json"));
        let g = gl_ready("reg", &m);
        let labels: Vec<String> = LABELS.iter().map(|s| s.to_string()).collect();
        let reg = g.mint(&repo(), "kiln-5-0", &labels).await.unwrap();
        assert_eq!(reg.runner_id, 79);
        let b64 = base64::engine::general_purpose::STANDARD.encode("glrt-FIXTURE-REDACTED");
        assert_eq!(reg.guest_secret, format!("kiln.forge=gitlab\nkiln.url={}\nkiln.cred={b64}", m.base));
        assert!(!reg.guest_secret.contains(TOKEN), "never the PAT");
        let sent = m.sent.lock().unwrap();
        let (call, body) = sent.iter().find(|(c, _)| c.starts_with("POST ")).unwrap();
        assert_eq!(call, "POST /api/v4/user/runners");
        let body: Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            body,
            json!({"runner_type": "project_type", "project_id": 1, "description": "a1b2c3-kiln-5-0", "tag_list": ["kiln-2cpu", "kiln"],
                   "run_untagged": false, "locked": true, "access_level": "not_protected"})
        );
        // The tags are the ones demand matches on.
        assert_eq!(body["tag_list"], json!(runner_tags("kiln", 2, 2)));
        assert!(g.mine.lock().unwrap().contains(&79));
    }

    async fn mint_err(g: &GitLab) -> anyhow::Error {
        g.mint(&repo(), "kiln-5-0", &["kiln-2cpu".to_string()]).await.err().unwrap()
    }

    #[tokio::test]
    async fn register_errors_name_the_cause_and_keep_the_token_out() {
        let m = Mock::start().await;
        let g = gl_ready("regerr", &m);
        // Developer and below, the instance setting and the toggle all look the same (SP-6).
        m.on("POST", "user/runners", 403, fx("err_403_role.json"));
        let e = mint_err(&g).await;
        let me = mint_error(&e);
        assert_eq!((me.status, me.github_wide()), (Some(403), false));
        let s = e.to_string();
        assert!(
            s.contains("GitLab returned HTTP 403")
                && s.contains("Maintainer")
                && s.contains("valid_runner_registrars")
                && s.contains("toggle"),
            "{s}"
        );
        // A wrong scope is a different 403.
        m.on("POST", "user/runners", 403, fx("err_403_scope.json"));
        let s = mint_err(&g).await.to_string();
        assert!(s.contains("create_runner scope") && !s.contains("Maintainer"), "{s}");
        m.on("POST", "user/runners", 401, fx("err_401.json"));
        assert!(mint_err(&g).await.to_string().contains("rejected"));
        m.on("POST", "user/runners", 502, "<html>bad gateway</html>".into());
        let e = mint_err(&g).await;
        assert!(mint_error(&e).github_wide());
        // A 201 without a runner token is no registration.
        m.on("POST", "user/runners", 201, r#"{"id":5,"token":"not-a-runner-token"}"#.into());
        let e = mint_err(&g).await;
        assert!(e.downcast_ref::<MintError>().is_none() && !e.to_string().contains("not-a-runner-token"), "{e:#}");
        assert!(g.mine.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_gitlab_is_a_forge_wide_registration_failure() {
        let m = Mock::start().await;
        let g = gl_ready("down", &m);
        g.project_id("acme/demo", false).await.unwrap();
        let mut g = g;
        g.url = "http://127.0.0.1:1".into();
        let e = g.mint(&repo(), "kiln-5-0", &[]).await.err().unwrap();
        let me = mint_error(&e);
        assert!(me.status.is_none() && me.github_wide());
        assert!(!e.to_string().contains(TOKEN));
    }

    #[tokio::test]
    async fn pause_pauses_waits_then_lists_the_jobs_the_runner_holds() {
        let m = Mock::start().await;
        m.on("PUT", "runners/79", 200, fx("runner_paused.json"));
        m.ok("runners/79/jobs?status=running", "runner_jobs_running.json");
        let g = gl_ready("pause", &m);
        assert_eq!(g.pause(79).await.unwrap(), ["251"]);
        assert_eq!(m.calls(), ["PUT runners/79", "GET runners/79/jobs?status=running"]);
        assert_eq!(serde_json::from_str::<Value>(&m.sent.lock().unwrap()[0].1).unwrap(), json!({"paused": true}));
        m.ok("runners/79/jobs?status=running", "runner_jobs_none.json");
        assert!(g.pause(79).await.unwrap().is_empty());
        // Fail closed: a refused pause, an unpaused answer, a missing runner, an unreadable list.
        m.on("PUT", "runners/79", 403, fx("err_403_scope.json"));
        assert!(g.pause(79).await.unwrap_err().to_string().contains("scope"));
        m.on("PUT", "runners/79", 200, fx("runner_new.json"));
        assert!(g.pause(79).await.is_err(), "paused was not confirmed");
        m.on("PUT", "runners/79", 404, fx("err_404_runner.json"));
        assert!(g.pause(79).await.is_err());
        m.on("PUT", "runners/79", 200, fx("runner_paused.json"));
        m.route("runners/79/jobs?status=running", 200, vec![], r#"[{"status":"running"}]"#.into());
        assert!(g.pause(79).await.is_err(), "a job without an id");
    }

    fn serve_runner(m: &Mock, jobs: &str) {
        m.on("PUT", "runners/79", 200, fx("runner_paused.json"));
        m.ok("runners/79/jobs?status=running", jobs);
        m.on("DELETE", "runners/79", 204, String::new());
    }

    #[tokio::test]
    async fn deregister_deletes_an_idle_runner_and_leaves_a_busy_one() {
        let m = Mock::start().await;
        serve_runner(&m, "runner_jobs_none.json");
        let g = gl_ready("dereg", &m);
        g.mine.lock().unwrap().insert(79);
        assert!(matches!(g.deregister(&repo(), 79, Reason::Surplus).await, Dereg::Gone));
        assert_eq!(m.calls(), ["PUT runners/79", "GET runners/79/jobs?status=running", "DELETE runners/79"]);
        assert!(g.mine.lock().unwrap().is_empty());
        // It got a job meanwhile: unpaused again, and not deleted.
        serve_runner(&m, "runner_jobs_running.json");
        m.sent.lock().unwrap().clear();
        assert!(matches!(g.deregister(&repo(), 79, Reason::Warm).await, Dereg::Busy));
        assert_eq!(m.calls(), ["PUT runners/79", "GET runners/79/jobs?status=running", "PUT runners/79"]);
        assert_eq!(serde_json::from_str::<Value>(&m.sent.lock().unwrap()[2].1).unwrap(), json!({"paused": false}));
        // Already gone (the guest deleted itself, or an earlier retire did).
        m.on("PUT", "runners/79", 404, fx("err_404_runner.json"));
        m.sent.lock().unwrap().clear();
        assert!(matches!(g.deregister(&repo(), 79, Reason::Unused).await, Dereg::Gone));
        assert_eq!(m.calls(), ["PUT runners/79"]);
        // A refused delete leaves the VM alone.
        serve_runner(&m, "runner_jobs_none.json");
        m.on("DELETE", "runners/79", 403, fx("err_403_scope.json"));
        assert!(matches!(g.deregister(&repo(), 79, Reason::Surplus).await, Dereg::Err(_)));
        // An unreadable job list is no proof of idleness: nothing is deleted, the runner is unpaused.
        m.route("runners/79/jobs?status=running", 500, vec![], "{}".into());
        m.sent.lock().unwrap().clear();
        assert!(matches!(g.deregister(&repo(), 79, Reason::Surplus).await, Dereg::Err(_)));
        assert_eq!(m.calls().last().unwrap(), "PUT runners/79");
        assert_eq!(m.count("DELETE"), 0);
    }

    #[tokio::test]
    async fn a_stale_policy_deletes_the_runner_even_when_a_job_raced_in() {
        let m = Mock::start().await;
        serve_runner(&m, "runner_jobs_running.json");
        let g = gl_ready("stale", &m);
        assert!(matches!(g.deregister(&repo(), 79, Reason::StalePolicy).await, Dereg::Gone));
        assert_eq!(m.calls(), ["PUT runners/79", "GET runners/79/jobs?status=running", "DELETE runners/79"]);
        // Even when pausing failed: the VM dies either way, so the runner must not outlive it.
        m.sent.lock().unwrap().clear();
        m.on("PUT", "runners/79", 500, "{}".into());
        assert!(matches!(g.deregister(&repo(), 79, Reason::StalePolicy).await, Dereg::Gone));
        assert_eq!(m.calls(), ["PUT runners/79", "DELETE runners/79"]);
    }

    /// RFC 3339 for `t` seconds since the epoch (Hinnant's civil-from-days).
    fn ts(t: u64) -> String {
        let (days, s) = ((t / 86400) as i64, t % 86400);
        let z = days + 719468;
        let (era, doe) = (z.div_euclid(146097), z.rem_euclid(146097));
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let (d, mo) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
        let y = yoe + era * 400 + i64::from(mo <= 2);
        format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.000Z", s / 3600, s % 3600 / 60, s % 60)
    }

    #[test]
    fn the_test_timestamp_round_trips() {
        for t in [0, 951_782_400, 1_760_000_000, 4_102_444_800] {
            assert_eq!(crate::github::parse_rfc3339(&ts(t)), Some(t));
        }
    }

    #[tokio::test]
    async fn sweep_deletes_orphans_by_prefix_and_age_never_by_status() {
        let now = crate::now();
        let runner = |id: u64, desc: &str, status: &str, age: u64, kind: &str| {
            let mut r = serde_json::from_str::<Vec<Value>>(&fx("runner_list.json")).unwrap().remove(0);
            r["id"] = id.into();
            r["description"] = desc.into();
            r["status"] = status.into();
            r["created_at"] = ts(now - age).into();
            r["runner_type"] = kind.into();
            r
        };
        let day = 86_400;
        let list = vec![
            runner(1, "a1b2c3-kiln-1-0", "never_contacted", 11 * 60, "project_type"), // died before its first poll
            runner(2, "a1b2c3-kiln-1-1", "never_contacted", 5 * 60, "project_type"),  // still booting
            runner(3, "a1b2c3-kiln-1-2", "online", 2 * 3600, "project_type"),         // "online" lies for hours: kept
            runner(4, "a1b2c3-kiln-1-3", "online", day + 11 * 60, "project_type"),    // older than any job could run
            runner(5, "a1b2c3-kiln-1-4", "paused", day + 11 * 60, "project_type"),    // crashed after pause
            runner(6, "ffffff-kiln-1-0", "never_contacted", 3 * day, "project_type"), // another install
            runner(7, "a1b2c3-kiln-1-5", "never_contacted", 3 * day, "group_type"),   // not a project runner
            runner(8, "my-own-runner", "online", 30 * day, "project_type"),
            runner(9, "a1b2c3-kiln-1-6", "never_contacted", 3 * day, "project_type"), // registered by this process
        ];
        let m = Mock::start().await;
        let path = |p: usize| format!("projects/1/runners?type=project_type&per_page=5&page={p}");
        m.route(&path(1), 200, vec![], serde_json::to_string(&list[..5]).unwrap());
        m.route(&path(2), 200, vec![], serde_json::to_string(&list[5..]).unwrap());
        for id in [1, 4, 5] {
            m.on("DELETE", &format!("runners/{id}"), 204, String::new());
        }
        let g = gl_ready("sweep", &m);
        g.mine.lock().unwrap().insert(9);
        assert_eq!(g.sweep(&repo()).await.unwrap(), 3);
        let deleted: Vec<_> = m.calls().into_iter().filter(|c| c.starts_with("DELETE")).collect();
        assert_eq!(deleted, ["DELETE runners/1", "DELETE runners/4", "DELETE runners/5"]);
        assert!(m.requests().iter().all(|r| !r.contains("status=")), "status is never a filter");
        // A refused delete stops the sweep with an error.
        m.on("DELETE", "runners/4", 403, fx("err_403_scope.json"));
        assert!(g.sweep(&repo()).await.is_err());
    }

    #[tokio::test]
    async fn the_doctor_names_a_missing_scope_and_a_low_role() {
        let m = Mock::start().await;
        m.ok("version", "version.json");
        m.ok("personal_access_tokens/self", "pat_self.json");
        m.ok("projects/acme%2Fdemo", "project.json");
        let g = gl_ready("doc", &m);
        let all = |v: &[(String, bool, String)]| v.iter().all(|c| c.1);
        let out = g.doctor(&[repo()]).await;
        assert!(all(&out) && out.len() == 3, "{out:?}");
        assert!(out[0].2.contains("19.4.1") && out[1].2.contains("2027-10-11"));
        let mut pat: Value = serde_json::from_str(&fx("pat_self.json")).unwrap();
        pat["scopes"] = json!(["read_api"]);
        m.route("personal_access_tokens/self", 200, vec![], pat.to_string());
        let out = g.doctor(&[repo()]).await;
        assert!(!out[1].1 && out[1].2.contains("create_runner, manage_runner"), "{out:?}");
        let mut p: Value = serde_json::from_str(&fx("project.json")).unwrap();
        p["permissions"]["project_access"]["access_level"] = 30.into();
        m.route("projects/acme%2Fdemo", 200, vec![], p.to_string());
        let out = g.doctor(&[repo()]).await;
        let d = &out[2].2;
        assert!(!out[2].1 && d.contains("below Maintainer") && d.contains("valid_runner_registrars") && d.contains("toggle"), "{d}");
        assert!(out.iter().all(|c| !c.2.contains(TOKEN)));
    }

    // ---- GL-4: verdict facts, cache trust, dashboard API ----

    use super::super::{Call, Verdict, gate};

    fn serve_job(m: &Mock, j: &Value) {
        m.route(&format!("projects/1/jobs/{}", j["id"]), 200, vec![], j.to_string());
    }

    fn protected_branch(m: &Mock, name: &str) {
        m.route(
            &format!("projects/1/repository/branches/{name}"),
            200,
            vec![],
            fx("branch_ci.json").replace("\"protected\": false", "\"protected\": true"),
        );
    }

    /// The lookups every trust test needs: project, MRs, branches (`prot` is protected, `feat` is not).
    fn serve_trust(m: &Mock) {
        serve_lookups(m);
        m.ok("projects/1/repository/branches/main", "branch_ci.json");
        protected_branch(m, "prot");
    }

    /// The whole host path for a job: `gate` with GitLab's pause answer (the job it holds) and `verdict_facts`.
    async fn gated(g: &GitLab, job: &str, held: &[&str]) -> Verdict {
        let held = Some(held.iter().map(|s| s.to_string()).collect());
        gate(job, std::time::Duration::from_secs(5), async { Ok(held) }, g.verdict_facts(&repo(), job)).await
    }

    fn with(n: u64, r: &str, source: &str, f: impl FnOnce(&mut Value)) -> Value {
        job(n, |j| {
            set(j, r, source);
            j["status"] = "success".into();
            f(j)
        })
    }

    async fn trust(g: &GitLab, j: &Value, writers: &[&str]) -> Result<(String, String, String, String)> {
        let id = j["id"].to_string();
        g.cache_trust(&JobRef { repo: repo(), id }, &writers.iter().map(|w| w.to_string()).collect::<Vec<_>>()).await
    }

    #[tokio::test]
    async fn every_decide_case_against_the_api() {
        let m = Mock::start().await;
        serve_trust(&m);
        m.route("projects/1/merge_requests/7", 500, vec![], "{}".into());
        m.route("projects/1/merge_requests/9", 404, vec![], fx("mr_404.json"));
        let other = |j: &mut Value| j["pipeline"]["project_id"] = 2.into();
        let cases: Vec<(&str, Value, Call)> = vec![
            ("push to the default branch", with(1, "main", "push", |_| {}), Call::Ok),
            ("push to a protected branch", with(2, "prot", "push", |_| {}), Call::Ok),
            ("tag", with(3, "v1", "push", |j| j["tag"] = true.into()), Call::Cold),
            ("MR from a fork", with(4, "refs/merge-requests/3/head", "merge_request_event", |_| {}), Call::Refuse),
            ("same-project MR", with(5, "refs/merge-requests/2/head", "merge_request_event", |_| {}), Call::Ok),
            ("source pipeline", with(6, "ci", "pipeline", |_| {}), Call::Ok),
            ("child of a fork MR", with(7, "refs/merge-requests/3/head", "parent_pipeline", |_| {}), Call::Refuse),
            ("unknown source", with(8, "ci", "external_pull_request_event", |_| {}), Call::Refuse),
            ("no source", with(9, "ci", "push", |j| j["pipeline"]["source"] = Value::Null), Call::Refuse),
            ("MR lookup fails", with(10, "refs/merge-requests/7/head", "merge_request_event", |_| {}), Call::Refuse),
            ("MR not found", with(11, "refs/merge-requests/9/head", "merge_request_event", |_| {}), Call::Refuse),
            ("branch deleted", with(12, "gone", "push", |_| {}), Call::Refuse),
            ("pipeline of another project", with(13, "main", "push", other), Call::Refuse),
            ("no pipeline project", with(14, "main", "push", |j| j["pipeline"]["project_id"] = Value::Null), Call::Refuse),
            ("tag from the web", with(15, "v1", "web", |j| j["tag"] = true.into()), Call::Cold),
        ];
        m.route("projects/1/repository/branches/gone", 404, vec![], fx("branch_404.json"));
        let g = gl("decide", &m);
        for (name, j, want) in &cases {
            serve_job(&m, j);
            let id = j["id"].to_string();
            assert_eq!(gated(&g, &id, &[&id]).await.v, *want, "{name}");
        }
        // API errors and unreadable jobs refuse, with the reason.
        m.route("projects/1/jobs/500", 500, vec![], "{}".into());
        let v = gated(&g, "500", &["500"]).await;
        assert_eq!((v.v, v.why.contains("API error")), (Call::Refuse, true), "{}", v.why);
        assert_eq!(gated(&g, "404", &["404"]).await.v, Call::Refuse, "no such job");
        // A job answered under another id than asked is no answer.
        let mut wrong = with(16, "main", "push", |_| {});
        m.route("projects/1/jobs/1016", 200, vec![], {
            wrong["id"] = 77.into();
            wrong.to_string()
        });
        assert_eq!(gated(&g, "1016", &["1016"]).await.v, Call::Refuse);
        // Not digits: nothing is asked of GitLab.
        let before = m.requests().len();
        assert_eq!(gated(&g, "1/../2", &["1/../2"]).await.v, Call::Refuse);
        assert_eq!(g.verdict_facts(&repo(), "1/../2").await.err().unwrap().to_string(), "bad job id");
        assert_eq!(m.requests().len(), before);
    }

    #[tokio::test]
    async fn the_verdict_is_about_the_job_the_paused_runner_holds() {
        let m = Mock::start().await;
        serve_trust(&m);
        let j = with(1, "main", "push", |_| {});
        serve_job(&m, &j);
        let g = gl("held", &m);
        assert_eq!(gated(&g, "1001", &["1001"]).await.v, Call::Ok);
        for held in [&[][..], &["1002"], &["1001", "1002"]] {
            let v = gated(&g, "1001", held).await;
            assert_eq!(v.v, Call::Refuse, "{held:?}");
        }
        // The real pause against the runner's job list: one job, and it is the console's.
        let m = Mock::start().await;
        m.on("PUT", "runners/79", 200, fx("runner_paused.json"));
        m.ok("runners/79/jobs?status=running", "runner_jobs_running.json");
        serve_trust(&m);
        let mut ours = with(1, "main", "push", |_| {});
        ours["id"] = 251.into();
        serve_job(&m, &ours);
        let mut g = gl("held2", &m);
        g.settle = std::time::Duration::ZERO;
        let v =
            gate("251", std::time::Duration::from_secs(5), async { Ok(Some(g.pause(79).await?)) }, g.verdict_facts(&repo(), "251")).await;
        assert_eq!(v.v, Call::Ok, "{}", v.why);
        let v =
            gate("250", std::time::Duration::from_secs(5), async { Ok(Some(g.pause(79).await?)) }, g.verdict_facts(&repo(), "250")).await;
        assert_eq!(v.v, Call::Refuse, "the runner holds 251, not 250");
    }

    /// A fork's `.gitlab-ci.yml` (and a `trigger:` child's) sets every `CI_*` it can to look like a
    /// trusted push. The recorded jobs carry those claims in every place a reader might look; the
    /// verdict comes from the API's pipeline source, ref and MR lookup alone.
    #[tokio::test]
    async fn spoofed_ci_variables_cannot_turn_a_fork_into_a_trusted_job() {
        let m = Mock::start().await;
        serve_trust(&m);
        let mut g = gl("spoof", &m);
        g.poll = std::time::Duration::ZERO;
        for name in ["job_spoof_mr.json", "job_spoof_child.json"] {
            let raw = fx(name);
            for claim in ["CI_COMMIT_REF_PROTECTED", "CI_PIPELINE_SOURCE", "CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "CI_COMMIT_TAG"] {
                assert!(raw.contains(claim), "{name} must carry {claim}");
            }
            let j: Value = serde_json::from_str(&raw).unwrap();
            m.route(&format!("projects/1/jobs/{}", j["id"]), 200, vec![], raw);
            let id = j["id"].to_string();
            let f = g.verdict_facts(&repo(), &id).await.unwrap();
            assert!(f.ours && f.fork && !f.tag && !f.unknown_source, "{name}: {f:?}");
            let v = gated(&g, &id, &[&id]).await;
            assert_eq!((v.v, v.why.as_str()), (Call::Refuse, "pull request from a fork"), "{name}");
            // And it is no cache writer either, whatever it claims.
            let t = g.cache_trust(&JobRef { repo: repo(), id }, &[]).await.unwrap();
            assert_eq!(t.0, "fork", "{name}");
        }
        // The same job with its MR pointing at this project is trusted: the API data decided, not the claims.
        m.ok("projects/1/merge_requests/3", "mr_same.json");
        let g = gl("spoof2", &m);
        let v = gated(&g, "245", &["245"]).await;
        assert_eq!(v.v, Call::Ok);
    }

    #[tokio::test]
    async fn cache_trust_is_the_job_that_ran() {
        let m = Mock::start().await;
        serve_trust(&m);
        let mut g = gl("trust", &m);
        g.poll = std::time::Duration::ZERO;
        let t = |event: &str, branch: &str, c: &str| (event.to_string(), branch.to_string(), "main".to_string(), c.to_string());
        type Trust = (String, String, String, String);
        let cases: Vec<(&str, Value, &[&str], Trust)> = vec![
            ("push to the default branch", with(1, "main", "push", |_| {}), &[], t("push", "main", "success")),
            ("failed", with(2, "main", "push", |j| j["status"] = "failed".into()), &[], t("push", "main", "failed")),
            ("canceled", with(3, "main", "push", |j| j["status"] = "canceled".into()), &[], t("push", "main", "canceled")),
            ("protected writer branch", with(4, "prot", "push", |_| {}), &["prot"], t("push", "prot", "success")),
            ("unprotected writer branch", with(5, "feat", "push", |_| {}), &["feat"], t("push", "feat (not protected)", "success")),
            ("branch that is no writer", with(6, "feat", "push", |_| {}), &[], t("push", "feat", "success")),
            ("tag", with(7, "v1", "push", |j| j["tag"] = true.into()), &[], t("tag", "v1", "success")),
            (
                "same-project MR",
                with(8, "refs/merge-requests/2/head", "merge_request_event", |_| {}),
                &[],
                t("merge_request_event", "feat", "success"),
            ),
            (
                "fork MR",
                with(9, "refs/merge-requests/3/head", "merge_request_event", |_| {}),
                &[],
                t("fork", "refs/merge-requests/3/head", "success"),
            ),
            ("source pipeline", with(10, "main", "pipeline", |_| {}), &[], t("pipeline", "main", "success")),
            ("web", with(11, "main", "web", |_| {}), &[], t("web", "main", "success")),
            ("schedule", with(12, "main", "schedule", |_| {}), &[], t("schedule", "main", "success")),
        ];
        for (name, j, writers, want) in &cases {
            serve_job(&m, j);
            assert_eq!(&trust(&g, j, writers).await.unwrap(), want, "{name}");
        }
        // The default branch is read once, not per job.
        assert_eq!(m.count("projects/acme%2Fdemo"), 2, "project id once, default branch once");
        // A branch name no branch can have is marked, and a writer entry cannot rescue it.
        let odd = with(20, "a..b", "push", |_| {});
        m.ok("projects/1/repository/branches/a..b", "branch_ci.json");
        serve_job(&m, &odd);
        assert_eq!(trust(&g, &odd, &["a..b"]).await.unwrap().1, "a..b (not a plain branch name)");
    }

    #[tokio::test]
    async fn cache_trust_waits_for_the_result_and_fails_closed() {
        let m = Mock::start().await;
        serve_trust(&m);
        let mut g = gl("trustwait", &m);
        g.poll = std::time::Duration::ZERO;
        let running = with(1, "main", "push", |j| j["status"] = "running".into());
        serve_job(&m, &running);
        let t = trust(&g, &running, &[]).await.unwrap();
        assert_eq!(t.3, "running", "never success while unfinished");
        assert_eq!(m.count("projects/1/jobs/1001"), TRUST_LOOKS);
        // Another project's job, an unreadable job and a failed lookup are errors, not trust.
        let other = with(2, "main", "push", |j| j["pipeline"]["project_id"] = 2.into());
        serve_job(&m, &other);
        assert!(trust(&g, &other, &[]).await.unwrap_err().to_string().contains("not for"));
        m.route("projects/1/jobs/1003", 500, vec![], "{}".into());
        assert!(g.cache_trust(&JobRef { repo: repo(), id: "1003".into() }, &[]).await.is_err());
        m.route("projects/1/merge_requests/7", 500, vec![], "{}".into());
        let mr = with(4, "refs/merge-requests/7/head", "merge_request_event", |_| {});
        serve_job(&m, &mr);
        assert!(trust(&g, &mr, &[]).await.is_err());
        let b = with(5, "feat", "push", |_| {});
        serve_job(&m, &b);
        m.route("projects/1/repository/branches/feat", 500, vec![], "{}".into());
        assert!(trust(&g, &b, &["feat"]).await.is_err(), "protected lookup failed");
    }

    #[tokio::test]
    async fn runs_list_pipelines_with_server_built_links() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        m.route(
            "projects/1/pipelines?per_page=30&page=1&scope=finished&ref=main",
            200,
            fx_headers("pipelines.headers"),
            fx("pipelines.json"),
        );
        let g = gl("runs", &m);
        let q = RunQuery { status: Some("completed".into()), branch: Some("main".into()), page: 0 };
        let p = g.runs(&repo(), &q).await.unwrap();
        assert_eq!(p.next, Some(2));
        let r = &p.runs;
        assert_eq!(r.len(), 5);
        assert_eq!((r[0].id, r[0].number, r[0].status, r[0].outcome, r[0].event), (127, 116, RunStatus::Running, None, EventKind::Push));
        let b = format!("{}/acme/demo/-/", m.base);
        assert_eq!(r[0].links.run.as_deref(), Some(format!("{b}pipelines/127").as_str()));
        assert_eq!(r[0].links.branch.as_deref(), Some(format!("{b}tree/long").as_str()));
        assert_eq!(r[0].links.commit.as_deref(), Some(format!("{b}commit/{}", r[0].sha).as_str()));
        assert_eq!((r[1].event, r[1].outcome, r[1].links.branch.clone()), (EventKind::PullRequest, Some(Outcome::Succeeded), None));
        assert_eq!(r[1].links.pr.as_deref(), Some(format!("{b}merge_requests/2").as_str()));
        assert_eq!((r[2].outcome, r[2].name.as_str(), r[2].title.as_str()), (Some(Outcome::Failed), "nightly", "nightly"));
        assert_eq!((r[0].name.as_str(), r[0].title.as_str()), ("pipeline", ""));
        // A ref or sha that is not plain text gets no link; kiln builds links, GitLab's web_url is never used.
        assert_eq!(
            (r[3].status, r[3].event, r[3].links.branch.clone(), r[3].links.commit.clone()),
            (RunStatus::Queued, EventKind::Manual, None, None)
        );
        assert!(r[3].links.run.is_some());
        assert_eq!((r[4].status, r[4].outcome), (RunStatus::Running, None), "canceling is not finished");
        assert!(g.runs(&repo(), &RunQuery { status: Some("odd".into()), ..Default::default() }).await.is_err());
        // The last page has no X-Next-Page.
        m.route("projects/1/pipelines?per_page=30&page=1", 200, vec![], "[]".into());
        assert_eq!(g.runs(&repo(), &Default::default()).await.unwrap().next, None);
        m.route("projects/1/pipelines?per_page=30&page=1&scope=pending", 500, vec![], "{}".into());
        assert!(g.runs(&repo(), &RunQuery { status: Some("queued".into()), ..Default::default() }).await.is_err());
    }

    #[tokio::test]
    async fn a_run_has_its_jobs_and_its_commit_title() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        m.ok("projects/1/pipelines/127", "pipeline_127.json");
        m.ok("projects/1/pipelines/127/jobs?per_page=100", "pipeline_127_jobs.json");
        let g = gl("run", &m);
        let d = g.run(&repo(), 127).await.unwrap();
        assert_eq!((d.run.id, d.run.title.as_str(), d.run.actor.as_deref()), (127, "long ci", Some("root")));
        let jobs: Vec<_> = d.jobs.iter().map(|j| (j.id, j.status, j.outcome, j.runner.as_deref())).collect();
        assert_eq!(
            jobs,
            [
                (251, RunStatus::Running, None, Some("a1b2c3-kiln-7-0")),
                (252, RunStatus::Completed, Some(Outcome::Failed), None),
                (253, RunStatus::Queued, None, None)
            ]
        );
        assert_eq!(d.jobs[0].links.job.as_deref(), Some(format!("{}/acme/demo/-/jobs/251", m.base).as_str()));
        assert!(d.jobs[0].steps.is_empty());
        // Another pipeline's answer under the asked id is no answer.
        m.ok("projects/1/pipelines/128", "pipeline_127.json");
        assert!(g.run(&repo(), 128).await.is_err());
        assert!(g.run(&repo(), 999).await.is_err());
    }

    fn with_status(id: u64, status: &str) -> String {
        let mut j = recorded_jobs().into_iter().find(|j| j["id"] == id).unwrap();
        j["status"] = status.into();
        j.to_string()
    }

    #[tokio::test]
    async fn the_trace_is_capped_paged_and_complete_only_when_the_job_is_over() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        let trace = fx("trace_251.txt");
        m.route("projects/1/jobs/251/trace", 200, vec![], trace.clone());
        let g = gl("trace", &m);
        // The job is still running: the whole trace comes back but is not final.
        m.route("projects/1/jobs/251", 200, vec![], with_status(251, "running"));
        let p = g.job_log(&repo(), 251, 0).await.unwrap();
        assert_eq!((p.text.as_str(), p.next, p.complete, p.truncated), (trace.as_str(), trace.len(), false, false));
        assert!(p.text.contains("section_start:") && p.text.contains('\u{1b}'), "markers and ANSI are kept");
        m.route("projects/1/jobs/251", 200, vec![], with_status(251, "success"));
        assert!(g.job_log(&repo(), 251, 0).await.unwrap().complete);
        // From an offset, and past the end.
        let p = g.job_log(&repo(), 251, 10).await.unwrap();
        assert_eq!(p.text, trace[10..]);
        assert_eq!(g.job_log(&repo(), 251, 1 << 30).await.unwrap().text, "");
        // A big trace is paged at LOG_CAP.
        let big = "x".repeat(super::super::LOG_CAP + 10);
        m.route("projects/1/jobs/251/trace", 200, vec![], big);
        let p = g.job_log(&repo(), 251, 0).await.unwrap();
        assert_eq!((p.text.len(), p.next, p.complete), (super::super::LOG_CAP, super::super::LOG_CAP, false));
        m.route("projects/1/jobs/251/trace", 404, vec![], "{}".into());
        assert!(g.job_log(&repo(), 251, 0).await.unwrap_err().to_string().contains("404"));
    }

    #[tokio::test]
    async fn rerun_cancel_and_run_pipeline_map_to_gitlab_and_say_when_the_scope_is_short() {
        let m = Mock::start().await;
        m.ok("projects/acme%2Fdemo", "project.json");
        m.on("POST", "projects/1/pipelines/127/retry", 201, "{}".into());
        m.on("POST", "projects/1/pipelines/127/cancel", 200, "{}".into());
        m.on("POST", "projects/1/pipeline", 201, "{}".into());
        let g = gl("acts", &m);
        g.rerun(&repo(), 127, false).await.unwrap();
        g.rerun(&repo(), 127, true).await.unwrap();
        g.cancel(&repo(), 127).await.unwrap();
        g.dispatch(&repo(), None, "main", &HashMap::new()).await.unwrap();
        g.dispatch(&repo(), Some("ignored.yml"), "feat/x", &HashMap::new()).await.unwrap();
        let sent = m.sent.lock().unwrap().clone();
        let posts: Vec<_> =
            sent.iter().filter(|(c, _)| c.starts_with("POST")).map(|(c, b)| (c.replace("/api/v4/", ""), b.clone())).collect();
        assert_eq!(posts[0].0, "POST projects/1/pipelines/127/retry");
        assert_eq!(posts[2].0, "POST projects/1/pipelines/127/cancel");
        assert_eq!(serde_json::from_str::<Value>(&posts[3].1).unwrap(), json!({"ref": "main"}));
        assert_eq!(serde_json::from_str::<Value>(&posts[4].1).unwrap(), json!({"ref": "feat/x"}), "no variables, whatever was asked");
        assert_eq!(posts.len(), 5);
        // No variables in v1: refused before anything is sent.
        let inputs = HashMap::from([("A".to_string(), "1".to_string())]);
        assert!(g.dispatch(&repo(), None, "main", &inputs).await.unwrap_err().to_string().contains("variables"));
        assert_eq!(m.sent.lock().unwrap().iter().filter(|(c, _)| c.starts_with("POST")).count(), 5);
        // A token without `api` is told so; GitLab's own refusal text is shown.
        m.on("POST", "projects/1/pipelines/127/retry", 403, fx("err_403_scope.json"));
        assert!(g.rerun(&repo(), 127, false).await.unwrap_err().to_string().contains("api scope"));
        m.on("POST", "projects/1/pipeline", 400, r#"{"message":{"base":["Reference not found"]}}"#.into());
        let e = g.dispatch(&repo(), None, "nope", &HashMap::new()).await.unwrap_err().to_string();
        assert!(e.contains("400") && e.contains("Reference not found"), "{e}");
        m.on("POST", "projects/1/pipelines/9/cancel", 404, r#"{"message":"404 Not found"}"#.into());
        assert!(g.cancel(&repo(), 9).await.is_err());
        assert!(!e.contains(TOKEN));
        assert!(g.workflows(&repo()).await.unwrap().is_empty());
        assert_eq!(CAPS, Caps { rerun: true, rerun_failed: true, cancel: true, dispatch: true, workflows: false, live_steps: false });
    }
}
