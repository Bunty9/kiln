//! The GitLab forge, demand side (GL-2): which of the project's pending jobs are ours, which
//! running jobs belong to our runners, and whether a job's code came from a fork.
//!
//! Registration, retire, sweep, pause and verdict facts arrive with GL-3 and GL-4. Until then
//! they fail closed: `register` refuses, so no VM launches for GitLab demand yet.
//!
//! Everything the API says is data, never instructions: fork detection reads the job's `ref`,
//! `tag` and pipeline `source` plus one MR or branch lookup, never a `CI_*` value (a job's own
//! config can overwrite those). Any doubt is a fork. All HTTP goes through `net.rs` (no
//! redirects, address guard, size cap), and a `Link` URL is only compared, never fetched.

use super::{Caps, Credential, Demand, Dereg, EventKind, ForgeCfg, ForgeId, JobInfo, Links, Network, RepoRef, RunnerReg, net};
use anyhow::{Context, Result, anyhow, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

/// Dashboard actions arrive with GL-4.
pub const CAPS: Caps = Caps { rerun: false, rerun_failed: false, cancel: false, dispatch: false, workflows: false, live_steps: false };
pub const NOT_YET: &str = "not available for GitLab yet";
pub const LATER: &str = "GitLab runners arrive in a later version";
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
    token_env: String,
    /// Empty = none. Never logged or put in an error.
    token: RwLock<String>,
    /// Runner descriptions are `<install>-<vm id>`; ours are the ones with this prefix.
    install: String,
    per_page: usize,
    /// Unix time before which GitLab told us to back off (429), 0 = no.
    paused: Mutex<u64>,
    /// repo path -> numeric project id.
    projects: Mutex<HashMap<String, u64>>,
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
            token_file: data.join("forges").join(format!("{}.token", id.as_str())),
            token_env: env_name(&id),
            token: RwLock::new(String::new()),
            install: install_id(data)?,
            per_page: PER_PAGE,
            paused: Mutex::new(0),
            projects: Mutex::default(),
            origins: Mutex::default(),
            #[cfg(test)]
            unguarded: false,
            id,
        };
        g.refresh();
        Ok(g)
    }

    /// Re-reads the credential (the dashboard writes the file; the environment is fixed).
    pub fn refresh(&self) {
        let t = match self.cred {
            Credential::File => std::fs::read_to_string(&self.token_file).unwrap_or_default(),
            Credential::Env => std::env::var(&self.token_env).unwrap_or_default(),
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
                Credential::Env => format!("no token for GitLab forge {}: export {}", self.id.as_str(), self.token_env),
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

    // The rest waits for GL-3 / GL-4 and refuses.
    pub async fn register(&self, _repo: &RepoRef, _name: &str, _labels: &[String]) -> Result<RunnerReg> {
        bail!(LATER)
    }
    pub async fn deregister(&self, _repo: &RepoRef, _runner_id: u64) -> Dereg {
        Dereg::Err(anyhow!(LATER))
    }
    /// No runner of ours can exist yet, so there is nothing to sweep.
    pub async fn sweep(&self, _repo: &RepoRef) -> Result<usize> {
        Ok(0)
    }

    /// GET `api/v4/<path>`. The token only ever goes to the configured origin.
    async fn get(&self, path: &str) -> Result<Resp> {
        if let Some(t) = self.paused_until() {
            bail!("GitLab rate limit: paused until {t}");
        }
        let mut tok = HeaderValue::from_str(&self.token.read().unwrap()).map_err(|_| anyhow!("the GitLab token has invalid characters"))?;
        if tok.is_empty() {
            bail!("no GitLab token");
        }
        tok.set_sensitive(true);
        let rb = self.client.get(format!("{}/api/v4/{path}", self.url)).header("PRIVATE-TOKEN", tok);
        #[cfg(test)]
        let r = if self.unguarded { self.client.execute(rb.build()?).await? } else { net::send(&self.client, self.mode, rb).await? };
        #[cfg(not(test))]
        let r = net::send(&self.client, self.mode, rb).await?;
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        let body = net::read_capped(r, BODY_CAP).await?;
        if status == 429 {
            let secs = headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
            *self.paused.lock().unwrap() = crate::now() + secs.unwrap_or(60).clamp(1, 3600);
        }
        Ok(Resp { status, headers, body })
    }

    /// An error for a response that was not the one we wanted. GitLab's own message is shown
    /// (it never echoes the credential), cut and stripped of control characters.
    fn fail(&self, what: &str, r: &Resp) -> anyhow::Error {
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let msg: String =
            v["message"].as_str().or(v["error"].as_str()).unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect();
        let why = match (r.status, v["error"].as_str()) {
            (401, _) => "the token was rejected (expired, revoked or wrong)".to_string(),
            (403, Some("insufficient_scope")) => "the token lacks a scope (it needs read_api)".to_string(),
            (429, _) => "rate limited; backing off".to_string(),
            _ => msg,
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
        self.demand_for(repo, label, default_cpus, crate::host_threads()).await
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
        Ok(Demand { by_size, claimed, refused_forks })
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
        let kind = if j["tag"] == true {
            EventKind::Tag
        } else if pr.is_some() || source == "merge_request_event" {
            EventKind::PullRequest
        } else {
            match source.as_str() {
                "push" => EventKind::Push,
                "schedule" => EventKind::Schedule,
                // A multi-project downstream pipeline runs the target's own branch, but the caller's config controls it.
                "web" | "api" | "trigger" | "pipeline" => EventKind::Manual,
                _ => EventKind::Other,
            }
        };
        let branch = mr_branch.filter(|_| pr.is_some()).unwrap_or_else(|| r.clone());
        let base = format!("{}/{}", self.url, repo.path);
        let links = Links {
            run: j["pipeline"]["id"].as_u64().map(|p| format!("{base}/-/pipelines/{p}")),
            job: Some(format!("{base}/-/jobs/{id}")),
            commit: (!sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| format!("{base}/-/commit/{sha}")),
            pr: pr.map(|n| format!("{base}/-/merge_requests/{n}")),
            branch: (pr.is_none() && plain_ref(&r)).then(|| format!("{base}/-/tree/{r}")),
        };
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

/// The tags a runner of `cpus` vCPUs carries: `kiln-Ncpu`, and `kiln` too for the default size.
/// GitLab runs a job only on a runner whose tags include all the job's, so a job is ours exactly
/// when its tags are a subset of one size's set. (GL-3 registers with these.)
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

/// `gl` -> `KILN_FORGE_GL_TOKEN`.
fn env_name(id: &ForgeId) -> String {
    format!("KILN_FORGE_{}_TOKEN", id.as_str().to_ascii_uppercase().replace('-', "_"))
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

    /// A mock GitLab on loopback: `path?query` -> canned status, headers and body. Anything
    /// unrouted is a 404, so a changed request sequence shows up in `requests()`.
    struct Mock {
        base: String,
        routes: Routes,
        log: Log,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        async fn start() -> Mock {
            let (routes, log): (Routes, Log) = Default::default();
            async fn serve(State((routes, log)): State<(Routes, Log)>, req: Request) -> Response {
                let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
                let tok = req.headers().get("private-token").and_then(|v| v.to_str().ok()).map(String::from);
                log.lock().unwrap().push((path.clone(), tok));
                let (status, headers, body) =
                    routes.lock().unwrap().get(&path).cloned().unwrap_or((404, vec![], r#"{"message":"404 Not Found"}"#.into()));
                let mut r = Response::builder().status(status);
                for (k, v) in headers {
                    r = r.header(k, v);
                }
                r.body(Body::from(body)).unwrap()
            }
            let app = Router::new().fallback(serve).with_state((routes.clone(), log.clone()));
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", l.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let _ = axum::serve(l, app).await;
            });
            Mock { base, routes, log, task }
        }

        /// `api/v4/<path>`; the fixtures' placeholder host becomes this mock's origin.
        fn route(&self, path: &str, status: u16, headers: Vec<(String, String)>, body: String) {
            let headers = headers.into_iter().map(|(k, v)| (k, v.replace(SPOOF, &self.base))).collect();
            self.routes.lock().unwrap().insert(format!("/api/v4/{path}"), (status, headers, body.replace(SPOOF, &self.base)));
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
        g.refresh();
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
    async fn registration_and_the_gate_fail_closed_until_the_later_tasks() {
        use super::super::{Dereg, Forge, Kind};
        let gh = Arc::new(crate::github::Gh::new(String::new(), "none"));
        let f = Forge::new(&cfg(SPOOF), &gh, &temp("stubs")).unwrap();
        assert_eq!(f.kind(), Kind::GitLab);
        assert!(f.gated());
        let e = f.register(&repo(), "a1b2c3-kiln-1-0", &["kiln-4cpu".into()]).await.err().unwrap();
        assert!(e.to_string().contains("later version"), "{e:#}");
        assert!(matches!(f.deregister(&repo(), 1).await, Dereg::Err(_)));
        assert!(f.pause(&repo(), 1).await.is_err());
        assert!(f.verdict_facts(&repo(), "1").await.is_err());
        assert_eq!(f.sweep(&repo()).await.unwrap(), 0);
        assert!(f.runs(&repo(), &Default::default()).await.is_err());
        assert_eq!(f.repo_paused(&repo()), None);
        assert!(f.health().unwrap().contains("no token"));
    }
}
