//! Thin GitHub REST client: just the calls the scheduler needs, plus a raw
//! passthrough the dashboard uses for everything else.

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;

pub struct Gh {
    http: reqwest::Client,
    token: std::sync::RwLock<String>,
    /// Where the token came from: "env" | "file" | "gh" | "none".
    source: std::sync::RwLock<&'static str>,
    /// Per auth identity (0 = the token, else the installation id): last seen
    /// (remaining, limit, reset) from x-ratelimit-* headers.
    rates: std::sync::Mutex<BTreeMap<u64, (u64, u64, u64)>>,
    /// Per auth identity: unix time until which GitHub told us to back off.
    paused: std::sync::Mutex<BTreeMap<u64, u64>>,
    /// (latest runner release, don't refetch before this unix time).
    latest: std::sync::Mutex<(Option<String>, u64)>,
    // URL -> (etag, body). Conditional GETs that return 304 are free against
    // the rate limit, which is what makes 5s polling of several repos viable.
    etags: Mutex<HashMap<String, (String, Value)>>,
    /// lowercase "owner/name" -> GitHub's spelling, from App discovery.
    spelled: std::sync::Mutex<HashMap<String, String>>,
    /// GitHub App mode: tokens come from the App's installations, not `token`.
    app: std::sync::RwLock<Option<std::sync::Arc<crate::app_auth::AppAuth>>>,
    /// Config `app_accounts`: installations on these accounts are served besides the owner's.
    pub app_accounts: std::sync::RwLock<Vec<String>>,
    /// Unix time the token expires, from GitHub's response header (None = no expiry seen).
    pub expires: std::sync::Mutex<Option<u64>>,
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
        let http =
            reqwest::Client::builder().user_agent("kiln-ci").timeout(std::time::Duration::from_secs(60)).build().expect("http client");
        Self {
            http,
            token: std::sync::RwLock::new(token),
            source: std::sync::RwLock::new(source),
            rates: Default::default(),
            paused: Default::default(),
            latest: Default::default(),
            etags: Mutex::default(),
            defaults: Default::default(),
            expires: Default::default(),
            app: Default::default(),
            app_accounts: Default::default(),
            spelled: Default::default(),
        }
    }

    pub fn set_token(&self, t: String, source: &'static str) {
        *self.token.write().unwrap() = t;
        *self.source.write().unwrap() = source;
        *self.expires.lock().unwrap() = None;
    }

    pub fn source(&self) -> &'static str {
        if self.app().is_some() { "app" } else { *self.source.read().unwrap() }
    }

    pub fn set_app(&self, a: Option<std::sync::Arc<crate::app_auth::AppAuth>>) {
        *self.app.write().unwrap() = a;
        *self.expires.lock().unwrap() = None;
        // Identities change meaning between token and App mode.
        self.rates.lock().unwrap().clear();
        self.paused.lock().unwrap().clear();
    }

    pub fn app(&self) -> Option<std::sync::Arc<crate::app_auth::AppAuth>> {
        self.app.read().unwrap().clone()
    }

    /// Token mode's pause (App mode pauses per installation: see `repo_paused`).
    pub fn paused_until(&self) -> Option<u64> {
        self.paused_of(0)
    }

    fn paused_of(&self, who: u64) -> Option<u64> {
        self.paused.lock().unwrap().get(&who).copied().filter(|&t| t > crate::now())
    }

    fn pause(&self, who: u64, t: u64) {
        if !billed(self.app().is_some(), who) {
            return;
        }
        let mut p = self.paused.lock().unwrap();
        let e = p.entry(who).or_default();
        *e = (*e).max(t);
    }

    /// App mode: why `repo` must not be polled now (its installation is paused).
    pub fn repo_paused(&self, repo: &str) -> Option<String> {
        let a = self.app()?;
        let inst = crate::app_auth::install_for(&format!("repos/{repo}"), &a.repos.read().unwrap())?;
        self.paused_of(inst).map(|t| paused_msg(repo, t))
    }

    /// The most constrained identity's (remaining, limit, reset).
    pub fn rate(&self) -> Option<(u64, u64, u64)> {
        tightest(&self.rates.lock().unwrap(), crate::now())
    }

    pub fn rates(&self) -> BTreeMap<u64, (u64, u64, u64)> {
        live(&self.rates.lock().unwrap(), crate::now())
    }

    pub fn has_token(&self) -> bool {
        self.app().is_some() || !self.token.read().unwrap().is_empty()
    }

    /// Bearer for `path` ("" = unauthenticated): the PAT, or in App mode the serving
    /// installation's token. A repo the App does not serve is an error, except the public
    /// runner release lookup, which goes unauthenticated so a bake works before any
    /// installation exists. Other paths use any installation, or none if there is none.
    /// The App JWT is never handed out here: only `mint`, `discover` and `app_info` use it.
    /// `anon_unserved`: an unserved repo goes unauthenticated instead (update releases).
    /// Also returns the identity the rate limit is tracked under (0 = the token, or none).
    async fn token_for(&self, path: &str, anon_unserved: bool) -> Result<(String, u64)> {
        let Some(a) = self.app() else { return Ok((self.token.read().unwrap().clone(), 0)) };
        if crate::app_auth::is_public(path) {
            return Ok((String::new(), 0));
        }
        // CLI commands (bake, doctor) never ran the scheduler's discovery.
        let found = if a.discovered_at.load(Ordering::Relaxed) == 0 { self.discover().await.map(|_| ()) } else { Ok(()) };
        let inst = crate::app_auth::install_for(path, &a.repos.read().unwrap());
        match (inst, crate::app_auth::repo_of(path)) {
            (Some(i), Some(_)) => Ok((self.mint(&a, i).await?, i)),
            (None, Some(_)) if anon_unserved => Ok((String::new(), 0)),
            (None, Some(r)) => {
                found?;
                bail!(
                    "repo {r} is not served by the GitHub App: install the App on it (an account other than the App owner's must be in app_accounts)"
                )
            }
            // A failed mint goes out unauthenticated: the anonymous budget, not the installation's.
            (Some(i), None) => Ok(self.mint(&a, i).await.map_or((String::new(), 0), |t| (t, i))),
            (None, None) => Ok((String::new(), 0)),
        }
    }

    /// Cached installation token, minted when missing or within 5 min of expiry.
    async fn mint(&self, a: &crate::app_auth::AppAuth, inst: u64) -> Result<String> {
        let mut tokens = a.tokens.lock().await;
        if let Some(t) = a.cached(&mut tokens, inst, crate::now()) {
            return Ok(t);
        }
        let jwt = a.jwt(crate::now())?;
        let r = self.request_with(&jwt, Method::POST, &format!("app/installations/{inst}/access_tokens")).send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("minting an installation token: {status} {}", v["message"].as_str().unwrap_or(""));
        }
        let t = v["token"].as_str().context("no token in response")?.to_string();
        let exp = v["expires_at"].as_str().and_then(parse_rfc3339).context("no expires_at")?;
        tokens.insert(inst, (t.clone(), exp));
        Ok(t)
    }

    /// The request and the identity to pass to `exec`.
    async fn request(&self, method: Method, path: &str) -> Result<(reqwest::RequestBuilder, u64)> {
        let (t, who) = self.token_for(path, false).await?;
        Ok((self.request_with(&t, method, path), who))
    }

    /// GET from the update repo's releases (update.rs): the token, or in App mode the serving
    /// installation's, else unauthenticated (a public repo). `asset` downloads a release asset
    /// (follows the redirect to blob storage, which gets no auth header).
    pub async fn release(&self, path: &str, asset: bool) -> Result<reqwest::Response> {
        let (t, who) = self.token_for(path, true).await?;
        let mut req = self.request_with(&t, Method::GET, path).build()?;
        if asset {
            req.headers_mut().insert(header::ACCEPT, header::HeaderValue::from_static("application/octet-stream"));
            *req.timeout_mut() = Some(std::time::Duration::from_secs(600));
        }
        self.exec(reqwest::RequestBuilder::from_parts(self.http.clone(), req), who).await
    }

    fn request_with(&self, token: &str, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("https://api.github.com/{}", path.trim_start_matches('/'));
        let rb = self
            .http
            .request(method, url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        // "" = unauthenticated (public reads in App mode; no token at all in token mode).
        if token.is_empty() { rb } else { rb.bearer_auth(token) }
    }

    /// Every call goes through here so the rate-limit state of `who` (from `token_for`) stays current.
    async fn exec(&self, rb: reqwest::RequestBuilder, who: u64) -> Result<reqwest::Response> {
        let r = rb.send().await?;
        let num = |k: &str| r.headers().get(k).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        let (remaining, reset) = (num("x-ratelimit-remaining"), num("x-ratelimit-reset"));
        // An unauthenticated call (the App's runner-release lookup, or any call whose mint
        // failed) spends the per-IP anonymous budget, not ours: it must neither show as our
        // rate nor pause polling.
        let ours = !anonymous_budget(num("x-ratelimit-limit")) && billed(self.app().is_some(), who);
        if ours && let (Some(rem), Some(lim), Some(reset)) = (remaining, num("x-ratelimit-limit"), reset) {
            self.rates.lock().unwrap().insert(who, (rem, lim, reset));
        }
        // "2026-11-01 00:00:00 UTC": fine-grained tokens, and classic ones with an expiry.
        // Every successful API response says it, so a rotated token without one clears it.
        // Not a redirected log download: blob storage never sends it.
        if r.status().is_success() && r.url().host_str() == Some("api.github.com") && self.app().is_none() {
            *self.expires.lock().unwrap() =
                r.headers().get("github-authentication-token-expiration").and_then(|v| v.to_str().ok()).and_then(parse_rfc3339);
        }
        if r.status() == StatusCode::UNAUTHORIZED
            && let Some(a) = self.app()
        {
            // Not a try_lock clear: that is lost whenever a mint holds the lock.
            a.mark_stale();
        }
        if ours && let Some(t) = pause_until(r.status().as_u16(), remaining, reset, num("retry-after"), crate::now()) {
            self.pause(who, t);
        }
        Ok(r)
    }

    /// Secondary limits come as a 403 whose only marker is the body text.
    fn note_body(&self, who: u64, status: u16, body: &str) {
        if secondary_limit(status, body) {
            self.pause(who, crate::now() + 60);
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
        let (mut rb, who) = self.request(method, path).await?;
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = self.exec(rb, who).await?;
        let status = r.status().as_u16();
        let content_type = r.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/json").to_string();
        let body = r.bytes().await?;
        self.note_body(who, status, &String::from_utf8_lossy(&body));
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
        let (mut rb, who) = self.request(Method::GET, path).await?;
        if let Some((etag, _)) = &cached {
            rb = rb.header(header::IF_NONE_MATCH, etag);
        }
        let r = self.exec(rb, who).await?;
        if r.status() == StatusCode::NOT_MODIFIED
            && let Some((_, v)) = cached
        {
            return Ok(v);
        }
        if !r.status().is_success() {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            self.note_body(who, status.as_u16(), &body);
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
        let (rb, who) = self.request(method.clone(), path).await?;
        let r = self.exec(rb.json(&body), who).await?;
        if !r.status().is_success() {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            self.note_body(who, status.as_u16(), &body);
            bail!("{method} {path}: {status} {body}");
        }
        Ok(r.json().await.unwrap_or(Value::Null))
    }

    /// (event, head branch, default branch, job conclusion) of the run behind a job, to
    /// decide whether its cache may be committed. The conclusion is GitHub's, not the console's.
    /// `writers` are the extra cache-writer branches besides the default.
    pub async fn cache_trust(&self, repo: &str, job: u64, writers: &[String]) -> Result<(String, String, String, String)> {
        // The VM powers off a moment before GitHub records the job's conclusion;
        // without waiting, trusted saves on a writer branch would be lost to the race.
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
        // A pushed *tag* arrives as event=push with head_branch = the tag's name, so a
        // tag named like a writer branch looks like a push to it. Only trust the run
        // if the commit is really on that branch (identical to it or an ancestor of it).
        if event == "push" && (branch == default || writers.contains(&branch)) {
            if let Some(marked) = unsafe_branch(&branch) {
                return Ok((event, marked, default, conclusion));
            }
            let sha = run["head_sha"].as_str().context("run has no head_sha")?;
            // Resolve the branch tip through refs/heads explicitly: a bare name in
            // compare/ may resolve to a same-named tag, which anyone who can push a
            // tag controls.
            let tip = self.get(&format!("repos/{repo}/git/ref/heads/{branch}")).await?;
            let tip = tip["object"]["sha"].as_str().context("branch ref has no sha")?;
            let cmp = self.get(&format!("repos/{repo}/compare/{tip}...{sha}")).await?;
            if !matches!(cmp["status"].as_str(), Some("identical" | "behind")) {
                return Ok((event, format!("{branch} (commit {:.7} not on {branch})", sha), default, conclusion));
            }
        }
        Ok((event, branch, default, conclusion))
    }

    /// Queued jobs per VM size (see `job_size`), counted once per job id.
    /// Sizes above the host's CPU count are not ours and not counted.
    /// Also returns, for jobs picked up by one of our runners (`kiln-*`),
    /// runner name -> (job page, queued-at unix time, from a fork), and the
    /// number of queued fork jobs refused (never counted as demand).
    pub async fn queued_jobs(
        &self,
        repo: &str,
        label: &str,
        default_cpus: u32,
    ) -> Result<(HashMap<u32, usize>, HashMap<String, (String, u64, bool)>, usize)> {
        let host = crate::host_threads();
        let mut queued: HashMap<u64, u32> = HashMap::new();
        let mut forks = std::collections::HashSet::new();
        let mut ours = HashMap::new();
        // A run is "in_progress" while later jobs of it still wait in the queue,
        // so both statuses have to be scanned.
        for status in ["queued", "in_progress"] {
            let runs = self.get(&format!("repos/{repo}/actions/runs?status={status}&per_page=30")).await?;
            for run in runs["workflow_runs"].as_array().into_iter().flatten() {
                let id = run["id"].as_u64().context("run id")?;
                let fork = is_fork_run(run);
                let jobs = self.get(&format!("repos/{repo}/actions/runs/{id}/jobs?per_page=100")).await?;
                for j in jobs["jobs"].as_array().into_iter().flatten() {
                    if j["status"] == "queued"
                        && let Some(n) = job_size(&j["labels"], label, default_cpus, crate::host::ARM64).filter(|&n| n <= host)
                    {
                        let jid = j["id"].as_u64().unwrap_or_default();
                        if fork {
                            forks.insert(jid);
                        } else {
                            queued.insert(jid, n);
                        }
                    }
                    if let Some(name) = j["runner_name"].as_str().filter(|n| n.starts_with("kiln-"))
                        && let Some(url) = j["html_url"].as_str()
                        && let Some(at) = j["created_at"].as_str().and_then(parse_rfc3339)
                    {
                        ours.insert(name.to_string(), (url.to_string(), at, fork));
                    }
                }
            }
        }
        let mut by_size = HashMap::new();
        for n in queued.into_values() {
            *by_size.entry(n).or_default() += 1;
        }
        Ok((by_size, ours, forks.len()))
    }

    /// Exchange a manifest-flow code for the new App's id, slug, html_url, owner and pem (no auth).
    pub async fn manifest_conversion(&self, code: &str) -> Result<Value> {
        let r = self
            .http
            .post(format!("https://api.github.com/app-manifests/{code}/conversions"))
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("could not reach GitHub to finish the setup: try again (the setup code stays usable for an hour)")?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("{}", conversion_error(status.as_u16()));
        }
        Ok(v)
    }

    /// GET /app with this App's JWT: proves the id and key belong together.
    pub async fn app_info(&self, a: &crate::app_auth::AppAuth) -> Result<Value> {
        let r = self.request_with(&a.jwt(crate::now())?, Method::GET, "app").send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("GitHub rejected the App id or key: {status} {}", v["message"].as_str().unwrap_or(""));
        }
        Ok(v)
    }

    /// App mode: map every repo of every installation to its installation id, reusing
    /// a discovery that finished in the last 60 s (doctor, CLI commands).
    pub async fn discover(&self) -> Result<usize> {
        self.discover_since(crate::now().saturating_sub(60)).await
    }

    /// Discover now (scheduler, dashboard Refresh). A caller that waited for a discovery
    /// already running takes its result instead of starting another.
    pub async fn discover_now(&self) -> Result<usize> {
        self.discover_since(crate::now()).await
    }

    /// Leaves the previous map in place on any error.
    async fn discover_since(&self, since: u64) -> Result<usize> {
        let a = self.app().context("not in GitHub App mode")?;
        let mut last = a.discovery.lock().await;
        if crate::app_auth::reuse_discovery(last.0, since) {
            return match &last.1 {
                Some(e) => Err(anyhow::anyhow!("{e}")),
                None => Ok(a.names.read().unwrap().len()),
            };
        }
        let r = self.discover_into(&a).await;
        *a.error.lock().unwrap() = match &r {
            Ok((_, errs)) if errs.is_empty() => None,
            Ok((_, errs)) => Some(errs.join("; ")),
            Err(e) => Some(format!("{e:#}")),
        };
        *last = (crate::now(), r.as_ref().err().map(|e| format!("{e:#}")));
        r.map(|(n, _)| n)
    }

    /// (repos found, per-installation errors; ignored installations go to `notes`). One failing
    /// installation keeps its previous repos and does not stop the others; suspended
    /// installations and those on accounts other than the owner's and `app_accounts` are skipped.
    async fn discover_into(&self, a: &crate::app_auth::AppAuth) -> Result<(usize, Vec<String>)> {
        // The owner comes from GitHub every time (one JWT call): app.json's copy is for
        // display only. If it can't be read, discovery fails and the last map stays.
        let me = self.app_info(a).await.context("reading the App's owner (GET /app)")?;
        let owner = me["owner"]["id"].as_u64().context("GitHub's GET /app response names no owner")?;
        if let Some(login) = me["owner"]["login"].as_str()
            && *a.owner.read().unwrap() != login
            && let Err(e) = a.set_owner(login)
        {
            tracing::warn!("saving the App owner to app.json: {e:#}");
        }
        let accounts = self.app_accounts.read().unwrap().clone();
        let jwt = a.jwt(crate::now())?;
        let mut map = BTreeMap::new();
        let mut errs = vec![];
        let mut notes = vec![];
        let mut page = 1;
        loop {
            let r = self.request_with(&jwt, Method::GET, &format!("app/installations?per_page=100&page={page}")).send().await?;
            if !r.status().is_success() {
                bail!("listing App installations: {}", r.status());
            }
            let insts: Vec<Value> = r.json().await?;
            let (ids, ignored) = crate::app_auth::served_installations(&insts, owner, &accounts);
            notes.extend(ignored);
            for id in ids {
                match self.installation_repos(a, id).await {
                    Ok(repos) => map.extend(repos.into_iter().map(|n| (n, id))),
                    Err(e) => {
                        errs.push(format!("installation {id}: {e:#}"));
                        let old = a.repos.read().unwrap().clone();
                        map.extend(old.into_iter().filter(|(_, i)| *i == id));
                    }
                }
            }
            if insts.len() < 100 {
                break;
            }
            page += 1;
        }
        *a.notes.lock().unwrap() = notes;
        // Display names: GitHub's spelling from the last successful listing, else the key.
        let prev: Vec<String> = a.names.read().unwrap().clone();
        let mut names: Vec<String> = map
            .keys()
            .map(|k| {
                self.spelled
                    .lock()
                    .unwrap()
                    .get(k)
                    .cloned()
                    .or_else(|| prev.iter().find(|p| p.to_ascii_lowercase() == *k).cloned())
                    .unwrap_or_else(|| k.clone())
            })
            .collect();
        names.sort_by_key(|n| n.to_ascii_lowercase());
        let n = names.len();
        *a.repos.write().unwrap() = map;
        *a.names.write().unwrap() = names;
        a.discovered_at.store(crate::now(), Ordering::Relaxed);
        Ok((n, errs))
    }

    /// Lowercase names of an installation's repos; records GitHub's spelling in `spelled`.
    async fn installation_repos(&self, a: &crate::app_auth::AppAuth, id: u64) -> Result<Vec<String>> {
        let token = self.mint(a, id).await?;
        let mut out = vec![];
        let mut p = 1;
        loop {
            let path = format!("installation/repositories?per_page=100&page={p}");
            let r = self.request_with(&token, Method::GET, &path).send().await?;
            if !r.status().is_success() {
                bail!("listing its repos: {}", r.status());
            }
            let v: Value = r.json().await?;
            let repos = v["repositories"].as_array().cloned().unwrap_or_default();
            for n in repos.iter().filter_map(|r| r["full_name"].as_str()) {
                self.spelled.lock().unwrap().insert(n.to_ascii_lowercase(), n.to_string());
                out.push(n.to_ascii_lowercase());
            }
            if repos.len() < 100 {
                return Ok(out);
            }
            p += 1;
        }
    }

    /// Delete offline, idle `kiln-*` runners left behind by a crash. Only runners of this
    /// host's architecture: a kiln of the other one may serve the same repo, and its
    /// runners are offline while their VMs boot.
    pub async fn sweep_runners(&self, repo: &str) -> Result<usize> {
        let v = self.get(&format!("repos/{repo}/actions/runners?per_page=100")).await?;
        let mut n = 0;
        for r in v["runners"].as_array().into_iter().flatten() {
            if let Some(id) = r["id"].as_u64()
                && r["name"].as_str().is_some_and(|n| n.starts_with("kiln-"))
                && same_arch(&r["labels"], crate::host::ARM64)
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
        let file =
            json!({ "path": ".github/workflows/kiln-hello.yml", "mode": "100644", "type": "blob", "content": hello_workflow(label) });
        let (st, v) =
            self.api(Method::POST, &format!("repos/{repo}/git/trees"), Some(json!({ "base_tree": base_tree, "tree": [file] }))).await?;
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
        let (rb, who) = self.request(Method::DELETE, &format!("repos/{repo}/actions/runners/{id}")).await?;
        let r = self.exec(rb, who).await?;
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
    # Never run pull requests from forks on self-hosted hardware.
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
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

/// Why a manifest code could not be converted. 404/422: the code expired or was used,
/// possibly by a conversion whose response never arrived, so the App may exist already.
fn conversion_error(status: u16) -> String {
    match status {
        404 | 422 => format!(
            "GitHub refused the setup code ({status}): it is single use and expires after an hour. \
             If GitHub already created the App, open it on github.com, generate a private key, and use 'Use an existing App'."
        ),
        _ => format!("GitHub could not finish the setup ({status}): try again (the setup code stays usable for an hour)"),
    }
}

/// Allowed `<label>-<N>cpu` sizes.
pub const SIZES: [u32; 4] = [2, 4, 8, 16];

/// RAM for a size label; the default size uses the configured memory instead.
pub fn size_mem_mb(cpus: u32) -> u32 {
    (cpus * 2048).min(24576)
}

/// `branch` marked up (so no writer matches it) when it is not a plain branch name
/// that is safe to put in an API path unencoded ([A-Za-z0-9._/-], no ".."); None if it is.
fn unsafe_branch(branch: &str) -> Option<String> {
    (!crate::valid_branch(branch)).then(|| format!("{branch} (not a plain branch name)"))
}

/// Did this run's code come from another repository (a fork PR)? Fails closed:
/// a run whose head repository is gone (deleted fork) counts as a fork.
fn is_fork_run(run: &Value) -> bool {
    match (run["head_repository"]["full_name"].as_str(), run["repository"]["full_name"].as_str()) {
        (Some(head), Some(base)) => !head.eq_ignore_ascii_case(base),
        _ => true,
    }
}

/// The configured label as runners of this architecture advertise it: arm64 hosts
/// add `-arm64`, so a job written for x64 (`<label>`) never lands on an arm64 VM.
pub fn arch_label(label: &str, arm64: bool) -> String {
    if arm64 { format!("{label}-arm64") } else { label.to_string() }
}

/// Does a runner (its `labels` from the runners API) have this host's architecture label?
fn same_arch(labels: &Value, arm64: bool) -> bool {
    let arch = if arm64 { "arm64" } else { "x64" };
    labels.as_array().into_iter().flatten().any(|l| l["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(arch)))
}

/// The VM size a job asks for, if it is ours: every label must be implicit
/// (GitHub adds `self-hosted`, `linux` and the architecture, `x64` or `ARM64`, to
/// self-hosted runners) or one of ours, and exactly one of ours must be present.
/// `<label>` is the default size, `<label>-Ncpu` size N (`<label>-arm64`... on an
/// arm64 host). A plain `self-hosted` job is someone else's, and so is a job for
/// the other architecture.
fn job_size(job_labels: &Value, label: &str, default_cpus: u32, arm64: bool) -> Option<u32> {
    let label = arch_label(label, arm64).to_ascii_lowercase();
    let arch = if arm64 { "arm64" } else { "x64" };
    let mut size = None;
    let mut found = 0;
    for l in job_labels.as_array()? {
        let l = l.as_str()?.to_ascii_lowercase();
        if ["self-hosted", "linux", arch].contains(&l.as_str()) {
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
/// GitHub's unauthenticated budget (60/h per IP); every token's is 5000 or more.
fn anonymous_budget(limit: Option<u64>) -> bool {
    limit.is_some_and(|l| l <= 60)
}

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

/// Whether `who`'s rate limit is ours to track and pause on. In App mode identity 0 only
/// makes unauthenticated calls, which spend GitHub's per-IP budget, not an installation's.
fn billed(app_mode: bool, who: u64) -> bool {
    !app_mode || who != 0
}

/// The entries whose rate-limit window has not reset yet.
fn live(rates: &BTreeMap<u64, (u64, u64, u64)>, now: u64) -> BTreeMap<u64, (u64, u64, u64)> {
    rates.iter().filter(|(_, r)| r.2 > now).map(|(&k, &v)| (k, v)).collect()
}

/// The identity with the lowest remaining/limit ratio, among windows not yet reset.
fn tightest(rates: &BTreeMap<u64, (u64, u64, u64)>, now: u64) -> Option<(u64, u64, u64)> {
    live(rates, now).into_values().min_by_key(|&(rem, lim, _)| (rem as u128 * 1_000_000) / lim.max(1) as u128)
}

/// Repo error for a repo whose installation (on the repo's owner) is paused until `t`.
fn paused_msg(repo: &str, t: u64) -> String {
    let owner = repo.split('/').next().unwrap_or(repo);
    format!("GitHub rate limit for installation on {owner}: paused until {:02}:{:02} UTC", t / 3600 % 24, t / 60 % 60)
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
    #[test]
    fn anonymous_budget_is_not_ours() {
        // GitHub's unauthenticated budget is 60/h per IP; any token's is 5000+.
        assert!(super::anonymous_budget(Some(60)));
        assert!(!super::anonymous_budget(Some(5000)));
        assert!(!super::anonymous_budget(Some(15000)));
        assert!(!super::anonymous_budget(None));
    }

    #[test]
    fn fork_runs() {
        let run = |head: Value| json!({ "head_repository": head, "repository": { "full_name": "o/n" } });
        assert!(!super::is_fork_run(&run(json!({ "full_name": "O/N" }))));
        assert!(super::is_fork_run(&run(json!({ "full_name": "evil/n" }))));
        assert!(super::is_fork_run(&run(Value::Null)));
    }

    use super::*;

    #[test]
    fn cache_trust_branch_names() {
        assert_eq!(unsafe_branch("main"), None);
        assert_eq!(unsafe_branch("release/1.x"), None);
        // would change the API path built from it: refused, marked up so cache_verdict says no
        for b in ["a#b", "x?y", "dev%2F..%2Fmain", "../../main", "dev branch", ""] {
            let m = unsafe_branch(b).unwrap_or_else(|| panic!("{b:?}"));
            assert_ne!(m, b);
        }
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        // GitHub's token expiry header format
        assert_eq!(parse_rfc3339("2026-10-06 10:51:50 UTC"), Some(1791283910));
        assert_eq!(parse_rfc3339("2026-10-06T10:51:50Z"), Some(1791283910));
        assert_eq!(parse_rfc3339("2024-02-29T23:59:59Z"), Some(1709251199));
        assert_eq!(parse_rfc3339("garbage"), None);
    }

    #[test]
    fn tightest_rate() {
        let m = |v: &[(u64, (u64, u64, u64))]| v.iter().copied().collect::<BTreeMap<_, _>>();
        assert_eq!(tightest(&m(&[]), 0), None);
        // PAT mode: the single identity, as before
        assert_eq!(tightest(&m(&[(0, (4000, 5000, 9))]), 0), Some((4000, 5000, 9)));
        // lowest remaining/limit ratio wins, not the lowest remaining count
        assert_eq!(tightest(&m(&[(1, (900, 1000, 1)), (2, (1000, 15000, 2)), (3, (4000, 5000, 3))]), 0), Some((1000, 15000, 2)));
    }

    #[test]
    fn expired_rates_ignored() {
        let m: BTreeMap<_, _> = [(1, (0, 5000, 100)), (2, (4000, 5000, 900))].into_iter().collect();
        // Identity 1's window reset at 100: its empty budget is history.
        assert_eq!(tightest(&m, 99), Some((0, 5000, 100)));
        assert_eq!(tightest(&m, 100), Some((4000, 5000, 900)));
        assert_eq!(live(&m, 100).keys().copied().collect::<Vec<_>>(), [2]);
        assert_eq!(tightest(&m, 900), None);
    }

    #[test]
    fn app_mode_identity_zero_is_anonymous() {
        // Token mode: 0 is the token, tracked and paused.
        assert!(billed(false, 0));
        // App mode: 0 is an unauthenticated call (public lookup, or a failed mint), never ours.
        assert!(!billed(true, 0));
        assert!(billed(true, 42));
    }

    #[test]
    fn install_pause_message() {
        // 1791283910 = 2026-10-06 10:51:50 UTC
        assert_eq!(paused_msg("Bunty9/kiln", 1791283910), "GitHub rate limit for installation on Bunty9: paused until 10:51 UTC");
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
        let size = |v: Value| job_size(&v, "kiln", 4, false);
        assert_eq!(size(json!(["self-hosted", "kiln"])), Some(4));
        assert_eq!(size(json!(["kiln"])), Some(4));
        assert_eq!(size(json!(["Self-Hosted", "Linux", "KILN"])), Some(4));
        assert_eq!(size(json!(["self-hosted", "linux", "x64", "kiln-16cpu"])), Some(16));
        assert_eq!(size(json!(["kiln-8cpu"])), Some(8));
        assert_eq!(size(json!(["self-hosted", "Kiln-2CPU"])), Some(2));
        assert_eq!(size(json!(["kiln-4cpu"])), Some(4));
        assert_eq!(job_size(&json!(["kiln"]), "kiln", 6, false), Some(6));
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
        // An x64 host ignores arm64 jobs.
        assert_eq!(size(json!(["self-hosted", "kiln-arm64"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln-arm64-8cpu"])), None);
        assert_eq!(size(json!(["self-hosted", "ARM64", "kiln"])), None);
    }

    #[test]
    fn arm64_label_matching() {
        let size = |v: Value| job_size(&v, "kiln", 4, true);
        assert_eq!(size(json!(["self-hosted", "kiln-arm64"])), Some(4));
        assert_eq!(size(json!(["self-hosted", "linux", "ARM64", "kiln-arm64"])), Some(4));
        assert_eq!(size(json!(["kiln-arm64-8cpu"])), Some(8));
        assert_eq!(size(json!(["self-hosted", "Kiln-ARM64-16CPU"])), Some(16));
        // x64 jobs never land on an arm64 host.
        assert_eq!(size(json!(["self-hosted", "kiln"])), None);
        assert_eq!(size(json!(["self-hosted", "kiln-8cpu"])), None);
        assert_eq!(size(json!(["self-hosted", "x64", "kiln-arm64"])), None);
        assert_eq!(size(json!(["kiln-arm64", "kiln-arm64-8cpu"])), None);
        assert_eq!(size(json!(["kiln-arm64-3cpu"])), None);
        assert_eq!(size(json!(["kiln-arm64-"])), None);
        assert_eq!(arch_label("kiln", true), "kiln-arm64");
        assert_eq!(arch_label("kiln", false), "kiln");
        let labels = |names: &[&str]| Value::from(names.iter().map(|n| json!({ "id": 1, "name": n })).collect::<Vec<_>>());
        assert!(same_arch(&labels(&["self-hosted", "Linux", "X64", "kiln"]), false));
        assert!(!same_arch(&labels(&["self-hosted", "Linux", "X64", "kiln"]), true), "an arm64 kiln leaves x64 runners alone");
        assert!(same_arch(&labels(&["self-hosted", "Linux", "ARM64", "kiln-arm64"]), true));
        assert!(!same_arch(&labels(&["self-hosted", "Linux", "ARM64", "kiln-arm64"]), false));
        assert!(!same_arch(&Value::Null, false));
    }

    #[test]
    fn hello() {
        let w = hello_workflow("kiln");
        assert!(
            w.contains("runs-on: [self-hosted, kiln]\n") && w.contains("awk '/Mem:/{print $2}'") && w.contains("echo \"vCPUs: $(nproc)")
        );
        let m = json!({ "message": "Nope" });
        assert!(hello_err(404, &m, "creating the branch").contains("Contents and Workflows"));
        assert!(hello_err(403, &m, "adding the workflow").starts_with("GitHub refused"));
        assert_eq!(hello_err(404, &m, "reading the repo"), "repo not found, or the token cannot see it");
        assert_eq!(hello_err(422, &m, "creating the branch"), "GitHub: 422 while creating the branch: Nope");
    }

    #[test]
    fn conversion_errors() {
        let hint = "If GitHub already created the App, open it on github.com, generate a private key, and use 'Use an existing App'.";
        for st in [404, 422] {
            let e = conversion_error(st);
            assert!(e.ends_with(hint), "{e}");
            assert!(e.contains(&st.to_string()));
        }
        let e = conversion_error(502);
        assert!(e.contains("try again") && !e.contains("existing App"), "{e}");
    }

    #[test]
    fn size_memory() {
        assert_eq!(size_mem_mb(2), 4096);
        assert_eq!(size_mem_mb(8), 16384);
        assert_eq!(size_mem_mb(16), 24576);
    }
}
