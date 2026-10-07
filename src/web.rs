//! Dashboard + JSON API. Reachable only from loopback and the tailnet.

use crate::{App, Config, mirror, now, vm};
use anyhow::{Context, anyhow};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{any, get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex};
use tokio::process::Command;

type S = State<Arc<App>>;

pub struct Error(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for Error {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, format!("{:#}", self.0)).into_response()
    }
}
type R<T> = Result<T, Error>;

/// The address actually bound; a config change to `listen` needs a restart.
static RUNNING_LISTEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub async fn serve(app: Arc<App>) -> anyhow::Result<()> {
    let addr = app.cfg().listen;
    let _ = RUNNING_LISTEN.set(addr.clone());
    load_key(&app.data)?;
    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("dashboard.html")) }))
        .route("/api/state", get(state))
        .route("/api/config", post(set_config))
        .route("/api/token", post(set_token))
        .route("/api/app", post(app_manual).delete(app_remove))
        .route("/api/app/manifest", post(app_manifest))
        .route("/api/app/convert", post(app_convert))
        .route("/api/doctor", get(doctor))
        .route("/api/log", get(log))
        .route("/api/vms/{id}/kill", post(kill))
        .route("/api/vms/{id}/release", post(release))
        .route("/api/cache/clear", post(cache_clear))
        .route("/api/onboard", get(onboard))
        .route("/api/onboard/hello", post(onboard_hello))
        .route("/api/bake", post(bake))
        .route("/api/tailscale", get(ts_status))
        .route("/api/tailscale/netcheck", get(ts_netcheck))
        .route("/api/tailscale/ping", post(ts_ping))
        .route("/api/tailscale/serve", post(ts_serve))
        .route("/api/gh/{*path}", any(gh_proxy))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("bind {addr}"))?;
    tracing::info!("dashboard on http://{addr}");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

fn is_tailnet(ip: IpAddr) -> bool {
    match ip {
        // 100.64.0.0/10 (CGNAT range Tailscale assigns from)
        IpAddr::V4(v4) => v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64,
        // fd7a:115c:a1e0::/48
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// (login, node StableID) of the tailnet node behind `ip`.
type Who = (String, String);
static WHOIS: LazyLock<Mutex<HashMap<IpAddr, (Who, u64)>>> = LazyLock::new(Mutex::default);

async fn whois(ip: IpAddr) -> Option<Who> {
    if let Some((who, at)) = WHOIS.lock().unwrap().get(&ip)
        && now() - at < 300
    {
        return Some(who.clone());
    }
    let out = Command::new("tailscale").args(["whois", "--json", &ip.to_string()]).output().await.ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let who = (v["UserProfile"]["LoginName"].as_str()?.to_string(), v["Node"]["StableID"].as_str()?.to_string());
    WHOIS.lock().unwrap().insert(ip, (who.clone(), now()));
    Some(who)
}

/// This machine's own tailnet IPs and the login that owns it, from
/// `tailscale status`. Refreshed every 5 minutes.
#[derive(Clone, Default)]
struct SelfInfo {
    ips: Vec<IpAddr>,
    node: Option<String>,
    owner: Option<String>,
    at: u64,
}
static SELF: LazyLock<Mutex<SelfInfo>> = LazyLock::new(Mutex::default);

async fn self_info() -> SelfInfo {
    let cached = SELF.lock().unwrap().clone();
    if cached.at != 0 && now() - cached.at < 300 {
        return cached;
    }
    let Ok(out) = Command::new("tailscale").args(["status", "--json"]).output().await else { return cached };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let ips = v["Self"]["TailscaleIPs"].as_array().into_iter().flatten().filter_map(|ip| ip.as_str()?.parse().ok()).collect();
    let uid = v["Self"]["UserID"].to_string();
    let owner = v["User"][uid.as_str()]["LoginName"].as_str().map(String::from);
    let node = v["Self"]["ID"].as_str().map(String::from);
    let info = SelfInfo { ips, node, owner, at: now() };
    *SELF.lock().unwrap() = info.clone();
    info
}

/// Secret for requests that originate on this machine (see `guard`).
/// Generated once, stored next to the config, mode 0600.
static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn load_key(data: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path = data.join("dashboard.key");
    let key = match std::fs::read_to_string(&path) {
        Ok(k) if k.trim().len() >= 32 => k.trim().to_string(),
        _ => {
            let mut raw = [0u8; 24];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
            let k: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
            std::io::Write::write_all(&mut f, k.as_bytes())?;
            k
        }
    };
    let _ = KEY.set(key);
    Ok(())
}

fn key_ok(given: Option<&str>) -> bool {
    let (Some(given), Some(key)) = (given, KEY.get()) else { return false };
    // Constant-time compare.
    given.len() == key.len() && given.bytes().zip(key.bytes()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Reject DNS-rebinding: a page on evil.example resolving to our IP would
/// otherwise be same-origin with us and could add our headers.
fn host_ok(host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, p)| if p.parse::<u16>().is_ok() { h } else { host }),
    };
    name.parse::<IpAddr>().is_ok()
        || name == "localhost"
        || name.ends_with(".ts.net")
        // MagicDNS short name, e.g. http://ryzen7:7878
        || (!name.is_empty() && !name.contains('.'))
}

/// Who may talk to kiln:
/// - Tailnet peers whose `tailscale whois` login is in `allowed_users`
///   (default: the owner of this machine, so shared-in nodes are out).
/// - Requests from this machine itself only with the dashboard key. Job VMs
///   reach the host through QEMU's NAT and arrive as loopback or as this
///   host's own tailnet IP, so a local source address proves nothing.
async fn guard(State(app): S, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut r = admit(app, peer, req, next).await;
    let h = r.headers_mut();
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // No script-src: the dashboard uses an inline script.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("frame-ancestors 'none'"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // The page is embedded in the binary: no-cache so a redeploy shows up on reload.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(if api { "no-store" } else { "no-cache" }));
    r
}

/// Tailscale reports tagged nodes as this pseudo-login; it names no person.
const TAGGED: &str = "tagged-devices";

/// `allowed` is the configured list; empty falls back to the box's owner,
/// unless that owner is the tagged pseudo-user. A tagged peer gets in only
/// when listed explicitly.
fn peer_allowed(allowed: &[String], owner: Option<String>, login: &str) -> bool {
    let mut allowed = allowed.to_vec();
    if allowed.is_empty() {
        allowed.extend(owner.filter(|o| o != TAGGED));
    }
    allowed.iter().any(|a| a.eq_ignore_ascii_case(login))
}

async fn admit(app: Arc<App>, peer: SocketAddr, req: Request, next: Next) -> Response {
    let ip = peer.ip().to_canonical();
    let deny = |code: StatusCode, msg: &str| (code, msg.to_string()).into_response();
    // Owned copies: `req` (its body) is not Sync, so no borrows across awaits.
    let (host, csrf, key) = {
        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(String::from);
        (h("host"), h("x-kiln"), h("x-kiln-key"))
    };
    let api = req.uri().path().starts_with("/api/");
    let get = req.method() == Method::GET;
    if !host_ok(host.as_deref()) {
        return deny(StatusCode::FORBIDDEN, "unexpected Host header");
    }
    // Browsers can't add custom headers cross-origin without a CORS preflight
    // we never grant, so this blocks drive-by POSTs from other sites.
    if api && !get && csrf.is_none() {
        return deny(StatusCode::FORBIDDEN, "missing x-kiln header");
    }
    // LAN and internet sources are refused outright, whatever Tailscale's state:
    // over plain HTTP they could otherwise be asked for the dashboard key.
    if !ip.is_loopback() && !is_tailnet(ip) {
        return deny(StatusCode::FORBIDDEN, "kiln only answers on the tailnet");
    }
    let me = self_info().await;
    let who = if is_tailnet(ip) && !ip.is_loopback() { whois(ip).await } else { None };
    // Fail closed: if we can't tell our own addresses or node apart from a
    // peer (tailscale down, CLI error), treat the request as local.
    let local = ip.is_loopback()
        || me.ips.is_empty()
        || me.node.is_none()
        || me.ips.contains(&ip)
        || who.as_ref().is_some_and(|(_, node)| Some(node) == me.node.as_ref());
    if local {
        if api && !key_ok(key.as_deref()) {
            return deny(StatusCode::UNAUTHORIZED, "dashboard key required (see ~/.local/share/kiln/dashboard.key on the CI box)");
        }
    } else if !who.is_some_and(|(l, _)| peer_allowed(&app.cfg().allowed_users, me.owner, &l)) {
        return deny(StatusCode::FORBIDDEN, "your tailnet identity is not allowed (allowed_users)");
    }
    next.run(req).await
}

async fn host_stats(app: &App) -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    json!({
        "load": load.split_whitespace().take(3).collect::<Vec<_>>(),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "mem_total_mb": vm::meminfo_kb("MemTotal:") / 1024,
        "mem_avail_mb": vm::mem_avail_mb(),
        "disk_free_gb": vm::disk_free_gb(&app.data).await,
    })
}

async fn state(State(app): S) -> R<Json<Value>> {
    let vms: Vec<_> = app.vms.lock().unwrap().iter().rev().take(100).cloned().collect();
    let mut poll = serde_json::to_value(&*app.poll.lock().unwrap())?;
    poll["backoff"] = app
        .backoff
        .lock()
        .unwrap()
        .iter()
        .map(|(r, &(fails, retry_at))| (r.clone(), json!({ "fails": fails, "retry_at": retry_at })))
        .collect::<serde_json::Map<_, _>>()
        .into();
    poll["rate"] = match *app.gh.rate.lock().unwrap() {
        Some((remaining, limit, reset)) => json!({ "remaining": remaining, "limit": limit, "reset": reset }),
        None => Value::Null,
    };
    poll["paused_until"] = json!(app.gh.paused_until());
    Ok(Json(json!({
        "config": app.cfg(),
        "token_set": app.gh.has_token(),
        "app": app.gh.app().map(|a| json!({
            "id": a.id,
            "slug": a.slug,
            "html_url": a.html_url,
            "repos": a.names.read().unwrap().clone(),
            "discovered_at": a.discovered_at.load(std::sync::atomic::Ordering::Relaxed),
            "error": a.error.lock().unwrap().clone(),
        })),
        "token_source": app.gh.source(),
        "token_expires": *app.gh.expires.lock().unwrap(),
        "token_saved": std::fs::metadata(app.data.join("token")).ok().filter(|_| app.gh.source() == "file").and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
        "poll": poll,
        "vms": vms,
        "image": vm::image_info(&app.data, app.gh.latest_cached(), &app.cfg()),
        "image_ready": vm::image_ready(&app.data),
        "baking": app.baking.load(std::sync::atomic::Ordering::Relaxed),
        "host": host_stats(&app).await,
        "version": env!("CARGO_PKG_VERSION"),
        "mirror": mirror::status_json(&app).await,
        "caches": vm::cache_stats(&app.data, &app.repos()),
    })))
}

async fn doctor(State(app): S) -> R<Json<Value>> {
    Ok(Json(json!({ "checks": vm::doctor(&app, false).await })))
}

async fn set_config(State(app): S, Json(c): Json<Config>) -> R<Json<Value>> {
    let restart = RUNNING_LISTEN.get().is_some_and(|l| *l != c.listen);
    let to_filtered = c.egress == "filtered" && app.cfg().egress != "filtered";
    app.save_cfg(c)?;
    if to_filtered {
        // Probe now so the dashboard shows the result and the scheduler has it cached.
        let a = app.clone();
        tokio::spawn(async move {
            let _ = vm::egress_ready(&a, true).await;
        });
    }
    Ok(Json(json!({ "restart_required": restart })))
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}
/// Check the token against GitHub before saving it: it must authenticate, and
/// each configured repo's runners API is probed so a missing Administration
/// permission shows now (doctor checks the others).
async fn set_token(State(app): S, Json(b): Json<TokenBody>) -> R<Json<Value>> {
    let token = b.token.trim().to_string();
    let (status, scopes, user) = app.gh.probe(&token, "user").await?;
    if status != 200 {
        bail_r(&format!("GitHub rejected the token: {status} {}", user["message"].as_str().unwrap_or("")))?;
    }
    let mut repos = serde_json::Map::new();
    for r in app.repos() {
        let (st, _, body) = app.gh.probe(&token, &format!("repos/{r}/actions/runners?per_page=1")).await?;
        let msg = if st == 200 { "ok".to_string() } else { format!("{st} {}", body["message"].as_str().unwrap_or("")) };
        repos.insert(r, msg.into());
    }
    app.save_token(token)?;
    Ok(Json(json!({ "login": user["login"], "scopes": scopes, "repos": repos })))
}

#[derive(Deserialize)]
struct LogQuery {
    /// "bake", or a VM id
    src: String,
    /// "console" | "steps" (VMs only)
    #[serde(default)]
    file: String,
    #[serde(default)]
    from: u64,
}

/// Incremental log read: the client keeps `next` and asks again.
async fn log(State(app): S, Query(q): Query<LogQuery>) -> R<Json<Value>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let path = if q.src == "bake" {
        app.data.join("images/bake.log")
    } else {
        vm::check_id(&q.src)?;
        let file = match q.file.as_str() {
            "steps" => "steps.log",
            _ => "console.log",
        };
        app.data.join("vms").join(&q.src).join(file)
    };
    let Ok(mut f) = tokio::fs::File::open(&path).await else {
        return Ok(Json(json!({ "data": "", "next": 0 })));
    };
    let len = f.metadata().await?.len();
    // A shorter file than our cursor means it was rewritten (new bake): restart.
    let from = if q.from > len { 0 } else { q.from };
    f.seek(std::io::SeekFrom::Start(from)).await?;
    let mut buf = vec![];
    f.take(512 * 1024).read_to_end(&mut buf).await?;
    let next = from + buf.len() as u64;
    Ok(Json(json!({ "data": String::from_utf8_lossy(&buf), "next": next, "size": len })))
}

async fn kill(State(app): S, Path(id): Path<String>) -> R<StatusCode> {
    let n = app.kills.lock().unwrap().get(&id).cloned().ok_or_else(|| anyhow!("no running VM {id}"))?;
    n.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

/// Ends a hold early: the guest powers off and the VM finishes normally.
async fn release(State(app): S, Path(id): Path<String>) -> R<StatusCode> {
    vm::check_id(&id)?;
    if !app.vms.lock().unwrap().iter().any(|v| v.id == id && v.state == vm::State::Held) {
        bail_r("that VM is not held")?;
    }
    let n = app.releases.lock().unwrap().get(&id).cloned().ok_or_else(|| anyhow!("no running VM {id}"))?;
    n.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RepoBody {
    repo: String,
}
async fn cache_clear(State(app): S, Json(b): Json<RepoBody>) -> R<StatusCode> {
    vm::clear_cache(&app, &b.repo)?;
    Ok(StatusCode::NO_CONTENT)
}

/// {"o/n": {"pr_url", "at"}} of hello PRs this kiln opened; survives restarts.
fn hello_prs(data: &std::path::Path) -> serde_json::Map<String, Value> {
    std::fs::read(data.join("onboard.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

async fn onboard(State(app): S) -> Json<Value> {
    Json(json!({ "hello_prs": hello_prs(&app.data) }))
}

/// Opens a PR with a hello workflow in a configured repo (no proxy: needs write scopes).
async fn onboard_hello(State(app): S, Json(b): Json<RepoBody>) -> R<Json<Value>> {
    static SAVE: Mutex<()> = Mutex::new(());
    let cfg = app.cfg();
    if app.gh.app().is_some() {
        bail_r("the hello PR is off in GitHub App mode (the App cannot write code)")?;
    }
    let repo = cfg.repos.iter().find(|r| r.eq_ignore_ascii_case(&b.repo)).ok_or_else(|| anyhow!("not a configured repo"))?;
    let t = now();
    let (pr_url, branch) = app.gh.hello_pr(repo, &cfg.label, t).await?;
    let _g = SAVE.lock().unwrap();
    let mut m = hello_prs(&app.data);
    m.insert(repo.clone(), json!({ "pr_url": pr_url, "at": t }));
    // Best effort: the PR exists either way.
    let _ = std::fs::write(app.data.join("onboard.json"), serde_json::to_vec(&m)?);
    Ok(Json(json!({ "pr_url": pr_url, "branch": branch })))
}

async fn bake(State(app): S) -> R<StatusCode> {
    if app.baking.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(anyhow!("already baking").into());
    }
    tokio::spawn(async move {
        if let Err(e) = vm::bake(app).await {
            tracing::error!("bake failed: {e:#}");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn tailscale(args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new("tailscale").args(args).output().await.context("running tailscale CLI")
}

async fn ts_status() -> R<Json<Value>> {
    let status = tailscale(&["status", "--json"]).await?;
    let serve = tailscale(&["serve", "status", "--json"]).await?;
    Ok(Json(json!({
        "status": serde_json::from_slice::<Value>(&status.stdout).unwrap_or(Value::Null),
        "serve": serde_json::from_slice::<Value>(&serve.stdout).unwrap_or(Value::Null),
    })))
}

async fn ts_netcheck() -> R<Json<Value>> {
    let out = tailscale(&["netcheck", "--format=json"]).await?;
    Ok(Json(serde_json::from_slice(&out.stdout).context("netcheck output")?))
}

#[derive(Deserialize)]
struct PingBody {
    peer: String,
}
async fn ts_ping(Json(b): Json<PingBody>) -> R<Json<Value>> {
    let ok_chars = b.peer.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c));
    if b.peer.is_empty() || b.peer.starts_with('-') || !ok_chars {
        bail_r("bad peer name")?;
    }
    let out = tailscale(&["ping", "--c", "1", "--timeout", "3s", &b.peer]).await?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    Ok(Json(json!({ "ok": out.status.success(), "output": text.trim() })))
}

#[derive(Deserialize)]
struct ServeBody {
    on: bool,
}
/// Publishes the dashboard as https://<host>.<tailnet>.ts.net:8443 with a real
/// cert. 8443 so we never disturb whatever already lives on :443.
async fn ts_serve(State(app): S, Json(b): Json<ServeBody>) -> R<Json<Value>> {
    let port = app.cfg().listen.rsplit(':').next().unwrap_or("7878").to_string();
    let target = format!("http://127.0.0.1:{port}");
    let args: Vec<&str> = if b.on { vec!["serve", "--bg", "--https=8443", &target] } else { vec!["serve", "--https=8443", "off"] };
    let out = tailscale(&args).await?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail_r(text.trim())?;
    }
    Ok(Json(json!({ "output": text.trim() })))
}

#[derive(Deserialize)]
struct ManifestBody {
    #[serde(default)]
    org: String,
}

/// Start the one-click App creation: the manifest, GitHub's form URL and a one-time state.
/// The redirect goes back to the origin the browser used (its Host header, already vetted).
async fn app_manifest(State(app): S, headers: HeaderMap, Json(b): Json<ManifestBody>) -> R<Json<Value>> {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).ok_or_else(|| anyhow!("no Host header"))?;
    let org = b.org.trim();
    if !org.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail_r("org must be a GitHub org login")?;
    }
    let name = std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| "box".into());
    let state = app.app_states.lock().unwrap().issue(now());
    let base = if org.is_empty() {
        "https://github.com/settings/apps/new".to_string()
    } else {
        format!("https://github.com/organizations/{org}/settings/apps/new")
    };
    Ok(Json(json!({
        "url": format!("{base}?state={state}"),
        "manifest": crate::app_auth::manifest(&format!("http://{host}"), name.trim()),
        "state": state,
    })))
}

#[derive(Deserialize)]
struct ConvertBody {
    code: String,
    state: String,
}

/// Finish the one-click flow: trade GitHub's code for the App's id and key, and switch to it.
async fn app_convert(State(app): S, Json(b): Json<ConvertBody>) -> R<Json<Value>> {
    if !app.app_states.lock().unwrap().take(&b.state, now()) {
        bail_r("this setup link is unknown, already used or older than an hour: start again")?;
    }
    if b.code.is_empty() || !b.code.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail_r("bad code")?;
    }
    let v = app.gh.manifest_conversion(&b.code).await?;
    let id = v["id"].as_u64().ok_or_else(|| anyhow!("GitHub returned no app id"))?;
    let (slug, url, pem) = (v["slug"].as_str().unwrap_or(""), v["html_url"].as_str().unwrap_or(""), v["pem"].as_str().unwrap_or(""));
    let a = crate::app_auth::save(&app.data, id, slug, url, pem)?;
    app.gh.set_app(Some(Arc::new(a)));
    let _ = app.gh.discover().await;
    Ok(Json(json!({ "slug": slug, "html_url": url })))
}

#[derive(Deserialize)]
struct ManualBody {
    id: u64,
    pem: String,
}

/// Use an existing App: checked against GitHub (GET /app with its JWT) before saving.
async fn app_manual(State(app): S, Json(b): Json<ManualBody>) -> R<Json<Value>> {
    let a = crate::app_auth::AppAuth::new(b.id, String::new(), String::new(), &b.pem)?;
    let me = app.gh.app_info(&a).await?;
    let (slug, url) = (me["slug"].as_str().unwrap_or(""), me["html_url"].as_str().unwrap_or(""));
    let a = crate::app_auth::save(&app.data, b.id, slug, url, &b.pem)?;
    app.gh.set_app(Some(Arc::new(a)));
    let _ = app.gh.discover().await;
    Ok(Json(json!({ "slug": slug, "html_url": url })))
}

/// Back to token auth: delete the App's key and record.
async fn app_remove(State(app): S) -> R<Json<Value>> {
    for f in ["app.pem", "app.json"] {
        match std::fs::remove_file(app.data.join(f)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    app.gh.set_app(None);
    Ok(Json(json!({ "ok": true })))
}

fn bail_r(msg: &str) -> R<()> {
    Err(anyhow!(msg.to_string()).into())
}

/// GitHub passthrough, restricted to `repos/<configured repo>/actions/...`,
/// so the dashboard can browse workflows/runs/jobs/logs and dispatch, rerun
/// or cancel without a dedicated endpoint per call.
async fn gh_proxy(State(app): S, method: Method, Path(path): Path<String>, q: axum::extract::RawQuery, body: Bytes) -> R<Response> {
    if !proxy_path_ok(&path, &app.repos()) {
        bail_r("only repos/<configured repo>/actions/{workflows,runs,jobs}... is proxied")?;
    }
    if method != Method::GET && method != Method::POST {
        bail_r("only GET and POST are proxied")?;
    }
    let full = match q.0 {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let json_body = if body.is_empty() { None } else { Some(serde_json::from_slice(&body)?) };
    let r = app.gh.raw(method, &full, json_body).await?;
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, r.content_type.parse().unwrap_or(header::HeaderValue::from_static("text/plain")));
    Ok((StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY), h, r.body).into_response())
}

/// Strict allowlist: plain characters only (so nothing like `%2e%2e` can be
/// re-decoded into `..` by the URL parser), no dot segments, and only the
/// workflow/run/job APIs — not runners, secrets or variables.
fn proxy_path_ok(path: &str, repos: &[String]) -> bool {
    path.chars().all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
        && !path.split('/').any(|seg| seg == "." || seg == "..")
        && repos.iter().any(|r| {
            path.strip_prefix(&format!("repos/{r}/actions/"))
                .is_some_and(|rest| rest == "runs" || ["workflows", "runs/", "jobs/"].iter().any(|p| rest.starts_with(p)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_allowlist() {
        let repos = vec!["Bunty9/kiln".to_string()];
        let ok = |p: &str| proxy_path_ok(p, &repos);
        assert!(ok("repos/Bunty9/kiln/actions/runs"));
        assert!(ok("repos/Bunty9/kiln/actions/runs/123/jobs"));
        assert!(ok("repos/Bunty9/kiln/actions/workflows/ci.yml/dispatches"));
        assert!(ok("repos/Bunty9/kiln/actions/jobs/9/logs"));
        assert!(!ok("repos/Bunty9/kiln/actions/runners/generate-jitconfig"));
        assert!(!ok("repos/Bunty9/kiln/actions/secrets"));
        assert!(!ok("repos/Bunty9/kiln/actions/runs/../../../other/x/actions/runs"));
        assert!(!ok("repos/Bunty9/kiln/actions/runs/%2e%2e/%2e%2e"));
        assert!(!ok("repos/Bunty9/kiln-evil/actions/runs"));
        assert!(!ok("repos/Other/repo/actions/runs"));
    }

    #[test]
    fn tagged_devices_never_default_allowed() {
        let owner = || Some("me@x.com".to_string());
        assert!(peer_allowed(&[], owner(), "ME@x.com"));
        assert!(!peer_allowed(&[], owner(), TAGGED));
        assert!(!peer_allowed(&[], Some(TAGGED.into()), TAGGED));
        assert!(!peer_allowed(&[], None, "me@x.com"));
        assert!(peer_allowed(&[TAGGED.into()], owner(), TAGGED));
        assert!(!peer_allowed(&["a@x.com".into()], owner(), "me@x.com"));
    }

    #[test]
    fn host_header() {
        assert!(host_ok(Some("100.73.48.98:7878")));
        assert!(host_ok(Some("[fd7a:115c:a1e0::7001:307a]:7878")));
        assert!(host_ok(Some("ryzen7:7878")));
        assert!(host_ok(Some("ryzen7.tailedf5ce.ts.net:8443")));
        assert!(host_ok(Some("localhost:7878")));
        assert!(!host_ok(Some("evil.example.com:7878")));
        assert!(!host_ok(Some("evil.example.com")));
        assert!(!host_ok(None));
    }

    #[test]
    fn key_compare() {
        let _ = KEY.set("a".repeat(48));
        assert!(key_ok(Some(&"a".repeat(48))));
        assert!(!key_ok(Some(&"a".repeat(47))));
        assert!(!key_ok(Some(&"b".repeat(48))));
        assert!(!key_ok(None));
    }
    #[test]
    fn tailnet_ranges() {
        assert!(is_tailnet("100.73.48.98".parse().unwrap()));
        assert!(is_tailnet("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet("192.168.1.6".parse().unwrap()));
        assert!(is_tailnet("fd7a:115c:a1e0::7001:307a".parse().unwrap()));
        assert!(!is_tailnet("fe80::1".parse().unwrap()));
    }
}
