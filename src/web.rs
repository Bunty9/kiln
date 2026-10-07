//! Dashboard + JSON API. Reachable only from loopback and the tailnet.

use crate::{App, Config, mirror, now, platform, update, vm};
use anyhow::{Context, anyhow};
use axum::{
    Extension, Json, Router,
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
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
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
        .route("/", get(|| async { Html(PAGE.as_str()) }))
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(sw))
        .route("/icon.svg", get(|| async { icon_file("icon.svg") }))
        .route("/icons/{name}", get(|Path(name): Path<String>| async move { icon_file(&name) }))
        .route("/api/state", get(state))
        .route("/api/host", get(|| async { Json(crate::host::recent(usize::MAX)) }))
        .route("/api/config", post(set_config))
        .route("/api/token", post(set_token))
        .route("/api/app", post(app_manual).delete(app_remove))
        .route("/api/app/manifest", post(app_manifest))
        .route("/api/app/convert", post(app_convert))
        .route("/api/app/refresh", post(app_refresh))
        .route("/api/doctor", get(doctor))
        .route("/api/log", get(log))
        .route("/api/vms/{id}/kill", post(kill))
        .route("/api/vms/{id}/release", post(release))
        .route("/api/cache/clear", post(cache_clear))
        .route("/api/onboard", get(onboard))
        .route("/api/onboard/hello", post(onboard_hello))
        .route("/api/bake", post(bake))
        .route("/api/update", get(update_get))
        .route("/api/update/check", post(update_check))
        .route("/api/update/apply", post(update_apply))
        .route("/api/update/cancel", post(update_cancel))
        .route("/api/tailscale", get(ts_status))
        .route("/api/tailscale/netcheck", get(ts_netcheck))
        .route("/api/tailscale/ping", post(ts_ping))
        .route("/api/tailscale/serve", post(ts_serve))
        .route("/api/gh/{*path}", any(gh_proxy))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("bind {addr}"))?;
    let sock = app.data.join("serve.sock");
    // Without the socket (e.g. a KILN_DATA path past the ~108-byte unix socket limit) kiln still
    // serves; HTTPS via tailscale serve then proxies to loopback, where the API needs the key.
    match bind_serve_socket(&sock) {
        Ok(unix) => {
            let _ = SERVE_SOCKET.set(true);
            tracing::info!("dashboard on http://{addr} and {} (for tailscale serve)", sock.display());
            tokio::try_join!(
                axum::serve(listener, router.clone().into_make_service_with_connect_info::<Via>()).into_future(),
                axum::serve(unix, router.into_make_service_with_connect_info::<Via>()).into_future(),
            )?;
        }
        Err(e) => {
            tracing::warn!("no tailscale serve socket at {}: {e:#}; HTTPS will need the dashboard key", sock.display());
            tracing::info!("dashboard on http://{addr}");
            axum::serve(listener, router.into_make_service_with_connect_info::<Via>()).await?;
        }
    }
    Ok(())
}

/// Whether `<data>/serve.sock` is listening (set once at startup).
static SERVE_SOCKET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// The socket `tailscale serve` proxies to. Mode 0600: tailscaled (root) can connect,
/// other local users can't, and job VMs (QEMU NAT) can't reach a unix socket at all.
/// Bound in a private directory and then moved into place, so it is never reachable
/// with looser permissions; a stale socket from a previous run is replaced.
fn bind_serve_socket(path: &std::path::Path) -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let tmp = path.with_extension("d");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::DirBuilder::new().mode(0o700).create(&tmp)?;
    let inner = tmp.join("s");
    let bound = (|| {
        let l = tokio::net::UnixListener::bind(&inner)?;
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&inner, path)?;
        anyhow::Ok(l)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    bound
}

/// How a connection reached kiln: the TCP listener, or the unix socket only
/// `tailscale serve` (tailscaled, as root) can connect to.
#[derive(Clone, Copy)]
enum Via {
    Tcp(SocketAddr),
    Serve,
}
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::TcpListener>> for Via {
    fn connect_info(s: axum::serve::IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Via::Tcp(*s.remote_addr())
    }
}
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::UnixListener>> for Via {
    fn connect_info(_: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        Via::Serve
    }
}

/// Who a request says it is, before the Tailscale lookups in `admit`.
#[derive(Debug, PartialEq)]
enum Claim {
    /// From the box itself, or a serve request from no tailnet address: the API needs the key.
    Local,
    /// A tailnet address (TCP, or a serve request without a login: a tagged node): `tailscale whois`.
    Peer(IpAddr),
    /// Through `tailscale serve`: the login tailscaled vouches for, and the address it saw.
    /// Cross-checked with `tailscale whois` of that address.
    Login(String, IpAddr),
    /// Refused outright.
    Outside(&'static str),
}

/// `login`, `fwd_for` and `funnel` are the `Tailscale-User-Login`, `X-Forwarded-For` and
/// `Tailscale-Funnel-Request` headers. They mean something only on the serve socket, where
/// tailscaled has replaced whatever the client sent; on TCP anyone can set them.
fn claim(via: Via, login: Option<&str>, fwd_for: Option<&str>, funnel: bool) -> Claim {
    match via {
        Via::Tcp(peer) => {
            let ip = peer.ip().to_canonical();
            if ip.is_loopback() {
                Claim::Local
            } else if is_tailnet(ip) {
                Claim::Peer(ip)
            } else {
                // LAN and internet sources are refused whatever Tailscale's state:
                // over plain HTTP they could otherwise be asked for the dashboard key.
                Claim::Outside("kiln only answers on the tailnet")
            }
        }
        Via::Serve if funnel => Claim::Outside("kiln does not answer through Tailscale Funnel"),
        // No login: a tagged node (or this machine), identified like a TCP peer. No tailnet source: local.
        Via::Serve => match (login.filter(|l| !l.is_empty()), fwd_for.and_then(|f| f.parse::<IpAddr>().ok()).map(|ip| ip.to_canonical())) {
            (Some(l), Some(ip)) if is_tailnet(ip) => Claim::Login(l.to_string(), ip),
            (None, Some(ip)) if is_tailnet(ip) => Claim::Peer(ip),
            _ => Claim::Local,
        },
    }
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
    let out = tailscale(&["whois", "--json", &ip.to_string()]).await.inspect_err(|e| tracing::warn!("tailscale whois {ip}: {e:#}")).ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let who = (v["UserProfile"]["LoginName"].as_str()?.to_string(), v["Node"]["StableID"].as_str()?.to_string());
    WHOIS.lock().unwrap().insert(ip, (who.clone(), now()));
    Some(who)
}

/// This machine's own tailnet IPs and the login that owns it, from
/// `tailscale status`. Refreshed every 5 minutes, or sooner for an unknown address.
#[derive(Clone, Default)]
struct SelfInfo {
    ips: Vec<IpAddr>,
    node: Option<String>,
    owner: Option<String>,
    /// Last successful read.
    at: u64,
    /// Last attempt: `tailscale status` runs at most every 10 s.
    tried: u64,
}
static SELF: LazyLock<Mutex<SelfInfo>> = LazyLock::new(Mutex::default);

fn refresh_due(info: &SelfInfo, now: u64, max_age: u64) -> bool {
    now.saturating_sub(info.tried) >= 10 && now.saturating_sub(info.at) >= max_age
}

/// `max_age`: 300 normally; 10 when a request comes from an address not in the cached
/// list, which may be this box's own after its addresses changed.
async fn self_info(max_age: u64) -> SelfInfo {
    let cached = {
        let mut s = SELF.lock().unwrap();
        if !refresh_due(&s, now(), max_age) {
            return s.clone();
        }
        s.tried = now();
        s.clone()
    };
    let Ok(out) =
        tailscale(&["status", "--json"]).await.inspect_err(|e| tracing::warn!("tailscale status: {e:#}; keeping the last known addresses"))
    else {
        return cached;
    };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let ips = v["Self"]["TailscaleIPs"].as_array().into_iter().flatten().filter_map(|ip| ip.as_str()?.parse().ok()).collect();
    let uid = v["Self"]["UserID"].to_string();
    let owner = v["User"][uid.as_str()]["LoginName"].as_str().map(String::from);
    let node = v["Self"]["ID"].as_str().map(String::from);
    let info = SelfInfo { ips, node, owner, at: now(), tried: now() };
    *SELF.lock().unwrap() = info.clone();
    info
}

/// Secret for requests that originate on this machine (see `guard`).
/// Generated once, stored next to the config, mode 0600.
static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn load_key(data: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Read;
    let path = data.join("dashboard.key");
    let key = match std::fs::read_to_string(&path) {
        Ok(k) if k.trim().len() >= 32 => k.trim().to_string(),
        _ => {
            let mut raw = [0u8; 24];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
            let k: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            crate::app_auth::write_private(&path, k.as_bytes())?;
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
/// - Tailnet peers whose login is in `allowed_users` (default: the owner of
///   this machine, so shared-in nodes are out). Over TCP the login comes from
///   `tailscale whois`; through `tailscale serve` (the unix socket) from the
///   `Tailscale-User-Login` header tailscaled sets.
/// - Requests from this machine itself only with the dashboard key. Job VMs
///   reach the host through QEMU's NAT and arrive as loopback or as this
///   host's own tailnet IP, so a local source address proves nothing.
async fn guard(State(app): S, ConnectInfo(via): ConnectInfo<Via>, req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut r = admit(app, via, req, next).await;
    let h = r.headers_mut();
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, CSP.clone());
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // The GitHub proxy passes GitHub's content types through: never let a browser guess.
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=(), payment=()"));
    // The page is embedded in the binary: no-cache so a redeploy shows up on reload.
    // Icons set their own (longer) Cache-Control; the API is always no-store.
    if api || !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(if api { "no-store" } else { "no-cache" }));
    }
    r
}

/* ---------- installable app (PWA): manifest, service worker, icons ---------- */

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The dashboard, stamped with the version that serves it: a page the service worker kept
/// from an older kiln sees the server's version differ and reloads (see doPoll).
static PAGE: LazyLock<String> = LazyLock::new(|| include_str!("dashboard.html").replace("{{KILN_VERSION}}", VERSION));

/// Content-Security-Policy for every response. Scripts run only if they are the page's own
/// inline blocks (by hash, computed from the embedded page), so an injected `<script>` or
/// handler never runs even if some string escaped `esc()`. Forms post only to GitHub (the
/// App manifest flow); nothing else leaves the origin.
static CSP: LazyLock<HeaderValue> = LazyLock::new(|| HeaderValue::from_str(&csp(&PAGE)).expect("CSP is a valid header value"));

fn csp(page: &str) -> String {
    use base64::Engine;
    let hashes: Vec<String> = page
        .split("<script>")
        .skip(1)
        .filter_map(|s| s.split_once("</script>"))
        .map(|(js, _)| {
            let d = ring::digest::digest(&ring::digest::SHA256, js.as_bytes());
            format!("'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(d.as_ref()))
        })
        .collect();
    format!(
        "default-src 'none'; script-src {}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
         manifest-src 'self'; worker-src 'self'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'",
        hashes.join(" ")
    )
}

/// Dashboard dark background; the installed window's title bar and splash.
const THEME: &str = "#0A0A0A";

fn manifest_json(version: &str) -> Value {
    let icon = |file: &str, size: &str, purpose: &str| json!({ "src": format!("/icons/{file}?v={version}"), "sizes": size, "type": "image/png", "purpose": purpose });
    let shortcut = |name: &str, url: &str| json!({ "name": name, "url": url });
    json!({
        "id": "/",
        "name": "kiln",
        "short_name": "kiln",
        "description": "One fresh VM per GitHub Actions job, on your own box.",
        "start_url": "/#/overview",
        "scope": "/",
        "display": "standalone",
        "background_color": THEME,
        "theme_color": THEME,
        "categories": ["developer"],
        "icons": [
            { "src": format!("/icon.svg?v={version}"), "sizes": "any", "type": "image/svg+xml", "purpose": "any" },
            icon("icon-192.png", "192x192", "any"),
            icon("icon-512.png", "512x512", "any"),
            icon("icon-maskable-512.png", "512x512", "maskable"),
        ],
        "shortcuts": [shortcut("Jobs", "/#/jobs"), shortcut("Repos", "/#/repos"), shortcut("Settings", "/#/settings/capacity")],
    })
}

async fn manifest() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/manifest+json")], manifest_json(VERSION).to_string())
}

/// The worker's cache name carries the version, so a new release installs a new worker.
fn sw_source(version: &str) -> String {
    include_str!("../assets/sw.js").replace("__KILN_VERSION__", version)
}

async fn sw() -> impl IntoResponse {
    let h = [
        (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
        (header::CACHE_CONTROL, "no-cache"),
        (header::HeaderName::from_static("service-worker-allowed"), "/"),
    ];
    (h, sw_source(VERSION))
}

fn icon_file(name: &str) -> Response {
    let (ty, body): (&str, &'static [u8]) = match name {
        "icon.svg" => ("image/svg+xml", include_bytes!("../assets/icon.svg")),
        "icon-192.png" => ("image/png", include_bytes!("../assets/icon-192.png")),
        "icon-512.png" => ("image/png", include_bytes!("../assets/icon-512.png")),
        "icon-maskable-512.png" => ("image/png", include_bytes!("../assets/icon-maskable-512.png")),
        "apple-touch-icon.png" => ("image/png", include_bytes!("../assets/apple-touch-icon.png")),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // The manifest links them with ?v=<version>; a week is plenty for the unversioned favicon links.
    ([(header::CONTENT_TYPE, ty), (header::CACHE_CONTROL, "public, max-age=604800")], body).into_response()
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

/// None: local, needs the key. Some(login): a tailnet user (None if unknown: refused).
/// `who` is `tailscale whois` of the claim's address.
fn identify(claim: Claim, me: &SelfInfo, who: Option<Who>) -> Option<Option<String>> {
    // Fail closed: if we can't tell our own addresses or node apart from a
    // peer (tailscale down, CLI error), treat the request as local. tailscaled
    // names this box's owner for traffic from the box itself (a job VM
    // through QEMU's NAT, too), so a login from our own IP or node is local.
    let ours = |ip: &IpAddr| {
        me.ips.is_empty()
            || me.node.is_none()
            || me.ips.contains(ip)
            || who.as_ref().is_some_and(|(_, node)| Some(node) == me.node.as_ref())
    };
    match claim {
        Claim::Outside(_) | Claim::Local => None,
        Claim::Peer(ip) | Claim::Login(_, ip) if ours(&ip) => None,
        Claim::Peer(_) => Some(who.map(|(l, _)| l)),
        // tailscaled's header and whois must name the same user.
        Claim::Login(login, _) => Some(who.filter(|(l, _)| *l == login).map(|(l, _)| l)),
    }
}

/// What `tailscale serve` does with kiln's socket.
#[derive(Clone, Debug, PartialEq)]
enum ServeUse {
    /// No handler targets it.
    Unused,
    /// Only tailscaled's HTTPS reverse proxy, tailnet-only: its identity headers can be trusted.
    Proxied,
    /// Something lets a client write its own headers (raw TCP forward, Funnel), or the
    /// config could not be read: never trusted.
    Unsafe(String),
}

/// Judge `tailscale serve status --json` for `sock`. Shape (ipn.ServeConfig):
/// `{"TCP": {"<port>": {"HTTPS": true} | {"TCPForward": "<target>", "TerminateTLS": "<host>"}},
///   "Web": {"<host>:<port>": {"Handlers": {"<path>": {"Proxy": "<target>"}}}},
///   "AllowFunnel": {"<host>:<port>": true}, "Services": {"<svc>": {..}}, "Foreground": {"<id>": {..}}}`.
fn serve_use(status: &Value, sock: &std::path::Path) -> ServeUse {
    serve_use_in(status, status, sock)
}

fn serve_use_in(cfg: &Value, root: &Value, sock: &std::path::Path) -> ServeUse {
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    // "unix:/p", "unix:///p" or a bare path; symlinks resolved when they exist.
    let to_us = |v: &Value| {
        v.as_str().is_some_and(|t| {
            let p = t.strip_prefix("unix:").unwrap_or(t);
            canon(std::path::Path::new(&format!("/{}", p.trim_start_matches('/')))) == canon(sock)
        })
    };
    let entries = |v: &Value| v.as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
    let mut found = ServeUse::Unused;
    for (port, h) in entries(&cfg["TCP"]) {
        if to_us(&h["TCPForward"]) {
            return ServeUse::Unsafe(format!("TCP port {port} forwards raw connections to it"));
        }
    }
    for (hp, web) in entries(&cfg["Web"]) {
        for (_, h) in entries(&web["Handlers"]) {
            if !to_us(&h["Proxy"]) {
                continue;
            }
            if cfg["AllowFunnel"][&hp] == true || root["AllowFunnel"][&hp] == true {
                return ServeUse::Unsafe(format!("{hp} is open to the internet with Funnel"));
            }
            found = ServeUse::Proxied;
        }
    }
    for (_, c) in entries(&cfg["Services"]).into_iter().chain(entries(&cfg["Foreground"])) {
        match serve_use_in(&c, root, sock) {
            ServeUse::Unused => {}
            ServeUse::Proxied => found = ServeUse::Proxied,
            bad => return bad,
        }
    }
    found
}

/// `tailscale serve status`, judged; Err when it can't be read.
async fn serve_status(sock: &std::path::Path) -> Result<ServeUse, String> {
    let o = tailscale(&["serve", "status", "--json"]).await.map_err(|e| format!("{e:#}"))?;
    if !o.status.success() {
        return Err(format!("`tailscale serve status` failed: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    let v = serde_json::from_slice::<Value>(&o.stdout).map_err(|e| format!("unreadable `tailscale serve status --json`: {e}"))?;
    Ok(serve_use(&v, sock))
}

/// The verdict on the serve config and when it was read; cleared when kiln changes it.
static SERVE_CHECK: Mutex<Option<(ServeUse, u64)>> = Mutex::new(None);

/// Cached `serve_status`: 60 s, or 10 s while unused (a socket request then means serve was
/// just set up). Unreadable counts as unsafe.
async fn serve_check(sock: &std::path::Path) -> ServeUse {
    let prev = SERVE_CHECK.lock().unwrap().clone();
    if let Some((v, at)) = &prev
        && now().saturating_sub(*at) < if *v == ServeUse::Unused { 10 } else { 60 }
    {
        return v.clone();
    }
    let v = serve_status(sock).await.unwrap_or_else(ServeUse::Unsafe);
    if let ServeUse::Unsafe(why) = &v
        && prev.as_ref().map(|p| &p.0) != Some(&v)
    {
        tracing::warn!("tailscale serve config exposes kiln's socket unsafely ({why}): requests through it need the dashboard key");
    }
    *SERVE_CHECK.lock().unwrap() = Some((v.clone(), now()));
    v
}

/// Doctor's (ok, detail); None when tailscale serve can't be read (the tailscale check covers that).
pub async fn serve_doctor(data: &std::path::Path) -> Option<(bool, String)> {
    Some(match serve_status(&data.join("serve.sock")).await.ok()? {
        ServeUse::Unsafe(why) => {
            (false, format!("tailscale serve config exposes kiln's socket unsafely: {why}; never TCP-forward or funnel serve.sock"))
        }
        ServeUse::Proxied => (true, "HTTPS proxies to kiln's socket; tailnet identities trusted".into()),
        ServeUse::Unused => (true, "kiln's socket is not served".into()),
    })
}

/// Admission, then the handler. Admitted API writes go to the audit log; refused ones only to
/// kiln's log (see `audited`).
async fn admit(app: Arc<App>, via: Via, req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let (admitted, who) = admission(&app, via, req).await;
    let admitted_ok = admitted.is_ok();
    let resp = match admitted {
        Ok(req) => next.run(req).await,
        Err(denied) => denied,
    };
    if audited(&method, &path, admitted_ok) {
        let mut e =
            json!({ "actor": who.actor, "from": who.from, "method": method.as_str(), "path": path, "status": resp.status().as_u16() });
        if let Some(n) = resp.extensions().get::<crate::audit::Note>() {
            e["note"] = n.0.clone().into();
        }
        crate::audit::record(&app.data, e);
    } else if audited(&method, &path, true) {
        tracing::info!(target: "audit", "audit: refused {method} {path} from {} ({}): {}", who.from, who.actor, resp.status());
    }
    resp
}

/// Does this request go to audit.log? API writes that passed admission. Refusals do not: a
/// job VM can send them in a loop, and must not roll the real entries out of the file.
fn audited(method: &Method, path: &str, admitted: bool) -> bool {
    admitted && path.starts_with("/api/") && method != Method::GET
}

/// Who made a request, as far as admission got: for the audit log.
struct Requester {
    /// Tailnet login, "local" (loopback or the box itself, with the key), or for refusals
    /// "local, without the key" or "unknown".
    actor: String,
    /// Source address, or "tailscale serve" until the request names a tailnet address.
    from: String,
}

/// Ok: the request may proceed. Err: the refusal to send. And who asked, either way.
async fn admission(app: &App, via: Via, mut req: Request) -> (Result<Request, Response>, Requester) {
    let from = match via {
        Via::Tcp(peer) => peer.ip().to_canonical().to_string(),
        Via::Serve => "tailscale serve".into(),
    };
    let mut who = Requester { actor: "unknown".into(), from };
    let deny = |code: StatusCode, msg: &str, who: Requester| (Err((code, msg.to_string()).into_response()), who);
    // tailscaled sends `Host: localhost` to a unix socket and the name the browser
    // used in X-Forwarded-Host; put that back so the Host check and handlers see it.
    if matches!(via, Via::Serve)
        && let Some(fh) = req.headers().get("x-forwarded-host").cloned()
    {
        req.headers_mut().insert(header::HOST, fh);
    }
    // Owned copies: `req` (its body) is not Sync, so no borrows across awaits.
    let (host, csrf, key, claim) = {
        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).map(String::from);
        let funnel = req.headers().contains_key("tailscale-funnel-request");
        (h("host"), h("x-kiln"), h("x-kiln-key"), claim(via, h("tailscale-user-login").as_deref(), h("x-forwarded-for").as_deref(), funnel))
    };
    let api = req.uri().path().starts_with("/api/");
    let get = req.method() == Method::GET;
    if !host_ok(host.as_deref()) {
        return deny(StatusCode::FORBIDDEN, "unexpected Host header", who);
    }
    // Browsers can't add custom headers cross-origin without a CORS preflight
    // we never grant, so this blocks drive-by POSTs from other sites.
    if api && !get && csrf.is_none() {
        return deny(StatusCode::FORBIDDEN, "missing x-kiln header", who);
    }
    if let Claim::Outside(msg) = claim {
        return deny(StatusCode::FORBIDDEN, msg, who);
    }
    // The identity headers mean something only if tailscaled's web proxy is all that reaches the socket.
    let claim = if matches!(via, Via::Serve) && serve_check(&app.data.join("serve.sock")).await != ServeUse::Proxied {
        Claim::Local
    } else {
        claim
    };
    let ip = match claim {
        Claim::Peer(ip) | Claim::Login(_, ip) => Some(ip),
        _ => None,
    };
    if let Some(ip) = ip {
        who.from = ip.to_string();
    }
    let mut me = self_info(300).await;
    if let Some(ip) = ip
        && !me.ips.contains(&ip)
    {
        me = self_info(10).await;
    }
    let whois = match ip {
        Some(ip) => whois(ip).await,
        None => None,
    };
    let user = identify(claim, &me, whois);
    who.actor = match &user {
        None => "local".into(),
        Some(login) => login.clone().unwrap_or_else(|| "unknown".into()),
    };
    match user {
        None if api && !key_ok(key.as_deref()) => {
            who.actor = "local, without the key".into();
            deny(StatusCode::UNAUTHORIZED, "dashboard key required (see ~/.local/share/kiln/dashboard.key on the CI box)", who)
        }
        Some(login) if !login.as_deref().is_some_and(|l| peer_allowed(&app.cfg().allowed_users, me.owner.clone(), l)) => {
            deny(StatusCode::FORBIDDEN, "your tailnet identity is not allowed (allowed_users)", who)
        }
        _ => (Ok(req), who),
    }
}

async fn host_stats(app: &App) -> Value {
    json!({
        "load": platform::load_avg(),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "mem_total_mb": platform::mem_total_mb(),
        "mem_avail_mb": platform::mem_avail_mb(),
        "disk_free_gb": vm::disk_free_gb(&app.data).await,
        // A few, so a poll that lands between samples still gets every one.
        "samples": crate::host::recent(3),
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
    let rate = |(remaining, limit, reset): (u64, u64, u64)| json!({ "remaining": remaining, "limit": limit, "reset": reset });
    // App mode: the most constrained installation, plus each one's.
    poll["rate"] = app.gh.rate().map(rate).into();
    if app.gh.app().is_some() {
        poll["rates"] = app.gh.rates().into_iter().map(|(i, r)| (i.to_string(), rate(r))).collect::<serde_json::Map<_, _>>().into();
    }
    poll["paused_until"] = json!(app.gh.paused_until());
    Ok(Json(json!({
        "config": app.cfg(),
        // `runs-on` label for the default size: `label`, or `<label>-arm64` on an arm64 host.
        "job_label": app.cfg().job_label(),
        "token_set": app.gh.has_token(),
        "app": app_json(&app),
        "token_source": app.gh.source(),
        "token_expires": *app.gh.expires.lock().unwrap(),
        "token_saved": std::fs::metadata(app.data.join("token")).ok().filter(|_| app.gh.source() == "file").and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
        "poll": poll,
        "vms": vms,
        // 32 days covers the current month in any timezone.
        "usage": vm::usage_since(&app.data, now() / 86400 - 32),
        "image": vm::image_info(&app.data, app.gh.latest_cached(), &app.cfg()),
        "image_ready": vm::image_ready(&app.data),
        "baking": app.baking.load(std::sync::atomic::Ordering::Relaxed),
        "host": host_stats(&app).await,
        "version": env!("CARGO_PKG_VERSION"),
        "mirror": mirror::status_json(&app).await,
        "caches": vm::cache_stats(&app.data, &app.repos()),
        "update": update::compact(&app),
    })))
}

/// The `app` object of /api/state (null in token mode).
fn app_json(app: &App) -> Value {
    let Some(a) = app.gh.app() else { return Value::Null };
    json!({
        "id": a.id,
        "slug": a.slug,
        "html_url": a.html_url,
        "owner": *a.owner.read().unwrap(),
        "accounts": app.cfg().app_accounts,
        "repos": a.names.read().unwrap().clone(),
        "discovered_at": a.discovered_at.load(std::sync::atomic::Ordering::Relaxed),
        "error": a.error.lock().unwrap().clone(),
        "notes": a.notes.lock().unwrap().clone(),
    })
}

async fn doctor(State(app): S) -> R<Json<Value>> {
    Ok(Json(json!({ "checks": vm::doctor(&app, false).await })))
}

async fn set_config(State(app): S, Json(c): Json<Config>) -> R<(Extension<crate::audit::Note>, Json<Value>)> {
    let restart = RUNNING_LISTEN.get().is_some_and(|l| *l != c.listen);
    let to_filtered = c.egress == "filtered" && app.cfg().egress != "filtered";
    let changed = crate::audit::config_changes(&serde_json::to_value(app.cfg())?, &serde_json::to_value(&c)?);
    app.save_cfg(c)?;
    if to_filtered {
        // Probe now so the dashboard shows the result and the scheduler has it cached.
        let a = app.clone();
        tokio::spawn(async move {
            let _ = vm::egress_ready(&a, true).await;
        });
    }
    Ok((Extension(crate::audit::Note(changed)), Json(json!({ "restart_required": restart }))))
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
    if !vm::release_hold(&app, &id, None) {
        bail_r("that VM is not held")?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RepoBody {
    repo: String,
}
async fn cache_clear(State(app): S, Json(b): Json<RepoBody>) -> R<(StatusCode, Extension<crate::audit::Note>)> {
    vm::clear_cache(&app, &b.repo)?;
    Ok((StatusCode::NO_CONTENT, Extension(crate::audit::Note(b.repo))))
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
    let (pr_url, branch) = app.gh.hello_pr(repo, &cfg.job_label(), t).await?;
    let _g = SAVE.lock().unwrap();
    let mut m = hello_prs(&app.data);
    m.insert(repo.clone(), json!({ "pr_url": pr_url, "at": t }));
    // Best effort: the PR exists either way.
    let _ = std::fs::write(app.data.join("onboard.json"), serde_json::to_vec(&m)?);
    Ok(Json(json!({ "pr_url": pr_url, "branch": branch })))
}

async fn bake(State(app): S) -> R<StatusCode> {
    use std::sync::atomic::Ordering::SeqCst;
    if app.baking.load(SeqCst) {
        return Err(anyhow!("already baking").into());
    }
    // vm::bake refuses too; checked here so the dashboard gets the reason.
    if let Some(why) = vm::bake_refused(app.draining.load(SeqCst), app.stopping.load(SeqCst)) {
        return Err(anyhow!("{why}").into());
    }
    tokio::spawn(async move {
        if let Err(e) = vm::bake(app).await {
            tracing::error!("bake failed: {e:#}");
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn update_get(State(app): S) -> Json<Value> {
    Json(update::json(&app))
}

fn conflict(msg: &str) -> Response {
    (StatusCode::CONFLICT, msg.to_string()).into_response()
}

/// Check now; a failed check is reported in the returned status, not as an HTTP error.
async fn update_check(State(app): S) -> Response {
    if !update::check(&app).await {
        return conflict("an update check or update is already running");
    }
    Json(update::json(&app)).into_response()
}

/// Download, verify, drain and restart into the latest release (progress in GET /api/update).
async fn update_apply(State(app): S) -> Response {
    if !update::start(&app, true) {
        return conflict("an update check or update is already running");
    }
    (StatusCode::ACCEPTED, Json(update::json(&app))).into_response()
}

/// Stop a draining update and resume launching.
async fn update_cancel(State(app): S) -> Response {
    if !update::cancel(&app) {
        return conflict("only an update that is still draining can be cancelled");
    }
    Json(update::json(&app)).into_response()
}

/// Bound on a tailscale CLI call; `tailscale serve` gets `SERVE_LIMIT`.
const TS_LIMIT: Duration = Duration::from_secs(20);
const SERVE_LIMIT: Duration = Duration::from_secs(15);

/// What `ts_serve` says when the tailnet has HTTPS certificates off.
const NO_CERTS: &str = "This tailnet can't issue HTTPS certificates. Enable DNS › HTTPS Certificates in the Tailscale admin console (https://login.tailscale.com/admin/dns), then try again.";

/// The tailscale CLI, bounded by `TS_LIMIT`.
pub async fn tailscale(args: &[&str]) -> anyhow::Result<std::process::Output> {
    bounded(platform::tailscale(), args, TS_LIMIT).await
}

/// Run `prog` with stdin closed, in its own process group, for at most `limit`. On timeout,
/// or when the caller is dropped (the HTTP client went away), the whole group is SIGKILLed:
/// `tailscale serve --https` on a tailnet without certs prints an enable-HTTPS URL and waits
/// forever, and a forked helper that still holds stdout would keep `output()` waiting even
/// after the direct child is gone, which `kill_on_drop` alone does not reach.
async fn bounded(prog: &str, args: &[&str], limit: Duration) -> anyhow::Result<std::process::Output> {
    let child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("running {prog}"))?;
    let mut group = KillGroup(child.id());
    let out = tokio::time::timeout(limit, child.wait_with_output()).await;
    match out {
        Ok(r) => {
            group.0 = None;
            Ok(r.with_context(|| format!("running {prog}"))?)
        }
        Err(_) => Err(anyhow!("`{prog} {}` did not finish within {} s, so kiln stopped it", args.join(" "), limit.as_secs())),
    }
}

/// SIGKILLs process group `.0` when dropped, unless disarmed with `None`.
struct KillGroup(Option<u32>);
impl Drop for KillGroup {
    fn drop(&mut self) {
        if let Some(pg) = self.0 {
            let bin = kill_bin(|p| std::path::Path::new(p).exists());
            let r = std::process::Command::new(bin)
                .args(["-KILL", "--", &format!("-{pg}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match r {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("`{bin} -KILL -{pg}` exited with {s}; its processes may linger"),
                Err(e) => tracing::warn!("could not run `{bin}` to stop process group {pg}: {e}"),
            }
        }
    }
}

/// The service PATH may lack `kill`, so try the absolute paths first.
fn kill_bin(exists: impl Fn(&str) -> bool) -> &'static str {
    ["/usr/bin/kill", "/bin/kill"].into_iter().find(|p| exists(p)).unwrap_or("kill")
}

/// `tailscale status --json` of a running node whose tailnet issues no HTTPS certificates:
/// `CertDomains` lists the names it may get certs for, and is null when DNS › HTTPS
/// Certificates is off.
pub fn no_certs(status: &Value) -> bool {
    status["BackendState"] == "Running" && status["CertDomains"].as_array().is_none_or(|a| a.is_empty())
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
/// cert. 8443 so we never disturb whatever already lives on :443. It proxies to
/// the unix socket, where `admit` trusts tailscaled's identity headers.
async fn ts_serve(State(app): S, Json(b): Json<ServeBody>) -> R<Json<Value>> {
    let target = if SERVE_SOCKET.get() == Some(&true) {
        format!("unix:{}", app.data.join("serve.sock").display())
    } else {
        // Fallback: loopback proxy (the API then needs the dashboard key, as before 0.2.2).
        let port = RUNNING_LISTEN.get().and_then(|l| l.rsplit_once(':')).map_or("7878", |(_, p)| p).to_string();
        format!("http://127.0.0.1:{port}")
    };
    if b.on
        && let Ok(o) = tailscale(&["status", "--json"]).await
        && no_certs(&serde_json::from_slice(&o.stdout).unwrap_or_default())
    {
        bail_r(NO_CERTS)?;
    }
    let args: Vec<&str> = if b.on { vec!["serve", "--bg", "--https=8443", &target] } else { vec!["serve", "--https=8443", "off"] };
    let out = bounded(platform::tailscale(), &args, SERVE_LIMIT).await;
    // Even a timed-out attempt may have changed the config.
    *SERVE_CHECK.lock().unwrap() = None;
    let out = out?;
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
    /// The page was loaded over https (tailscale serve); the host comes from the Host header.
    #[serde(default)]
    https: bool,
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
    let state = app.app_states.lock().unwrap().issue(now()).context("saving the setup state (app_states.json)")?;
    let base = if org.is_empty() {
        "https://github.com/settings/apps/new".to_string()
    } else {
        format!("https://github.com/organizations/{org}/settings/apps/new")
    };
    Ok(Json(json!({
        "url": format!("{base}?state={state}"),
        "manifest": crate::app_auth::manifest(&crate::app_auth::origin(host, b.https), name.trim()),
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
    if !app.app_states.lock().unwrap().valid(&b.state, now()) {
        bail_r("this setup link is unknown, already used or older than an hour: start again")?;
    }
    if b.code.is_empty() || !b.code.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail_r("bad code")?;
    }
    // The state is used up only once GitHub has handed over the App: a network error
    // or a 5xx leaves it valid so the same code can be retried.
    let v = app.gh.manifest_conversion(&b.code).await?;
    // Best effort: the App exists now whatever happens to the state file.
    let _ = app.app_states.lock().unwrap().consume(&b.state);
    let id = v["id"].as_u64().ok_or_else(|| anyhow!("GitHub returned no app id"))?;
    let (slug, url, pem) = (v["slug"].as_str().unwrap_or(""), v["html_url"].as_str().unwrap_or(""), v["pem"].as_str().unwrap_or(""));
    // Empty if GitHub ever leaves it out: discovery then asks GET /app once.
    let owner = v["owner"]["login"].as_str().unwrap_or("");
    // GitHub's code is single use: if saving fails, this response held the only copy of
    // the key, so say how to recover instead of inviting a second App.
    let a = crate::app_auth::save(&app.data, id, slug, url, owner, pem).map_err(|e| {
        anyhow!(
            "GitHub created the App ({url}) but kiln could not save its key: {e:#}. Fix that, then open the App on github.com, generate a private key, and use 'Use an existing App' with App ID {id}."
        )
    })?;
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
    let owner = me["owner"]["login"].as_str().unwrap_or("");
    let a = crate::app_auth::save(&app.data, b.id, slug, url, owner, &b.pem)?;
    app.gh.set_app(Some(Arc::new(a)));
    let _ = app.gh.discover().await;
    Ok(Json(json!({ "slug": slug, "html_url": url })))
}

/// Run discovery now (after installing the App, or changing `app_accounts`). Returns the
/// `app` object of /api/state; a failure is in its `error`, and the last map is kept.
async fn app_refresh(State(app): S) -> R<Json<Value>> {
    if app.gh.app().is_none() {
        bail_r("not in GitHub App mode: create or add the App in Settings › GitHub first")?;
    }
    let _ = app.gh.discover_now().await;
    Ok(Json(app_json(&app)))
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
    if method != Method::GET && (method != Method::POST || !proxy_post_ok(&path)) {
        bail_r("only GET, and POST to rerun or cancel a run or dispatch a workflow, are proxied")?;
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

/// The writes the dashboard makes through the proxy: rerun or cancel a run, dispatch a
/// workflow. Not run approvals, deployment reviews or log deletion.
fn proxy_post_ok(path: &str) -> bool {
    let mut seg = path.split('/').skip(4);
    match (seg.next(), seg.next(), seg.next(), seg.next()) {
        (Some("runs"), Some(id), Some("rerun" | "rerun-failed-jobs" | "cancel"), None) => {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
        }
        (Some("workflows"), Some(_), Some("dispatches"), None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admitted_writes_are_audited() {
        assert!(audited(&Method::POST, "/api/config", true));
        assert!(audited(&Method::DELETE, "/api/app", true));
        assert!(!audited(&Method::POST, "/api/config", false), "refusals stay out of audit.log");
        assert!(!audited(&Method::GET, "/api/state", true));
        assert!(!audited(&Method::POST, "/", true));
    }

    #[test]
    fn proxy_writes() {
        assert!(proxy_post_ok("repos/o/n/actions/runs/123/rerun"));
        assert!(proxy_post_ok("repos/o/n/actions/runs/123/rerun-failed-jobs"));
        assert!(proxy_post_ok("repos/o/n/actions/runs/123/cancel"));
        assert!(proxy_post_ok("repos/o/n/actions/workflows/ci.yml/dispatches"));
        for p in [
            "repos/o/n/actions/runs/123/approve",
            "repos/o/n/actions/runs/123/pending_deployments",
            "repos/o/n/actions/runs/123/deployment_protection_rule",
            "repos/o/n/actions/runs/x/cancel",
            "repos/o/n/actions/runs//cancel",
            "repos/o/n/actions/runs/123/cancel/x",
            "repos/o/n/actions/runs",
            "repos/o/n/actions/workflows/ci.yml/enable",
        ] {
            assert!(!proxy_post_ok(p), "{p}");
        }
    }

    #[test]
    fn csp_hashes_every_inline_script() {
        let c = csp("<script>a()</script><p>x</p><script>\nb()\n</script>");
        // sha256("a()") and sha256("\nb()\n"), base64
        assert_eq!(c.matches("'sha256-").count(), 2);
        assert!(c.contains("script-src 'sha256-"));
        assert!(!c.contains("'unsafe-inline' ;") && !c.contains("script-src 'self'"));
        // the real page: one hash per inline block, and no stray `<script ` with attributes
        let real = CSP.to_str().unwrap();
        assert_eq!(real.matches("'sha256-").count(), PAGE.matches("<script").count());
        assert!(real.contains("frame-ancestors 'none'") && real.contains("default-src 'none'"));
    }

    #[test]
    fn kill_bin_prefers_absolute_paths() {
        assert_eq!(kill_bin(|_| true), "/usr/bin/kill");
        assert_eq!(kill_bin(|p| p == "/bin/kill"), "/bin/kill");
        assert_eq!(kill_bin(|_| false), "kill");
    }

    /// Processes whose argv mentions `marker`.
    fn alive(marker: &str) -> Vec<String> {
        platform::process_cmdlines().into_iter().map(|c| c.replace('\0', " ")).filter(|c| c.contains(marker)).collect()
    }

    /// Fake `tailscale` scripts that hang: each one's long-lived processes carry the
    /// script path in argv (`sh -c '…; :' "$0"`), so survivors can be found in /proc.
    #[tokio::test]
    async fn bounded_kills_the_whole_group() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kiln-fake-ts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hang = "sh -c 'sleep 1000; :' \"$0\"";
        for (name, body) in [
            // (a) blocks forever
            ("sleeps", hang.to_string()),
            // (b) exits at once, but a forked grandchild keeps stdout open
            ("forks", format!("{hang} &\necho started")),
            // (c) what `tailscale serve --https` does without certs
            ("url", format!("echo 'To enable, visit: https://login.tailscale.com/f/serve?node=x'\n{hang}")),
        ] {
            let f = dir.join(name);
            std::fs::write(&f, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            let t = std::time::Instant::now();
            let r = bounded(f.to_str().unwrap(), &["serve"], Duration::from_millis(300)).await;
            assert!(r.unwrap_err().to_string().contains("did not finish"), "{name}");
            assert!(t.elapsed() < Duration::from_secs(2), "{name} took {:?}", t.elapsed());
        }
        // SIGKILL is asynchronous: give the kernel a moment.
        let marker = dir.to_str().unwrap();
        for _ in 0..50 {
            if alive(marker).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(alive(marker), Vec::<String>::new());
        // stdin is closed: a CLI that reads it does not wait on kiln.
        let r = bounded("cat", &[], Duration::from_secs(2)).await.unwrap();
        assert!(r.status.success() && r.stdout.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn https_certs_preflight() {
        let st = |j: &str| no_certs(&serde_json::from_str(j).unwrap());
        // Shape seen on a tailnet with HTTPS certificates off (tailscale 1.102.4).
        assert!(st(r#"{"BackendState":"Running","CertDomains":null}"#));
        assert!(st(r#"{"BackendState":"Running","CertDomains":[]}"#));
        assert!(st(r#"{"BackendState":"Running"}"#));
        assert!(!st(r#"{"BackendState":"Running","CertDomains":["box.tail1234.ts.net"]}"#));
        // Not logged in: certs are not the problem, let the CLI say what is.
        assert!(!st(r#"{"BackendState":"NeedsLogin","CertDomains":null}"#));
        assert!(!no_certs(&Value::Null));
    }

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
        assert!(host_ok(Some("100.64.0.7:7878")));
        assert!(host_ok(Some("[fd7a:115c:a1e0::7001:307a]:7878")));
        assert!(host_ok(Some("ryzen7:7878")));
        assert!(host_ok(Some("box.example.ts.net:8443")));
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
    fn pwa_manifest_shape() {
        let m: Value = serde_json::from_str(&manifest_json("9.9.9").to_string()).unwrap();
        assert_eq!(m["name"], "kiln");
        assert_eq!(m["short_name"], "kiln");
        assert_eq!(m["start_url"], "/#/overview");
        assert_eq!(m["scope"], "/");
        assert_eq!(m["display"], "standalone");
        assert_eq!(m["theme_color"], THEME);
        assert_eq!(m["background_color"], THEME);
        assert_eq!(m["categories"], json!(["developer"]));
        let icons = m["icons"].as_array().unwrap();
        for i in icons {
            let src = i["src"].as_str().unwrap();
            assert!(src.ends_with("?v=9.9.9"), "{src} is not versioned");
            let file = src.trim_start_matches("/icons/").trim_start_matches('/').split('?').next().unwrap();
            assert_eq!(icon_file(file).status(), StatusCode::OK, "{src} is not served");
        }
        assert!(icons.iter().any(|i| i["purpose"] == "maskable"));
        for size in ["192x192", "512x512"] {
            assert!(icons.iter().any(|i| i["sizes"] == size && i["purpose"] == "any"));
        }
        let urls: Vec<_> = m["shortcuts"].as_array().unwrap().iter().map(|s| s["url"].as_str().unwrap()).collect();
        assert_eq!(urls, ["/#/jobs", "/#/repos", "/#/settings/capacity"]);
    }

    #[test]
    fn pwa_service_worker() {
        let js = sw_source("9.9.9");
        assert!(js.contains("'kiln-9.9.9'"));
        assert!(!js.contains("__KILN_VERSION__"));
        // The API is never answered from a cache.
        assert!(js.contains("u.pathname.startsWith('/api/')) return;"));
        let shell = js.lines().find(|l| l.starts_with("const SHELL")).unwrap();
        assert!(shell.contains("'/'") && !shell.contains("/api"), "precache list: {shell}");
        assert!(js.contains("skipWaiting") && js.contains("clients.claim"));
        // Only navigations get the cached shell: a fetch('/') probe (the offline page) reaches kiln.
        assert!(js.contains("u.pathname !== '/' && SHELL.includes(u.pathname)"));
    }

    #[test]
    fn page_carries_the_server_version() {
        assert!(PAGE.contains(&format!(r#"<meta name="kiln-version" content="{VERSION}">"#)));
        assert!(!PAGE.contains("{{KILN_VERSION}}"));
        assert!(PAGE.contains(r#"querySelector('meta[name="kiln-version"]')"#), "the page reads its own version");
    }

    #[tokio::test]
    async fn pwa_content_types() {
        let ty = |r: &Response| r.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string();
        let m = manifest().await.into_response();
        assert_eq!(ty(&m), "application/manifest+json");
        let s = sw().await.into_response();
        assert!(ty(&s).starts_with("application/javascript"));
        assert_eq!(s.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(s.headers()["service-worker-allowed"], "/");
        assert_eq!(ty(&icon_file("icon.svg")), "image/svg+xml");
        let png = icon_file("icon-512.png");
        assert_eq!(ty(&png), "image/png");
        assert!(png.headers()[header::CACHE_CONTROL].to_str().unwrap().contains("max-age"));
        assert_eq!(icon_file("../Cargo.toml").status(), StatusCode::NOT_FOUND);
        // The embedded PNGs are real PNGs of the advertised size.
        for (bytes, px) in [
            (&include_bytes!("../assets/icon-192.png")[..], 192),
            (include_bytes!("../assets/icon-512.png"), 512),
            (include_bytes!("../assets/apple-touch-icon.png"), 180),
        ] {
            assert_eq!(&bytes[1..4], b"PNG");
            assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), px);
        }
    }

    #[test]
    fn identity_claims() {
        let tcp = |a: &str| Via::Tcp(a.parse().unwrap());
        let peer: IpAddr = "100.64.0.7".parse().unwrap();
        // TCP: the source address decides; identity headers are never read.
        assert_eq!(claim(tcp("127.0.0.1:5000"), None, None, false), Claim::Local);
        assert_eq!(claim(tcp("[::ffff:127.0.0.1]:5000"), None, None, false), Claim::Local);
        assert_eq!(claim(tcp("127.0.0.1:5000"), Some("me@x.com"), Some("100.64.0.7"), false), Claim::Local);
        assert_eq!(claim(tcp("100.64.0.7:5000"), None, None, false), Claim::Peer(peer));
        assert_eq!(claim(tcp("100.64.0.7:5000"), Some("evil@x.com"), None, false), Claim::Peer(peer));
        assert!(matches!(claim(tcp("192.168.1.6:5000"), Some("me@x.com"), Some("100.64.0.7"), false), Claim::Outside(_)));
        // The serve socket: tailscaled's login header, from the tailnet address it saw.
        assert_eq!(claim(Via::Serve, Some("me@x.com"), Some("100.64.0.7"), false), Claim::Login("me@x.com".into(), peer));
        // No user from a tailnet address: a tagged node (or the box itself), judged as over TCP.
        assert_eq!(claim(Via::Serve, None, Some("100.64.0.7"), false), Claim::Peer(peer));
        assert_eq!(claim(Via::Serve, Some(""), Some("100.64.0.7"), false), Claim::Peer(peer));
        // No tailnet source: key needed.
        assert_eq!(claim(Via::Serve, None, None, false), Claim::Local);
        assert_eq!(claim(Via::Serve, Some("me@x.com"), None, false), Claim::Local);
        assert_eq!(claim(Via::Serve, Some("me@x.com"), Some("127.0.0.1"), false), Claim::Local);
        assert_eq!(claim(Via::Serve, Some("me@x.com"), Some("192.168.1.6"), false), Claim::Local);
        // Funnel (the public internet) is refused outright.
        assert!(matches!(claim(Via::Serve, Some("me@x.com"), Some("100.64.0.7"), true), Claim::Outside(_)));
        assert!(matches!(claim(Via::Serve, None, None, true), Claim::Outside(_)));
    }

    #[test]
    fn identity_decisions() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let me = SelfInfo { ips: vec![ip("100.64.0.1")], node: Some("nSELF".into()), owner: Some("me@x.com".into()), at: 1, tried: 1 };
        let who = |l: &str, n: &str| Some((l.to_string(), n.to_string()));
        let login = |l: &str, a: &str| Claim::Login(l.into(), ip(a));
        // Serve login: whois must name the same user, on another node.
        assert_eq!(identify(login("me@x.com", "100.64.0.7"), &me, who("me@x.com", "nPEER")), Some(Some("me@x.com".into())));
        assert_eq!(identify(login("me@x.com", "100.64.0.7"), &me, who("evil@x.com", "nPEER")), Some(None));
        assert_eq!(identify(login("me@x.com", "100.64.0.7"), &me, None), Some(None));
        // whois says it is this box (an address not in the cached list): local, key needed.
        assert_eq!(identify(login("me@x.com", "100.64.0.7"), &me, who("me@x.com", "nSELF")), None);
        assert_eq!(identify(login("me@x.com", "100.64.0.1"), &me, who("me@x.com", "nPEER")), None);
        // Tagged node through serve (no login): whois names the pseudo-user, which allowed_users refuses.
        let tagged = identify(Claim::Peer(ip("100.64.0.7")), &me, who(TAGGED, "nTAG"));
        assert_eq!(tagged, Some(Some(TAGGED.into())));
        assert!(!peer_allowed(&[], me.owner.clone(), TAGGED));
        assert_eq!(identify(Claim::Peer(ip("100.64.0.1")), &me, who(TAGGED, "nSELF")), None);
        // Fail closed when we don't know ourselves.
        assert_eq!(identify(login("me@x.com", "100.64.0.7"), &SelfInfo::default(), who("me@x.com", "nPEER")), None);
        assert_eq!(identify(Claim::Local, &me, None), None);
    }

    #[test]
    fn self_info_refresh_due() {
        let info = |at, tried| SelfInfo { at, tried, ..Default::default() };
        // Normal 5-minute cache.
        assert!(!refresh_due(&info(1000, 1000), 1299, 300));
        assert!(refresh_due(&info(1000, 1000), 1300, 300));
        // An unknown address asks for 10 s freshness, but never more than one attempt per 10 s.
        assert!(refresh_due(&info(1000, 1000), 1010, 10));
        assert!(!refresh_due(&info(1000, 1005), 1010, 10));
        assert!(!refresh_due(&info(0, 1005), 1010, 300));
        assert!(refresh_due(&info(0, 0), 1010, 300));
    }

    #[test]
    fn serve_config_checks() {
        let sock = std::path::Path::new("/home/k/.local/share/kiln/serve.sock");
        let check = |v: Value| serve_use(&v, sock);
        let host = "box.example.ts.net";
        // Shape seen on ryzen7 (tailscale 1.102): unrelated loopback proxies only.
        let unrelated = json!({
            "TCP": { "443": { "HTTPS": true }, "8443": { "HTTPS": true } },
            "Web": {
                format!("{host}:443"): { "Handlers": { "/": { "Proxy": "http://127.0.0.1:8789" } } },
                format!("{host}:8443"): { "Handlers": { "/": { "Proxy": "http://127.0.0.1:7878" } } },
            },
        });
        assert_eq!(check(unrelated.clone()), ServeUse::Unused);
        assert_eq!(check(json!({})), ServeUse::Unused);
        let mut web = unrelated.clone();
        web["Web"][format!("{host}:8443")]["Handlers"]["/"]["Proxy"] = json!(format!("unix:{}", sock.display()));
        assert_eq!(check(web.clone()), ServeUse::Proxied);
        // Funnel on the port that proxies to kiln: anyone on the internet.
        let mut funnel = web.clone();
        funnel["AllowFunnel"] = json!({ format!("{host}:8443"): true });
        assert!(matches!(check(funnel), ServeUse::Unsafe(_)));
        // Funnel on an unrelated port is fine.
        let mut other_funnel = web.clone();
        other_funnel["AllowFunnel"] = json!({ format!("{host}:443"): true });
        assert_eq!(check(other_funnel), ServeUse::Proxied);
        // Raw TCP (plain or TLS-terminated) to the socket: the client writes the headers.
        for tcp in [
            json!({ "TCPForward": format!("unix:{}", sock.display()) }),
            json!({ "TCPForward": format!("unix:{}", sock.display()), "TerminateTLS": host }),
        ] {
            let mut fwd = web.clone();
            fwd["TCP"]["2222"] = tcp;
            assert!(matches!(check(fwd), ServeUse::Unsafe(_)));
        }
        let mut fwd_other = web.clone();
        fwd_other["TCP"]["2222"] = json!({ "TCPForward": "127.0.0.1:22" });
        assert_eq!(check(fwd_other), ServeUse::Proxied);
        // Foreground sessions and Services carry their own config.
        let fg = json!({ "Foreground": { "abc": { "TCP": { "9000": { "TCPForward": format!("unix://{}", sock.display()) } } } } });
        assert!(matches!(check(fg), ServeUse::Unsafe(_)));
        let svc = json!({ "Services": { "svc:kiln": { "Web": { "kiln.ts.net:443": { "Handlers": { "/": { "Proxy": format!("unix:{}", sock.display()) } } } } } } });
        assert_eq!(check(svc), ServeUse::Proxied);
        // Funnel set at the top level still applies to a foreground session's port.
        let fg_funnel = json!({
            "AllowFunnel": { format!("{host}:8443"): true },
            "Foreground": { "abc": { "Web": { format!("{host}:8443"): { "Handlers": { "/": { "Proxy": format!("unix:{}", sock.display()) } } } } } },
        });
        assert!(matches!(check(fg_funnel), ServeUse::Unsafe(_)));
    }

    #[tokio::test]
    async fn serve_socket_is_private() {
        let dir = std::env::temp_dir().join(format!("kiln-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("serve.sock");
        std::fs::write(&path, "stale").unwrap();
        let _l = bind_serve_socket(&path).unwrap();
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let m = std::fs::metadata(&path).unwrap();
        assert!(m.file_type().is_socket());
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tailnet_ranges() {
        assert!(is_tailnet("100.64.0.7".parse().unwrap()));
        assert!(is_tailnet("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet("192.168.1.6".parse().unwrap()));
        assert!(is_tailnet("fd7a:115c:a1e0::7001:307a".parse().unwrap()));
        assert!(!is_tailnet("fe80::1".parse().unwrap()));
    }
}
