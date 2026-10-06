//! Dashboard + JSON API. Reachable only from loopback and the tailnet.

use crate::{App, Config, now, vm};
use anyhow::{Context, anyhow};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
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

pub async fn serve(app: Arc<App>) -> anyhow::Result<()> {
    let addr = app.cfg().listen;
    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("dashboard.html")) }))
        .route("/api/state", get(state))
        .route("/api/config", post(set_config))
        .route("/api/token", post(set_token))
        .route("/api/log", get(log))
        .route("/api/vms/{id}/kill", post(kill))
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

static WHOIS: LazyLock<Mutex<HashMap<IpAddr, (String, u64)>>> = LazyLock::new(Mutex::default);

async fn whois(ip: IpAddr) -> Option<String> {
    if let Some((login, at)) = WHOIS.lock().unwrap().get(&ip)
        && now() - at < 300 {
            return Some(login.clone());
        }
    let out = Command::new("tailscale").args(["whois", "--json", &ip.to_string()]).output().await.ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let login = v["UserProfile"]["LoginName"].as_str()?.to_string();
    WHOIS.lock().unwrap().insert(ip, (login.clone(), now()));
    Some(login)
}

/// Network gate + CSRF gate + optional tailnet-identity allowlist.
async fn guard(State(app): S, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let ip = peer.ip().to_canonical();
    let deny = |msg: &str| (StatusCode::FORBIDDEN, msg.to_string()).into_response();
    if !ip.is_loopback() && !is_tailnet(ip) {
        return deny("kiln only answers on loopback and the tailnet");
    }
    // Browsers can't add custom headers cross-origin without a CORS preflight
    // we never grant, so this blocks drive-by POSTs from other sites.
    if req.method() != Method::GET && !req.headers().contains_key("x-kiln") {
        return deny("missing x-kiln header");
    }
    let allowed = app.cfg().allowed_users;
    if !allowed.is_empty() {
        // Behind `tailscale serve` the TCP peer is loopback and tailscaled
        // vouches for the caller in this header.
        let login = if ip.is_loopback() {
            req.headers().get("tailscale-user-login").and_then(|v| v.to_str().ok()).map(String::from)
        } else {
            whois(ip).await
        };
        if !login.is_some_and(|l| allowed.iter().any(|a| a.eq_ignore_ascii_case(&l))) {
            return deny("your tailnet identity is not in allowed_users");
        }
    }
    next.run(req).await
}

fn host_stats() -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let kb = |key: &str| -> u64 {
        mem.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    json!({
        "load": load.split_whitespace().take(3).collect::<Vec<_>>(),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "mem_total_mb": kb("MemTotal:") / 1024,
        "mem_avail_mb": kb("MemAvailable:") / 1024,
    })
}

async fn state(State(app): S) -> R<Json<Value>> {
    let vms: Vec<_> = app.vms.lock().unwrap().iter().rev().take(100).cloned().collect();
    let image: Value = std::fs::read(app.data.join("images/base.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "config": app.cfg(),
        "token_set": app.gh.has_token(),
        "poll": *app.poll.lock().unwrap(),
        "vms": vms,
        "image": image,
        "image_ready": vm::image_ready(&app.data),
        "baking": app.baking.load(std::sync::atomic::Ordering::Relaxed),
        "host": host_stats(),
    })))
}

async fn set_config(State(app): S, Json(c): Json<Config>) -> R<StatusCode> {
    app.save_cfg(c)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}
async fn set_token(State(app): S, Json(b): Json<TokenBody>) -> R<StatusCode> {
    app.save_token(b.token)?;
    Ok(StatusCode::NO_CONTENT)
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
    if b.peer.is_empty() || !b.peer.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c)) {
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
    let args: Vec<&str> = if b.on {
        vec!["serve", "--bg", "--https=8443", &target]
    } else {
        vec!["serve", "--https=8443", "off"]
    };
    let out = tailscale(&args).await?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail_r(text.trim())?;
    }
    Ok(Json(json!({ "output": text.trim() })))
}

fn bail_r(msg: &str) -> R<()> {
    Err(anyhow!(msg.to_string()).into())
}

/// GitHub passthrough, restricted to `repos/<configured repo>/actions/...`,
/// so the dashboard can browse workflows/runs/jobs/logs and dispatch, rerun
/// or cancel without a dedicated endpoint per call.
async fn gh_proxy(
    State(app): S,
    method: Method,
    Path(path): Path<String>,
    q: axum::extract::RawQuery,
    body: Bytes,
) -> R<Response> {
    let allowed = app.cfg().repos.iter().any(|r| path.starts_with(&format!("repos/{r}/actions/")));
    if !allowed || path.contains("..") {
        bail_r("only repos/<configured repo>/actions/... is proxied")?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
