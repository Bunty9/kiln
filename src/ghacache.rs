//! Host-side GitHub Actions cache (Twirp CacheService + the Azure blob subset the toolkit uses), on 127.0.0.1:5001.
//!
//! Trust model: the guest is untrusted, so identity never comes from the job. The router asks a `Resolver` who the
//! peer socket belongs to (task C-3 maps it to a VM through the kernel); an unidentified peer, or one without the
//! local cache, is proxied to GitHub's Results service untouched, exactly as if kiln were not there. Uploads land in
//! `staged/<vm>/` and are visible to that VM only; `promote` moves them into the repo's trusted scope when the job
//! earned it, `discard` deletes them. Every blob URL carries a random per-entry `sig`; an id from another VM or repo
//! is not even looked up. The proxy only ever talks to one fixed upstream host.

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use futures_util::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const PORT: u16 = 5001;
const UPSTREAM: &str = "https://results-receiver.actions.githubusercontent.com";
#[cfg(test)]
const CACHE_SVC: &str = "/twirp/github.actions.results.api.v1.CacheService/";
/// Largest single entry.
const ENTRY_CAP: u64 = 10 << 30;
/// Twirp and block-list bodies are tiny; anything bigger is a mistake.
const SMALL_BODY: usize = 1 << 20;

/// Who is on the other end of a connection, as decided by the host (never by the job).
#[derive(Clone, Debug)]
pub struct Caller {
    pub vm_id: String,
    /// "owner/name" (or any stable repo string); only used to pick the trusted scope directory.
    pub repo: String,
    /// The local cache is on for this VM; otherwise CacheService is proxied too.
    pub local: bool,
    /// May create entries (the verdict that later allows `promote`); reads are always allowed.
    pub can_write: bool,
}

/// Peer address -> caller. `None` = unknown: proxy everything.
pub type Resolver = Arc<dyn Fn(SocketAddr) -> Option<Caller> + Send + Sync>;

struct Inner {
    root: PathBuf,
    resolve: Resolver,
    upstream: String,
    budget: Arc<dyn Fn() -> u64 + Send + Sync>,
    http: reqwest::Client,
    /// Serialises metadata read-modify-write (create, finalize, block list, promote). Blob bytes stream outside it.
    // ponytail: one global lock; per-VM locks if metadata calls ever show up in a profile.
    lock: Mutex<()>,
}
type St = Arc<Inner>;

pub fn router(root: PathBuf, resolve: Resolver, upstream: String, budget: Arc<dyn Fn() -> u64 + Send + Sync>) -> Router {
    let http = reqwest::Client::builder()
        .user_agent("kiln-ci")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("http client");
    let st: St = Arc::new(Inner { root, resolve, upstream, budget, http, lock: Mutex::new(()) });
    Router::new()
        .route("/_kiln/ping", get(|| async { StatusCode::NO_CONTENT }))
        .route("/twirp/github.actions.results.api.v1.CacheService/{method}", post(twirp))
        .route("/devstoreaccount1/upload/{id}", put(put_blob).layer(axum::extract::DefaultBodyLimit::disable()))
        .route("/download/{id}", get(download))
        .fallback(proxy)
        .with_state(st)
}

/// Serve on 127.0.0.1:5001 (Linux only). Always on: until C-3 identifies callers it proxies everything.
pub async fn serve(app: Arc<crate::App>) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let root = app.data.join("gha-cache");
    let a = app.clone();
    let budget: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || a.cfg().gha_cache_gb << 30);
    let r = router(root, Arc::new(|_| None), UPSTREAM.into(), budget);
    let l = match tokio::net::TcpListener::bind(("127.0.0.1", PORT)).await {
        Ok(l) => l,
        Err(e) => return tracing::warn!("actions cache: cannot listen on 127.0.0.1:{PORT}: {e}"),
    };
    if let Err(e) = axum::serve(l, r.into_make_service_with_connect_info::<SocketAddr>()).await {
        tracing::warn!("actions cache listener ended: {e}");
    }
}

// ---------------------------------------------------------------- storage (pure, tested)

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Meta {
    key: String,
    version: String,
    /// Bytes, set at finalize.
    size: u64,
    /// Unix milliseconds.
    created: u64,
    last_used: u64,
    /// Block files in serving order. Never concatenated.
    blocks: Vec<String>,
    /// "staged" or "trusted".
    scope: String,
    /// Directory stem of the repo the entry belongs to (where `promote` puts it).
    repo: String,
    /// Random token every blob/download URL must carry.
    sig: String,
    finished: bool,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
    hex(&b)
}

/// Filesystem-safe, lowercase directory name for a repo or VM id. Idempotent; '/' becomes '~'.
pub fn stem(s: &str) -> String {
    let t: String = s
        .to_lowercase()
        .chars()
        .map(|c| {
            if c == '/' {
                '~'
            } else if c.is_ascii_alphanumeric() || "-_~".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if t.is_empty() { "_".into() } else { t }
}

fn staged_dir(root: &FsPath, vm: &str) -> PathBuf {
    root.join("staged").join(stem(vm))
}

fn trusted_dir(root: &FsPath, repo: &str) -> PathBuf {
    root.join("repos").join(stem(repo)).join("entries")
}

fn read_meta(dir: &FsPath) -> Option<Meta> {
    serde_json::from_slice(&std::fs::read(dir.join("meta.json")).ok()?).ok()
}

fn write_meta(dir: &FsPath, m: &Meta) -> std::io::Result<()> {
    let tmp = dir.join("meta.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(m)?)?;
    std::fs::rename(tmp, dir.join("meta.json"))
}

fn entries_in(parent: &FsPath) -> Vec<(PathBuf, Meta)> {
    let Ok(rd) = std::fs::read_dir(parent) else { return vec![] };
    rd.flatten().filter_map(|e| Some((e.path(), read_meta(&e.path())?))).collect()
}

fn dir_size(p: &FsPath) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Finished entries this caller may read: the repo's trusted scope plus its own VM's staged uploads.
fn visible(root: &FsPath, c: &Caller) -> Vec<(PathBuf, Meta)> {
    let mut v = entries_in(&trusted_dir(root, &c.repo));
    v.extend(entries_in(&staged_dir(root, &c.vm_id)));
    v.retain(|(_, m)| m.finished);
    v
}

/// GitHub's matching: for the primary key, then each restore key in order, an exact key first, then the newest entry
/// whose key starts with it; the version must match exactly.
fn lookup(root: &FsPath, c: &Caller, key: &str, restore: &[String], version: &str) -> Option<(PathBuf, Meta)> {
    let all: Vec<_> = visible(root, c).into_iter().filter(|(_, m)| m.version == version).collect();
    for k in std::iter::once(key).chain(restore.iter().map(String::as_str)) {
        if let Some(e) = all.iter().filter(|(_, m)| m.key == k).max_by_key(|(_, m)| m.created) {
            return Some(e.clone());
        }
        if let Some(e) = all.iter().filter(|(_, m)| m.key.starts_with(k)).max_by_key(|(_, m)| m.created) {
            return Some(e.clone());
        }
    }
    None
}

/// Move the VM's finished staged entries into their repo's trusted scope, skipping keys that already exist there
/// (first writer wins). Returns (promoted, dropped). Unfinished uploads are dropped.
#[allow(dead_code)] // C-3 calls it from finish_cache
pub fn promote(root: &FsPath, vm_id: &str) -> Result<(usize, usize)> {
    let (mut ok, mut dropped) = (0, 0);
    for (dir, m) in entries_in(&staged_dir(root, vm_id)) {
        let dest = trusted_dir(root, &m.repo);
        let dup = entries_in(&dest).iter().any(|(_, t)| t.finished && t.key == m.key && t.version == m.version);
        if !m.finished || dup {
            std::fs::remove_dir_all(&dir)?;
            dropped += 1;
            continue;
        }
        std::fs::create_dir_all(&dest)?;
        let target = dest.join(dir.file_name().unwrap_or_default());
        std::fs::rename(&dir, &target)?;
        write_meta(&target, &Meta { scope: "trusted".into(), ..m })?;
        ok += 1;
    }
    discard(root, vm_id);
    Ok((ok, dropped))
}

/// Delete everything the VM staged (also uploads still in progress).
#[allow(dead_code)] // C-3
pub fn discard(root: &FsPath, vm_id: &str) {
    let _ = std::fs::remove_dir_all(staged_dir(root, vm_id));
}

/// Delete trusted entries, least recently used first, until the whole store fits the budget. Returns bytes freed.
pub fn evict(root: &FsPath, budget: u64) -> u64 {
    let mut used = dir_size(root);
    let mut all: Vec<_> =
        std::fs::read_dir(root.join("repos")).into_iter().flatten().flatten().flat_map(|r| entries_in(&r.path().join("entries"))).collect();
    all.sort_by_key(|(_, m)| m.last_used);
    let mut freed = 0;
    for (dir, _) in all {
        if used <= budget {
            break;
        }
        let s = dir_size(&dir);
        if std::fs::remove_dir_all(&dir).is_ok() {
            used = used.saturating_sub(s);
            freed += s;
        }
    }
    freed
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

/// Block file name for a block id as it appears in the query (a '+' decodes to a space there) and in the XML.
fn block_file(id: &str) -> String {
    let id = id.replace(' ', "+");
    format!("b-{}", hex(ring::digest::digest(&ring::digest::SHA256, id.as_bytes()).as_ref()))
}

fn block_ids(xml: &str) -> Vec<String> {
    let (mut out, mut rest) = (vec![], xml);
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let Some(j) = rest.find('>') else { break };
        let tag = &rest[..j];
        rest = &rest[j + 1..];
        if matches!(tag, "Latest" | "Committed" | "Uncommitted")
            && let Some(k) = rest.find('<')
        {
            out.push(rest[..k].trim().to_string());
            rest = &rest[k..];
        }
    }
    out
}

// ---------------------------------------------------------------- Twirp

fn json_resp(code: StatusCode, v: Value) -> Response {
    (code, [(header::CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

fn twirp_err(code: StatusCode, c: &str, msg: &str) -> Response {
    json_resp(code, json!({ "code": c, "msg": msg }))
}

#[derive(Deserialize, Default)]
struct TwirpReq {
    #[serde(default)]
    key: String,
    #[serde(default)]
    version: String,
    #[serde(default, alias = "restoreKeys")]
    restore_keys: Option<Vec<String>>,
    /// An int64: a JSON string from the toolkit, a number from others.
    #[serde(default, alias = "sizeBytes")]
    size_bytes: Option<Value>,
}

fn host_of(h: &HeaderMap) -> String {
    let v = h.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b)) {
        v.into()
    } else {
        format!("10.0.2.2:{PORT}")
    }
}

async fn twirp(State(st): State<St>, ConnectInfo(peer): ConnectInfo<SocketAddr>, Path(method): Path<String>, req: Request) -> Response {
    let json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("application/json"));
    let known = matches!(method.as_str(), "CreateCacheEntry" | "FinalizeCacheEntryUpload" | "GetCacheEntryDownloadURL");
    let Some(c) = (st.resolve)(peer).filter(|c| c.local && json && known) else { return proxy(State(st), req).await };
    let host = host_of(req.headers());
    let Ok(body) = axum::body::to_bytes(req.into_body(), SMALL_BODY).await else {
        return twirp_err(StatusCode::BAD_REQUEST, "invalid_argument", "unreadable body");
    };
    let Ok(r) = serde_json::from_slice::<TwirpReq>(if body.is_empty() { b"{}" } else { &body }) else {
        return twirp_err(StatusCode::BAD_REQUEST, "invalid_argument", "bad json");
    };
    if r.key.is_empty() || r.version.is_empty() {
        return twirp_err(StatusCode::BAD_REQUEST, "invalid_argument", "key and version are required");
    }
    let _g = st.lock.lock().unwrap_or_else(|e| e.into_inner());
    match method.as_str() {
        "CreateCacheEntry" => create(&st, &c, &r, &host),
        "FinalizeCacheEntryUpload" => finalize(&st, &c, &r),
        _ => get_url(&st, &c, &r, &host),
    }
}

fn create(st: &Inner, c: &Caller, r: &TwirpReq, host: &str) -> Response {
    if !c.can_write || visible(&st.root, c).iter().any(|(_, m)| m.key == r.key && m.version == r.version) {
        return json_resp(StatusCode::OK, json!({ "ok": false }));
    }
    // A retry of an unfinished upload replaces the old reservation.
    for (d, m) in entries_in(&staged_dir(&st.root, &c.vm_id)) {
        if !m.finished && m.key == r.key && m.version == r.version {
            let _ = std::fs::remove_dir_all(d);
        }
    }
    let (id, sig) = (random_hex(16), random_hex(32));
    let dir = staged_dir(&st.root, &c.vm_id).join(&id);
    let m = Meta {
        key: r.key.clone(),
        version: r.version.clone(),
        size: 0,
        created: now_ms(),
        last_used: now_ms(),
        blocks: vec![],
        scope: "staged".into(),
        repo: stem(&c.repo),
        sig: sig.clone(),
        finished: false,
    };
    if std::fs::create_dir_all(&dir).and_then(|_| write_meta(&dir, &m)).is_err() {
        return twirp_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "cannot stage the entry");
    }
    json_resp(StatusCode::OK, json!({ "ok": true, "signed_upload_url": format!("http://{host}/devstoreaccount1/upload/{id}?sig={sig}") }))
}

fn finalize(st: &Inner, c: &Caller, r: &TwirpReq) -> Response {
    let Some((dir, mut m)) =
        entries_in(&staged_dir(&st.root, &c.vm_id)).into_iter().find(|(_, m)| !m.finished && m.key == r.key && m.version == r.version)
    else {
        return twirp_err(StatusCode::NOT_FOUND, "not_found", "no upload in progress for this key");
    };
    let want = match &r.size_bytes {
        Some(Value::String(s)) => s.parse::<u64>().ok(),
        Some(v) => v.as_u64(),
        None => None,
    };
    let got: Option<u64> = m.blocks.iter().map(|b| std::fs::metadata(dir.join(b)).ok().map(|x| x.len())).sum();
    let fail = |msg: String| {
        let _ = std::fs::remove_dir_all(&dir);
        json_resp(StatusCode::OK, json!({ "ok": false, "message": msg }))
    };
    let Some(got) = got.filter(|_| !m.blocks.is_empty()) else { return fail("the upload is incomplete".into()) };
    if want != Some(got) {
        return fail(format!("size {got} does not match the declared size"));
    }
    (m.size, m.finished, m.created, m.last_used) = (got, true, now_ms(), now_ms());
    if write_meta(&dir, &m).is_err() {
        return twirp_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "cannot save the entry");
    }
    let n = dir.file_name().and_then(|f| f.to_str()).and_then(|f| u64::from_str_radix(&f[..15], 16).ok()).unwrap_or(0);
    json_resp(StatusCode::OK, json!({ "ok": true, "entry_id": n.to_string() }))
}

fn get_url(st: &Inner, c: &Caller, r: &TwirpReq, host: &str) -> Response {
    let Some((dir, mut m)) = lookup(&st.root, c, &r.key, r.restore_keys.as_deref().unwrap_or(&[]), &r.version) else {
        return json_resp(StatusCode::OK, json!({ "ok": false }));
    };
    // Promise to serve: buildkit hard-fails on a later 404.
    if m.blocks.iter().any(|b| !dir.join(b).is_file()) {
        return json_resp(StatusCode::OK, json!({ "ok": false }));
    }
    m.last_used = now_ms();
    let _ = write_meta(&dir, &m);
    let id = dir.file_name().and_then(|f| f.to_str()).unwrap_or_default();
    json_resp(
        StatusCode::OK,
        json!({ "ok": true, "signed_download_url": format!("http://{host}/download/{id}?sig={}", m.sig), "matched_key": m.key }),
    )
}

// ---------------------------------------------------------------- blobs

fn status(c: StatusCode) -> Response {
    c.into_response()
}

/// Identified caller + the entry dir for `id` (own staged upload first, else the repo's trusted scope) + sig checked.
fn entry_for(st: &Inner, peer: SocketAddr, id: &str, q: &HashMap<String, String>) -> Result<(Caller, PathBuf, Meta), StatusCode> {
    let c = (st.resolve)(peer).filter(|c| c.local).ok_or(StatusCode::FORBIDDEN)?;
    if !valid_id(id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let (dir, m) = [staged_dir(&st.root, &c.vm_id).join(id), trusted_dir(&st.root, &c.repo).join(id)]
        .into_iter()
        .find_map(|d| Some((d.clone(), read_meta(&d)?)))
        .ok_or(StatusCode::NOT_FOUND)?;
    if !ct_eq(q.get("sig").map_or("", String::as_str), &m.sig) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((c, dir, m))
}

fn azure_ok() -> Response {
    let h = random_hex(16);
    let mut r = status(StatusCode::CREATED);
    let id = format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]);
    r.headers_mut().insert("x-ms-request-id", HeaderValue::from_str(&id).unwrap());
    r.headers_mut().insert("x-ms-version", HeaderValue::from_static("2021-12-02"));
    r
}

/// Stream `body` to `dest` (via a .part file); exactly `len` bytes or an error.
async fn save(body: Body, dest: &FsPath, len: u64) -> Result<(), StatusCode> {
    let tmp = dest.with_extension("part");
    let r: Result<(), StatusCode> = async {
        let mut f = tokio::fs::File::create(&tmp).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let (mut s, mut n) = (body.into_data_stream(), 0u64);
        while let Some(chunk) = s.next().await {
            let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
            n += chunk.len() as u64;
            if n > len {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            f.write_all(&chunk).await.map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
        }
        f.flush().await.map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;
        if n != len {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(())
    }
    .await;
    match r {
        Ok(()) => tokio::fs::rename(&tmp, dest).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(e)
        }
    }
}

async fn put_blob(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let (c, dir, mut m) = match entry_for(&st, peer, &id, &q) {
        Ok(x) => x,
        Err(e) => return status(e),
    };
    // Writes only into this VM's own unfinished upload.
    if m.finished || m.scope != "staged" || !c.can_write || dir != staged_dir(&st.root, &c.vm_id).join(&id) {
        return status(StatusCode::FORBIDDEN);
    }
    let Some(len) = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) else {
        return status(StatusCode::LENGTH_REQUIRED);
    };
    let comp = q.get("comp").map_or("", String::as_str);
    if comp == "blocklist" {
        let Ok(body) = axum::body::to_bytes(req.into_body(), SMALL_BODY).await else { return status(StatusCode::BAD_REQUEST) };
        let blocks: Vec<String> = block_ids(&String::from_utf8_lossy(&body)).iter().map(|b| block_file(b)).collect();
        if blocks.is_empty() || blocks.iter().any(|b| !dir.join(b).is_file()) {
            return status(StatusCode::BAD_REQUEST);
        }
        let _g = st.lock.lock().unwrap_or_else(|e| e.into_inner());
        // Blocks the list does not name are dropped; the list's order is the serving order.
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n != "meta.json" && !blocks.contains(&n) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        m.blocks = blocks;
        return if write_meta(&dir, &m).is_ok() { azure_ok() } else { status(StatusCode::INTERNAL_SERVER_ERROR) };
    }
    let name = match comp {
        "" => "blob".to_string(),
        "block" => match q.get("blockid") {
            Some(b) if !b.is_empty() => block_file(b),
            _ => return status(StatusCode::BAD_REQUEST),
        },
        _ => return status(StatusCode::NOT_IMPLEMENTED),
    };
    if len > ENTRY_CAP || dir_size(&dir) + len > ENTRY_CAP {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let budget = (st.budget)();
    if dir_size(&st.root) + len > budget {
        evict(&st.root, budget.saturating_sub(len));
        if dir_size(&st.root) + len > budget {
            return status(StatusCode::INSUFFICIENT_STORAGE);
        }
    }
    if let Err(e) = save(req.into_body(), &dir.join(&name), len).await {
        return status(e);
    }
    if comp.is_empty() {
        // Put Blob is the whole entry; it replaces anything earlier.
        let _g = st.lock.lock().unwrap_or_else(|e| e.into_inner());
        m.blocks = vec![name];
        if write_meta(&dir, &m).is_err() {
            return status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    azure_ok()
}

enum Span {
    Full,
    Part(u64, u64),
    Bad,
}

fn parse_range(h: Option<&str>, size: u64) -> Span {
    let Some(spec) = h.and_then(|h| h.strip_prefix("bytes=")) else { return Span::Full };
    let Some((a, b)) = spec.split_once('-').filter(|_| !spec.contains(',')) else { return Span::Full };
    let (a, b) = (a.trim(), b.trim());
    let last = size.saturating_sub(1);
    let r = match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(a), Ok(b)) => (a, b.min(last)),
        (Ok(a), Err(_)) if b.is_empty() => (a, last),
        (Err(_), Ok(n)) if a.is_empty() && n > 0 => (size.saturating_sub(n), last),
        _ => return Span::Full,
    };
    if size == 0 || r.0 > r.1 || r.0 >= size { Span::Bad } else { Span::Part(r.0, r.1) }
}

async fn download(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let (_, dir, m) = match entry_for(&st, peer, &id, &q) {
        Ok(x) => x,
        Err(e) => return status(e),
    };
    if !m.finished {
        return status(StatusCode::NOT_FOUND);
    }
    let (a, b, code) = match parse_range(headers.get(header::RANGE).and_then(|v| v.to_str().ok()), m.size) {
        Span::Full => (0, m.size.saturating_sub(1), StatusCode::OK),
        Span::Part(a, b) => (a, b, StatusCode::PARTIAL_CONTENT),
        Span::Bad => return (StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{}", m.size))]).into_response(),
    };
    let len = if m.size == 0 { 0 } else { b - a + 1 };
    // (file, offset, length) for the part of each block inside [a, b].
    let (mut segs, mut at) = (vec![], 0u64);
    for blk in &m.blocks {
        let Ok(md) = std::fs::metadata(dir.join(blk)) else { return status(StatusCode::NOT_FOUND) };
        let (lo, hi) = (at, at + md.len());
        at = hi;
        if len > 0 && lo <= b && hi > a {
            let off = a.saturating_sub(lo);
            segs.push((dir.join(blk), off, hi.min(b + 1) - lo - off));
        }
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        let s = futures_util::stream::iter(segs)
            .then(|(p, off, n)| async move {
                let mut f = tokio::fs::File::open(p).await?;
                f.seek(SeekFrom::Start(off)).await?;
                std::io::Result::Ok(tokio_util::io::ReaderStream::with_capacity(f.take(n), 256 << 10))
            })
            .try_flatten();
        Body::from_stream(s)
    };
    let mut r = Response::new(body);
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if code == StatusCode::PARTIAL_CONTENT {
        h.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes {a}-{b}/{}", m.size)).unwrap());
    }
    r
}

// ---------------------------------------------------------------- proxy to the Results service

const HOP: [&str; 9] =
    ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host"];

fn forwardable(n: &HeaderName) -> bool {
    !HOP.contains(&n.as_str()) && n != header::EXPECT
}

/// Stream the request to the fixed upstream (same method, path, query, headers, body) and stream the answer back.
/// Authorization passes through and is never logged.
async fn proxy(State(st): State<St>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut up = st.http.request(parts.method.clone(), format!("{}{pq}", st.upstream));
    for (n, v) in &parts.headers {
        if forwardable(n) {
            up = up.header(n, v);
        }
    }
    if parts.method != Method::GET && parts.method != Method::HEAD {
        up = up.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let resp = match up.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("actions cache proxy {} {}: {}", parts.method, parts.uri.path(), e.without_url());
            return status(StatusCode::BAD_GATEWAY);
        }
    };
    let mut out = Response::new(Body::empty());
    *out.status_mut() = resp.status();
    for (n, v) in resp.headers() {
        if forwardable(n) {
            out.headers_mut().append(n, v.clone());
        }
    }
    *out.body_mut() = Body::from_stream(resp.bytes_stream());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!("kiln-ghacache-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn caller(vm: &str, repo: &str) -> Caller {
        Caller { vm_id: vm.into(), repo: repo.into(), local: true, can_write: true }
    }

    /// A finished entry written straight to disk.
    fn seed(root: &FsPath, scope: &str, c: &Caller, key: &str, version: &str, created: u64, data: &[u8]) -> PathBuf {
        let id = random_hex(16);
        let dir = if scope == "staged" { staged_dir(root, &c.vm_id) } else { trusted_dir(root, &c.repo) }.join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), data).unwrap();
        let m = Meta {
            key: key.into(),
            version: version.into(),
            size: data.len() as u64,
            created,
            last_used: created,
            blocks: vec!["blob".into()],
            scope: scope.into(),
            repo: stem(&c.repo),
            sig: random_hex(32),
            finished: true,
        };
        write_meta(&dir, &m).unwrap();
        dir
    }

    #[test]
    fn lookup_exact_then_newest_prefix_in_key_order_and_version_must_match() {
        let root = tmp();
        let c = caller("vm1", "acme/demo");
        seed(&root, "trusted", &c, "npm-a1", "v", 10, b"old");
        seed(&root, "trusted", &c, "npm-b2", "v", 20, b"new");
        seed(&root, "trusted", &c, "npm", "v", 5, b"exact");
        seed(&root, "trusted", &c, "other", "w", 30, b"otherversion");
        let key = |k: &str, r: &[&str], v: &str| {
            lookup(&root, &c, k, &r.iter().map(|s| s.to_string()).collect::<Vec<_>>(), v).map(|(_, m)| m.key)
        };
        assert_eq!(key("npm", &[], "v").as_deref(), Some("npm"), "exact beats a newer prefix match");
        assert_eq!(key("nomatch", &["npm-"], "v").as_deref(), Some("npm-b2"), "newest prefix");
        assert_eq!(key("nomatch", &["zzz", "npm-a"], "v").as_deref(), Some("npm-a1"), "restore keys in order");
        assert_eq!(key("other", &[], "v"), None, "version mismatch is a miss");
        assert_eq!(key("other", &[], "w").as_deref(), Some("other"));
    }

    #[test]
    fn reads_see_trusted_plus_own_staged_only() {
        let root = tmp();
        let (a, b, other_repo) = (caller("vm-a", "acme/demo"), caller("vm-b", "acme/demo"), caller("vm-c", "acme/other"));
        seed(&root, "trusted", &a, "t", "v", 1, b"t");
        seed(&root, "staged", &a, "s", "v", 2, b"s");
        let keys = |c: &Caller| {
            let mut k: Vec<_> = visible(&root, c).into_iter().map(|(_, m)| m.key).collect();
            k.sort();
            k
        };
        assert_eq!(keys(&a), ["s", "t"]);
        assert_eq!(keys(&b), ["t"]);
        assert!(keys(&other_repo).is_empty());
    }

    #[test]
    fn promote_moves_finished_skips_existing_and_discard_deletes() {
        let root = tmp();
        let c = caller("vm1", "acme/demo");
        seed(&root, "trusted", &c, "dup", "v", 1, b"first writer");
        seed(&root, "staged", &c, "dup", "v", 2, b"second");
        seed(&root, "staged", &c, "fresh", "v", 3, b"fresh");
        let half = seed(&root, "staged", &c, "half", "v", 4, b"h");
        let mut m = read_meta(&half).unwrap();
        m.finished = false;
        write_meta(&half, &m).unwrap();
        assert_eq!(promote(&root, "vm1").unwrap(), (1, 2), "fresh promoted; the duplicate and the unfinished upload dropped");
        let t = entries_in(&trusted_dir(&root, "acme/demo"));
        assert_eq!(t.len(), 2);
        assert!(t.iter().all(|(_, m)| m.scope == "trusted"));
        assert_eq!(
            std::fs::read(lookup(&root, &caller("vm2", "acme/demo"), "dup", &[], "v").unwrap().0.join("blob")).unwrap(),
            b"first writer"
        );
        assert!(!staged_dir(&root, "vm1").exists());
        seed(&root, "staged", &c, "gone", "v", 1, b"g");
        discard(&root, "vm1");
        assert!(!staged_dir(&root, "vm1").exists());
    }

    #[test]
    fn evict_removes_least_recently_used_until_it_fits() {
        let root = tmp();
        let c = caller("vm1", "acme/demo");
        for (k, t) in [("old", 1), ("mid", 2), ("new", 3)] {
            seed(&root, "trusted", &c, k, "v", t, &[0u8; 1000]);
        }
        let total = dir_size(&root);
        assert_eq!(evict(&root, total), 0);
        assert!(evict(&root, total - 1) > 0);
        let mut k: Vec<_> = entries_in(&trusted_dir(&root, "acme/demo")).into_iter().map(|(_, m)| m.key).collect();
        k.sort();
        assert_eq!(k, ["mid", "new"]);
        evict(&root, 0);
        assert!(entries_in(&trusted_dir(&root, "acme/demo")).is_empty());
    }

    #[test]
    fn helpers_parse_ids_ranges_and_stems() {
        assert_eq!(
            block_ids("<BlockList><Latest>a b</Latest><Latest>c==</Latest><Committed>d</Committed></BlockList>"),
            ["a b", "c==", "d"]
        );
        assert_eq!(block_file("a+b"), block_file("a b"), "a '+' in a query decodes to a space");
        assert_eq!(stem("Acme/Demo"), "acme~demo");
        assert_eq!(stem(&stem("Acme/Demo")), stem("Acme/Demo"), "idempotent");
        assert_eq!(stem("../x"), "__~x");
        assert_eq!(stem(""), "_");
        let r = |h, s| match parse_range(Some(h), s) {
            Span::Full => "full".to_string(),
            Span::Part(a, b) => format!("{a}-{b}"),
            Span::Bad => "bad".into(),
        };
        assert_eq!(r("bytes=0-0", 10), "0-0");
        assert_eq!(r("bytes=4-", 10), "4-9");
        assert_eq!(r("bytes=-3", 10), "7-9");
        assert_eq!(r("bytes=5-500", 10), "5-9");
        assert_eq!(r("bytes=10-", 10), "bad");
        assert_eq!(r("bytes=0-1,3-4", 10), "full");
        assert_eq!(r("items=0-1", 10), "full");
    }

    // ------------------------------------------------------------ handlers, over a real socket

    type Who = Arc<Mutex<Option<Caller>>>;
    /// (method, path and query, authorization, body) per request the mock Results service received.
    type Seen = Arc<Mutex<Vec<(String, String, String, Vec<u8>)>>>;

    struct Rig {
        base: String,
        root: PathBuf,
        who: Who,
        http: reqwest::Client,
        _tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Rig {
        fn as_caller(&self, c: Option<Caller>) {
            *self.who.lock().unwrap() = c;
        }
        async fn twirp(&self, m: &str, body: Value) -> (StatusCode, Value) {
            let r = self.http.post(format!("{}{CACHE_SVC}{m}", self.base)).json(&body).send().await.unwrap();
            (r.status(), r.json().await.unwrap_or(Value::Null))
        }
    }

    async fn listen(r: Router) -> (String, tokio::task::JoinHandle<()>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        (
            base,
            tokio::spawn(async move {
                axum::serve(l, r.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
            }),
        )
    }

    /// kiln's router on 127.0.0.1:0, plus a mock "Results service" that records what it was sent.
    async fn rig(budget: u64) -> (Rig, Seen) {
        let seen: Seen = Arc::default();
        let s2 = seen.clone();
        let mock = Router::new().fallback(move |req: Request| {
            let s2 = s2.clone();
            async move {
                let (p, b) = req.into_parts();
                let auth = p.headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body = axum::body::to_bytes(b, 1 << 20).await.unwrap().to_vec();
                s2.lock().unwrap().push((p.method.to_string(), p.uri.to_string(), auth, body));
                (StatusCode::IM_A_TEAPOT, [("x-up", "1")], "from upstream")
            }
        });
        let (up, t1) = listen(mock).await;
        let root = tmp();
        let who: Who = Arc::new(Mutex::new(Some(caller("vm-a", "acme/demo"))));
        let w = who.clone();
        let r = router(root.clone(), Arc::new(move |_| w.lock().unwrap().clone()), up, Arc::new(move || budget));
        let (base, t2) = listen(r).await;
        (Rig { base, root, who, http: reqwest::Client::new(), _tasks: vec![t1, t2] }, seen)
    }

    /// Replays a toolkit save: create, 3 blocks (out of order), block list, finalize.
    async fn save_blocks(rig: &Rig, key: &str, version: &str) -> Vec<u8> {
        let (code, j) = rig.twirp("CreateCacheEntry", json!({ "key": key, "version": version })).await;
        assert_eq!((code, &j["ok"]), (StatusCode::OK, &json!(true)), "{j}");
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        assert!(url.contains("/devstoreaccount1/upload/") && url.contains("?sig="), "{url}");
        let ids = ["MzkxMDIx+/0A==", "MzkxMDIx+/0B==", "MzkxMDIx+/0C=="];
        let parts: [Vec<u8>; 3] = [vec![1u8; 70_000], (0..50_000u32).map(|i| i as u8).collect(), b"tail".to_vec()];
        for i in [2usize, 0, 1] {
            let enc = ids[i].replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
            let r = rig
                .http
                .put(format!("{url}&comp=block&blockid={enc}"))
                .header("x-ms-version", "2021-12-02")
                .body(parts[i].clone())
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::CREATED);
            assert!(r.headers().contains_key("x-ms-request-id") && r.headers().contains_key("x-ms-version"));
        }
        let xml = format!(
            "<?xml version=\"1.0\"?><BlockList>{}</BlockList>",
            ids.iter().map(|i| format!("<Latest>{i}</Latest>")).collect::<String>()
        );
        let r = rig.http.put(format!("{url}&comp=blocklist")).header("content-type", "application/xml").body(xml).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let all: Vec<u8> = parts.concat();
        let (code, j) =
            rig.twirp("FinalizeCacheEntryUpload", json!({ "key": key, "size_bytes": all.len().to_string(), "version": version })).await;
        assert_eq!((code, &j["ok"]), (StatusCode::OK, &json!(true)), "{j}");
        assert!(j["entry_id"].is_string());
        all
    }

    #[tokio::test]
    async fn blocks_roundtrip_with_range_and_head() {
        let (rig, _) = rig(1 << 30).await;
        let all = save_blocks(&rig, "linux-npm-1", "ver1").await;
        let (_, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "linux-npm-1", "version": "ver1" })).await;
        assert_eq!(j["matched_key"], "linux-npm-1");
        let url = j["signed_download_url"].as_str().unwrap().to_string();
        let r = rig.http.get(&url).send().await.unwrap();
        assert_eq!((r.status(), r.headers()["content-length"].to_str().unwrap().to_string()), (StatusCode::OK, all.len().to_string()));
        assert_eq!(r.headers()["accept-ranges"], "bytes");
        assert_eq!(r.bytes().await.unwrap().as_ref(), &all[..]);
        // A range across the block 1/2 boundary.
        let r = rig.http.get(&url).header("range", "bytes=69990-70010").send().await.unwrap();
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(r.headers()["content-range"].to_str().unwrap(), format!("bytes 69990-70010/{}", all.len()));
        assert_eq!(r.bytes().await.unwrap().as_ref(), &all[69990..=70010]);
        let r = rig.http.get(&url).header("range", "bytes=-4").send().await.unwrap();
        assert_eq!(r.bytes().await.unwrap().as_ref(), b"tail");
        let r = rig.http.get(&url).header("range", format!("bytes={}-", all.len())).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let r = rig.http.head(&url).send().await.unwrap();
        assert_eq!((r.status(), r.headers()["content-length"].to_str().unwrap().to_string()), (StatusCode::OK, all.len().to_string()));
        // Blocks stay separate files; nothing was concatenated.
        let entry = visible(&rig.root, &caller("vm-a", "acme/demo"))[0].0.clone();
        assert_eq!(std::fs::read_dir(&entry).unwrap().count(), 4, "meta.json + 3 blocks");
    }

    #[tokio::test]
    async fn single_put_blob_roundtrip() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let data = vec![7u8; 300_000];
        let r = rig.http.put(&url).header("x-ms-blob-type", "BlockBlob").body(data.clone()).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        // size_bytes may also arrive as a number; both forms are accepted.
        let (_, j) = rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "k", "size_bytes": data.len(), "version": "v" })).await;
        assert_eq!(j["ok"], true);
        let (_, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "k", "version": "v", "restore_keys": null })).await;
        let r = rig.http.get(j["signed_download_url"].as_str().unwrap()).send().await.unwrap();
        assert_eq!(r.bytes().await.unwrap().as_ref(), &data[..]);
    }

    #[tokio::test]
    async fn restore_key_prefix_hit_and_version_mismatch_miss() {
        let (rig, _) = rig(1 << 30).await;
        save_blocks(&rig, "rust-Linux-abc", "ver1").await;
        let (_, j) = rig
            .twirp(
                "GetCacheEntryDownloadURL",
                json!({ "key": "rust-Linux-zzz", "restore_keys": ["rust-Linux-", "rust-"], "version": "ver1" }),
            )
            .await;
        assert_eq!((j["ok"].clone(), j["matched_key"].clone()), (json!(true), json!("rust-Linux-abc")));
        let (code, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "rust-Linux-abc", "version": "other" })).await;
        assert_eq!((code, j), (StatusCode::OK, json!({ "ok": false })));
        let (_, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "nothing", "version": "ver1" })).await;
        assert_eq!(j, json!({ "ok": false }));
    }

    #[tokio::test]
    async fn create_refused_when_read_only_or_the_key_exists_and_bad_input_is_400() {
        let (rig, _) = rig(1 << 30).await;
        rig.as_caller(Some(Caller { can_write: false, ..caller("vm-a", "acme/demo") }));
        let (code, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!((code, j), (StatusCode::OK, json!({ "ok": false })));
        rig.as_caller(Some(caller("vm-a", "acme/demo")));
        save_blocks(&rig, "k", "v").await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!(j, json!({ "ok": false }), "existing key+version");
        let (code, j) = rig.twirp("CreateCacheEntry", json!({ "key": "", "version": "v" })).await;
        assert_eq!((code, j["code"].clone()), (StatusCode::BAD_REQUEST, json!("invalid_argument")));
        let (code, j) = rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "never", "version": "v", "size_bytes": "1" })).await;
        assert_eq!((code, j["code"].clone()), (StatusCode::NOT_FOUND, json!("not_found")));
    }

    #[tokio::test]
    async fn finalize_with_a_wrong_size_fails_and_drops_the_upload() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        rig.http.put(j["signed_upload_url"].as_str().unwrap()).body(vec![1u8; 10]).send().await.unwrap();
        let (_, j) = rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "k", "version": "v", "size_bytes": "11" })).await;
        assert_eq!(j["ok"], false);
        assert!(visible(&rig.root, &caller("vm-a", "acme/demo")).is_empty());
    }

    #[tokio::test]
    async fn wrong_or_missing_sig_is_403_and_other_vms_cannot_reach_an_entry() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let bare = url.split('?').next().unwrap().to_string();
        for u in [format!("{bare}?sig=deadbeef"), bare.clone()] {
            let r = rig.http.put(&u).body("x").send().await.unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{u}");
        }
        assert_eq!(rig.http.put(&url).body("x").send().await.unwrap().status(), StatusCode::CREATED);
        rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "k", "version": "v", "size_bytes": "1" })).await;
        let (_, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "k", "version": "v" })).await;
        let dl = j["signed_download_url"].as_str().unwrap().to_string();
        let dl_bare = dl.split('?').next().unwrap().to_string();
        assert_eq!(rig.http.get(format!("{dl_bare}?sig=nope")).send().await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(rig.http.get(&dl).send().await.unwrap().status(), StatusCode::OK);
        // Another VM of the same repo holding the URL and sig still can't read vm-a's staged entry; nor can an unidentified peer.
        rig.as_caller(Some(caller("vm-b", "acme/demo")));
        assert_eq!(rig.http.get(&dl).send().await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(rig.http.put(&url).body("x").send().await.unwrap().status(), StatusCode::NOT_FOUND);
        rig.as_caller(None);
        assert_eq!(rig.http.get(&dl).send().await.unwrap().status(), StatusCode::FORBIDDEN);
        // After promotion any VM of the repo reads it with the same URL; another repo does not.
        promote(&rig.root, "vm-a").unwrap();
        rig.as_caller(Some(caller("vm-b", "acme/demo")));
        assert_eq!(rig.http.get(&dl).send().await.unwrap().status(), StatusCode::OK);
        rig.as_caller(Some(caller("vm-c", "acme/other")));
        assert_eq!(rig.http.get(&dl).send().await.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unidentified_and_non_local_callers_and_other_services_are_proxied() {
        let (rig, seen) = rig(1 << 30).await;
        rig.as_caller(None);
        let r = rig
            .http
            .post(format!("{}{CACHE_SVC}CreateCacheEntry?x=1", rig.base))
            .header("authorization", "Bearer secret-token")
            .header("content-type", "application/json")
            .body(r#"{"key":"k","version":"v"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!((r.status(), r.headers()["x-up"].to_str().unwrap().to_string()), (StatusCode::IM_A_TEAPOT, "1".into()));
        assert_eq!(r.text().await.unwrap(), "from upstream");
        {
            let s = seen.lock().unwrap();
            assert_eq!(
                (s[0].0.as_str(), s[0].1.as_str()),
                ("POST", format!("{CACHE_SVC}CreateCacheEntry?x=1").as_str()),
                "path and query kept"
            );
            assert_eq!((s[0].2.as_str(), s[0].3.as_slice()), ("Bearer secret-token", &br#"{"key":"k","version":"v"}"#[..]));
        }
        assert!(!rig.root.join("staged").exists(), "nothing stored locally");
        // Identified but the local cache is off for this VM.
        rig.as_caller(Some(Caller { local: false, ..caller("vm-a", "acme/demo") }));
        rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "k", "version": "v" })).await;
        assert_eq!(seen.lock().unwrap().len(), 2);
        // Identified and local: ArtifactService, protobuf CacheService, unknown RPCs and other paths still go upstream.
        rig.as_caller(Some(caller("vm-a", "acme/demo")));
        rig.http
            .post(format!("{}/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact", rig.base))
            .json(&json!({ "name": "a" }))
            .send()
            .await
            .unwrap();
        rig.http
            .post(format!("{}{CACHE_SVC}CreateCacheEntry", rig.base))
            .header("content-type", "application/protobuf")
            .body(vec![0x12, 1, b'k'])
            .send()
            .await
            .unwrap();
        rig.twirp("DeleteCacheEntry", json!({})).await;
        let r = rig.http.get(format!("{}/some/other/path?q=1", rig.base)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(seen.lock().unwrap().len(), 6);
        assert_eq!(seen.lock().unwrap()[3].3, vec![0x12, 1, b'k'], "protobuf body intact");
        assert!(!rig.root.join("staged").exists());
        // A dead upstream is a 502, not a hang or a panic.
        let (dead, _t) = listen(router(tmp(), Arc::new(|_| None), "http://127.0.0.1:1".into(), Arc::new(|| 1 << 30))).await;
        assert_eq!(reqwest::get(format!("{dead}/x")).await.unwrap().status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn ping_is_204_and_quota_is_enforced_with_lru_eviction() {
        let (rig, _) = rig(100_000).await;
        assert_eq!(rig.http.get(format!("{}/_kiln/ping", rig.base)).send().await.unwrap().status(), StatusCode::NO_CONTENT);
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let r = rig.http.put(&url).body(vec![0u8; 150_000]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE, "over the quota with nothing to evict");
        // Over the quota, least recently used trusted entries make room.
        seed(&rig.root, "trusted", &caller("vm-z", "acme/demo"), "old", "v", 1, &[0u8; 80_000]);
        let r = rig.http.put(&url).body(vec![0u8; 60_000]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        assert!(entries_in(&trusted_dir(&rig.root, "acme/demo")).is_empty(), "evicted");
    }
}
