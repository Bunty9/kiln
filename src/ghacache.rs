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
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub(crate) const PORT: u16 = 5001;
const UPSTREAM: &str = "https://results-receiver.actions.githubusercontent.com";
#[cfg(test)]
const CACHE_SVC: &str = "/twirp/github.actions.results.api.v1.CacheService/";
/// Largest single entry.
const ENTRY_CAP: u64 = 10 << 30;
/// Most one VM may have staged (uploads in progress plus finished, not yet promoted).
const STAGED_CAP: u64 = 10 << 30;
/// Most blocks one entry's block list may name.
const MAX_BLOCKS: usize = 4096;
/// Twirp and block-list bodies are tiny; anything bigger is a mistake.
const SMALL_BODY: usize = 1 << 20;

/// Who is on the other end of a connection, as decided by the host (never by the job).
#[derive(Clone, Debug)]
pub struct Caller {
    pub vm_id: String,
    /// The repo's canonical identity (forge kind, host and full path, see `vm::repo_identity`). It picks the trusted
    /// scope directory (by hash) and is stored in, and checked against, every entry's metadata.
    pub repo: String,
    /// The local cache is on for this VM; otherwise CacheService is proxied too.
    pub local: bool,
    /// May create entries (the verdict that later allows `promote`); reads are always allowed.
    pub can_write: bool,
}

/// Peer address (and the request headers, for the identity cross-check only) -> caller. `None` = unknown: proxy everything.
pub type Resolver = Arc<dyn Fn(SocketAddr, &HeaderMap) -> Option<Caller> + Send + Sync>;

struct Inner {
    root: PathBuf,
    resolve: Resolver,
    upstream: String,
    budget: Arc<dyn Fn() -> u64 + Send + Sync>,
    http: reqwest::Client,
    /// Serialises metadata read-modify-write (create, finalize, block list, the commit of a blob). Blob bytes stream
    /// outside it. Async, so it can be held while the filesystem work runs on a blocking thread.
    // ponytail: one global lock; per-VM locks if metadata calls ever show up in a profile.
    lock: Arc<tokio::sync::Mutex<()>>,
}
type St = Arc<Inner>;

pub fn router(root: PathBuf, resolve: Resolver, upstream: String, budget: Arc<dyn Fn() -> u64 + Send + Sync>) -> Router {
    let http = reqwest::Client::builder()
        .user_agent("kiln-ci")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("http client");
    let st: St = Arc::new(Inner { root, resolve, upstream, budget, http, lock: Arc::new(tokio::sync::Mutex::new(())) });
    Router::new()
        .route("/_kiln/ping", get(|| async { StatusCode::NO_CONTENT }))
        .route("/twirp/github.actions.results.api.v1.CacheService/{method}", post(twirp))
        .route("/devstoreaccount1/upload/{id}", put(put_blob).layer(axum::extract::DefaultBodyLimit::disable()))
        .route("/download/{id}", get(download))
        .fallback(proxy)
        .with_state(st)
}

/// Serve on 127.0.0.1:5001 (Linux only). Always on: a peer that is not a live kiln VM is proxied to GitHub untouched.
pub async fn serve(app: Arc<crate::App>) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let root = app.data.join("gha-cache");
    // Uploads staged by VMs that are gone (a crash, a restart) never earned a promotion.
    let live: Vec<String> = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).map(|v| v.id.clone()).collect();
    let r = root.clone();
    // Also seeds the byte accounting from disk, once (always: the first PUT must not walk the store).
    let _ = tokio::task::spawn_blocking(move || {
        acct(&r, |_| ());
        discard_dead(&r, &live)
    })
    .await;
    let a = app.clone();
    let budget: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || a.cfg().gha_cache_gb << 30);
    let r = router(root, crate::vm::gha_resolver(app.clone(), SocketAddr::from(([127, 0, 0, 1], PORT))), UPSTREAM.into(), budget);
    // Retried with a doubling delay, like the registry mirror: a port another process holds for a minute at boot
    // must not leave patched images without their Results proxy until the next restart.
    let (mut wait, mut warned) = (1u64, false);
    while !app.stopping.load(std::sync::atomic::Ordering::SeqCst) {
        match tokio::net::TcpListener::bind(("127.0.0.1", PORT)).await {
            Ok(l) => {
                (wait, warned) = (1, false);
                if let Err(e) = axum::serve(l, r.clone().into_make_service_with_connect_info::<SocketAddr>()).await {
                    tracing::warn!("actions cache listener ended: {e}");
                }
            }
            Err(e) if !warned => {
                warned = true;
                tracing::warn!(
                    "actions cache: cannot listen on 127.0.0.1:{PORT}: {e}; jobs on patched images lose the Results proxy (artifacts) until it binds, retrying"
                );
            }
            Err(_) => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        wait = (wait * 2).min(60);
    }
}

/// What a VM's job did with the cache, counted as it happens: (restored, saved). Taken by `finish_cache`.
// ponytail: process-wide map keyed by VM id; an observer in `router` if a second consumer ever needs events.
static STATS: Mutex<Option<HashMap<String, (u32, u32)>>> = Mutex::new(None);

pub(crate) fn count(vm: &str, restored: u32, saved: u32) {
    let mut g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_default().entry(vm.to_string()).or_default();
    (e.0, e.1) = (e.0 + restored, e.1 + saved);
}

pub fn take_stats(vm: &str) -> (u32, u32) {
    STATS.lock().unwrap_or_else(|e| e.into_inner()).as_mut().and_then(|m| m.remove(vm)).unwrap_or_default()
}

/// Delete the staged dirs of every VM not in `live`.
pub fn discard_dead(root: &FsPath, live: &[String]) {
    let keep: Vec<String> = live.iter().map(|v| stem(v)).collect();
    for e in std::fs::read_dir(root.join("staged")).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name) {
            let _ = remove_counted(root, &e.path(), Some(&name));
            acct(root, |a| a.staged.remove(&name));
        }
    }
}

// ---------------------------------------------------------------- byte accounting

/// What the store holds, kept in memory so a PUT never walks the disk: all bytes (trusted and staged, reservations
/// of uploads in flight included) and the staged bytes per VM (keyed by `stem`).
#[derive(Default)]
struct Acct {
    used: u64,
    staged: HashMap<String, u64>,
}

static ACCT: Mutex<Option<HashMap<PathBuf, Acct>>> = Mutex::new(None);

/// Run `f` on the store's account; the first time for a root it is seeded from disk (outside the lock).
// ponytail: counts drift a little (a block replaced while its bytes are in flight); the hourly evict only subtracts what it
// frees, a restart re-seeds. Re-walk in the sweep if the drift ever matters.
fn acct<R>(root: &FsPath, f: impl FnOnce(&mut Acct) -> R) -> R {
    let known = ACCT.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_default().contains_key(root);
    let seed = (!known).then(|| {
        let staged: HashMap<String, u64> = std::fs::read_dir(root.join("staged"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| (e.file_name().to_string_lossy().into_owned(), dir_size(&e.path())))
            .collect();
        Acct { used: dir_size(root), staged }
    });
    let mut g = ACCT.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_default().entry(root.to_path_buf()).or_insert_with(|| seed.unwrap_or_default()))
}

/// Give back `n` bytes (of `vm`'s staged ones, when it is one's).
fn sub(root: &FsPath, vm: Option<&str>, n: u64) {
    acct(root, |a| {
        a.used = a.used.saturating_sub(n);
        if let Some(s) = vm.and_then(|v| a.staged.get_mut(&stem(v))) {
            *s = s.saturating_sub(n);
        }
    });
}

/// `remove_dir_all` that keeps the account right.
fn remove_counted(root: &FsPath, dir: &FsPath, vm: Option<&str>) -> std::io::Result<()> {
    acct(root, |_| ()); // seed before the bytes go
    let n = dir_size(dir);
    let r = std::fs::remove_dir_all(dir);
    if r.is_ok() {
        sub(root, vm, n);
    }
    r
}

/// Bytes set aside for one upload; released when dropped unless committed.
struct Reservation {
    root: PathBuf,
    vm: String,
    n: u64,
}

impl Reservation {
    /// The bytes are on disk now; `replaced` is what the file they overwrote held.
    fn commit(mut self, replaced: u64) {
        sub(&self.root, Some(&self.vm), replaced);
        self.n = 0;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.n > 0 {
            sub(&self.root, Some(&self.vm), self.n);
        }
    }
}

/// Reserve `len` bytes for a PUT by `vm`, or say why not: 413 over the VM's staged cap, 507 over the store's budget.
/// Never evicts: staged bytes must not push trusted entries out.
fn reserve(root: &FsPath, vm: &str, len: u64, budget: u64) -> Result<Reservation, StatusCode> {
    acct(root, |a| {
        let staged = a.staged.entry(stem(vm)).or_default();
        if staged.saturating_add(len) > STAGED_CAP {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        if a.used.saturating_add(len) > budget {
            return Err(StatusCode::INSUFFICIENT_STORAGE);
        }
        *staged += len;
        a.used += len;
        Ok(Reservation { root: root.to_path_buf(), vm: vm.to_string(), n: len })
    })
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
    /// Full identity of the repo the entry belongs to (where `promote` puts it). Checked on every read, download and
    /// promote: an entry whose identity differs from the caller's does not exist for it.
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

/// Directory of a repo's trusted scope: a short readable slug plus the hex SHA-256 of the identity. The hash makes
/// the mapping injective (the slug is decoration), so no two repos share a directory.
fn repo_dir(root: &FsPath, identity: &str) -> PathBuf {
    let slug: String = stem(identity).chars().take(32).collect();
    root.join("repos").join(format!("{slug}-{}", hex(ring::digest::digest(&ring::digest::SHA256, identity.as_bytes()).as_ref())))
}

fn trusted_dir(root: &FsPath, repo: &str) -> PathBuf {
    repo_dir(root, repo).join("entries")
}

type Usage = (u64, HashMap<String, (u32, u64)>);
static USAGE: Mutex<Option<(PathBuf, std::time::Instant, Usage)>> = Mutex::new(None);

/// What the trusted scopes hold: total bytes and, per repo identity, (entries, bytes). Walked at most once a minute
/// (the dashboard polls /api/state); a clear forgets it so the list is right at once.
// ponytail: one cached walk keyed by root; an incremental index if a store ever has so many entries the walk shows up.
pub fn usage(root: &FsPath) -> Usage {
    if let Some((r, at, u)) = &*USAGE.lock().unwrap_or_else(|e| e.into_inner())
        && r == root
        && at.elapsed().as_secs() < 60
    {
        return u.clone();
    }
    let mut per: HashMap<String, (u32, u64)> = HashMap::new();
    for r in std::fs::read_dir(root.join("repos")).into_iter().flatten().flatten() {
        for (dir, m) in entries_in(&r.path().join("entries")) {
            let e = per.entry(m.repo).or_default();
            (e.0, e.1) = (e.0 + 1, e.1 + dir_size(&dir));
        }
    }
    let u = (per.values().map(|e| e.1).sum(), per);
    *USAGE.lock().unwrap_or_else(|e| e.into_inner()) = Some((root.to_path_buf(), std::time::Instant::now(), u.clone()));
    u
}

/// Delete a repo's trusted entries (dashboard "clear cache").
pub fn clear_repo(root: &FsPath, identity: &str) -> std::io::Result<()> {
    *USAGE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    match remove_counted(root, &repo_dir(root, identity), None) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
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
    v.retain(|(_, m)| m.finished && m.repo == c.repo);
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

/// Serialises promotions: two VMs promoting the same key must leave exactly one entry (first writer wins).
static PROMOTE: Mutex<()> = Mutex::new(());

/// Move the VM's finished staged entries into their repo's trusted scope, skipping keys that already exist there
/// (first writer wins). Returns (promoted, dropped). Unfinished uploads are dropped.
pub fn promote(root: &FsPath, vm_id: &str) -> Result<(usize, usize)> {
    let _g = PROMOTE.lock().unwrap_or_else(|e| e.into_inner());
    let (mut ok, mut dropped) = (0, 0);
    for (dir, m) in entries_in(&staged_dir(root, vm_id)) {
        let dest = trusted_dir(root, &m.repo);
        let dup = entries_in(&dest).iter().any(|(_, t)| t.finished && t.repo == m.repo && t.key == m.key && t.version == m.version);
        if !m.finished || dup {
            remove_counted(root, &dir, Some(vm_id))?;
            dropped += 1;
            continue;
        }
        std::fs::create_dir_all(&dest)?;
        let target = dest.join(dir.file_name().unwrap_or_default());
        std::fs::rename(&dir, &target)?;
        // (A failure here skips the discard below; the entry is then in the trusted scope without its flag and the
        // caller discards the rest.)
        write_meta(&target, &Meta { scope: "trusted".into(), ..m })?;
        ok += 1;
    }
    discard(root, vm_id);
    Ok((ok, dropped))
}

/// Delete everything the VM staged (also uploads still in progress).
pub fn discard(root: &FsPath, vm_id: &str) {
    if let Err(e) = remove_counted(root, &staged_dir(root, vm_id), Some(vm_id))
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("actions cache: cannot delete {vm_id}'s staged uploads: {e}");
    }
    acct(root, |a| a.staged.remove(&stem(vm_id)));
}

/// Delete trusted entries, least recently used first, until the trusted entries fit the budget. Staged uploads are
/// never a reason to evict (they are refused at the PUT instead). Returns bytes freed.
pub fn evict(root: &FsPath, budget: u64) -> u64 {
    acct(root, |_| ()); // seed before anything goes
    let mut all: Vec<_> = std::fs::read_dir(root.join("repos"))
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|r| entries_in(&r.path().join("entries")))
        .map(|(d, m)| (dir_size(&d), d, m.last_used))
        .collect();
    let mut used: u64 = all.iter().map(|e| e.0).sum();
    all.sort_by_key(|e| e.2);
    let mut freed = 0;
    for (s, dir, _) in all {
        if used <= budget {
            break;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => (used, freed) = (used.saturating_sub(s), freed + s),
            Err(e) => tracing::warn!("actions cache: cannot evict {}: {e}", dir.display()),
        }
    }
    sub(root, None, freed);
    freed
}

/// Does `c` see a finished entry for exactly `key` (tests of other modules).
#[cfg(test)]
pub(crate) fn lookup_for_tests(root: &FsPath, c: &Caller, key: &str) -> bool {
    visible(root, c).iter().any(|(_, m)| m.key == key)
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
    let c = if json && known {
        let (s2, h) = (st.clone(), req.headers().clone());
        blocking(move || (s2.resolve)(peer, &h)).await.flatten().filter(|c| c.local)
    } else {
        None
    };
    let Some(c) = c else { return proxy(State(st), req).await };
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
    let g = st.lock.clone().lock_owned().await;
    let s2 = st.clone();
    blocking(move || {
        let _g = g;
        match method.as_str() {
            "CreateCacheEntry" => create(&s2, &c, &r, &host),
            "FinalizeCacheEntryUpload" => finalize(&s2, &c, &r),
            _ => get_url(&s2, &c, &r, &host),
        }
    })
    .await
    .unwrap_or_else(|| twirp_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the cache task failed"))
}

/// Filesystem work runs here, never on the async runtime's threads. None = the task panicked.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

fn create(st: &Inner, c: &Caller, r: &TwirpReq, host: &str) -> Response {
    // Also refused: a second create for a key this VM is still uploading, which would replace the first reservation.
    let uploading =
        || entries_in(&staged_dir(&st.root, &c.vm_id)).iter().any(|(_, m)| !m.finished && m.key == r.key && m.version == r.version);
    // Already at a cap: say "skip saving" now (clients accept that), rather than failing the export at the PUT.
    let full = acct(&st.root, |a| a.used >= (st.budget)() || a.staged.get(&stem(&c.vm_id)).is_some_and(|s| *s >= STAGED_CAP));
    if !c.can_write || full || visible(&st.root, c).iter().any(|(_, m)| m.key == r.key && m.version == r.version) || uploading() {
        return json_resp(StatusCode::OK, json!({ "ok": false }));
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
        repo: c.repo.clone(),
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
        let _ = remove_counted(&st.root, &dir, Some(&c.vm_id));
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
    count(&c.vm_id, 0, 1);
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
    if let Err(e) = write_meta(&dir, &m) {
        tracing::debug!("actions cache: cannot record last use of {}: {e}", m.key);
    }
    count(&c.vm_id, 1, 0);
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
async fn entry_for(
    st: &St,
    peer: SocketAddr,
    h: &HeaderMap,
    id: &str,
    q: &HashMap<String, String>,
) -> Result<(Caller, PathBuf, Meta), StatusCode> {
    let (st, h, id, q) = (st.clone(), h.clone(), id.to_string(), q.clone());
    blocking(move || entry_for_blocking(&st, peer, &h, &id, &q)).await.unwrap_or(Err(StatusCode::INTERNAL_SERVER_ERROR))
}

fn entry_for_blocking(
    st: &Inner,
    peer: SocketAddr,
    h: &HeaderMap,
    id: &str,
    q: &HashMap<String, String>,
) -> Result<(Caller, PathBuf, Meta), StatusCode> {
    let c = (st.resolve)(peer, h).filter(|c| c.local).ok_or(StatusCode::FORBIDDEN)?;
    if !valid_id(id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let (dir, m) = [staged_dir(&st.root, &c.vm_id).join(id), trusted_dir(&st.root, &c.repo).join(id)]
        .into_iter()
        .find_map(|d| Some((d.clone(), read_meta(&d)?)))
        .ok_or(StatusCode::NOT_FOUND)?;
    if m.repo != c.repo {
        return Err(StatusCode::NOT_FOUND);
    }
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

/// Stream `body` into a fresh temp file next to `dest`; exactly `len` bytes or an error. The caller renames it into
/// place once it has checked, under the lock, that the entry still takes writes.
async fn save(body: Body, dest: &FsPath, len: u64) -> Result<Tmp, StatusCode> {
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
    let tmp = Tmp(dest.with_file_name(format!("{name}.{}.part", random_hex(6))));
    let r: Result<(), StatusCode> = async {
        let mut f = tokio::fs::File::create(&tmp.0).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    r.map(|()| tmp)
}

/// A temp upload file that is unlinked when dropped (a cancelled request, an error, a refusal); after the rename into
/// place there is nothing left to unlink.
struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn put_blob(
    State(st): State<St>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let (c, dir, m) = match entry_for(&st, peer, req.headers(), &id, &q).await {
        Ok(x) => x,
        Err(e) => return status(e),
    };
    // Writes only into this VM's own unfinished upload.
    if m.finished || m.scope != "staged" || !c.can_write || dir != staged_dir(&st.root, &c.vm_id).join(&id) {
        return status(StatusCode::FORBIDDEN);
    }
    let comp = q.get("comp").map_or("", String::as_str);
    if comp == "blocklist" {
        let Ok(body) = axum::body::to_bytes(req.into_body(), SMALL_BODY).await else { return status(StatusCode::BAD_REQUEST) };
        let blocks: Vec<String> = block_ids(&String::from_utf8_lossy(&body)).iter().map(|b| block_file(b)).collect();
        let g = st.lock.clone().lock_owned().await;
        let (root, vm) = (st.root.clone(), c.vm_id.clone());
        return blocking(move || {
            let _g = g;
            let Some(mut m) = read_meta(&dir).filter(|m| !m.finished) else { return status(StatusCode::FORBIDDEN) };
            // One descriptor per listed block is opened per download: no repeats, no endless lists.
            let distinct = blocks.iter().collect::<std::collections::HashSet<_>>().len() == blocks.len();
            if blocks.is_empty() || blocks.len() > MAX_BLOCKS || !distinct || blocks.iter().any(|b| !dir.join(b).is_file()) {
                return status(StatusCode::BAD_REQUEST);
            }
            // Blocks the list does not name are dropped; the list's order is the serving order.
            let mut freed = 0;
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n == "meta.json" || blocks.contains(&n) {
                    continue;
                }
                let sz = e.metadata().map_or(0, |m| m.len()); // before the file is gone
                if std::fs::remove_file(e.path()).is_ok() && !n.ends_with(".part") {
                    freed += sz;
                }
            }
            sub(&root, Some(&vm), freed);
            m.blocks = blocks;
            if write_meta(&dir, &m).is_ok() { azure_ok() } else { status(StatusCode::INTERNAL_SERVER_ERROR) }
        })
        .await
        .unwrap_or_else(|| status(StatusCode::INTERNAL_SERVER_ERROR));
    }
    let Some(len) = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) else {
        return status(StatusCode::LENGTH_REQUIRED);
    };
    let name = match comp {
        "" => "blob".to_string(),
        "block" => match q.get("blockid") {
            Some(b) if !b.is_empty() => block_file(b),
            _ => return status(StatusCode::BAD_REQUEST),
        },
        _ => return status(StatusCode::NOT_IMPLEMENTED),
    };
    if len > ENTRY_CAP {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let dest = dir.join(&name);
    // Refused, not made room for: staged bytes never evict trusted entries. Released again if the PUT fails.
    let rsv = match reserve(&st.root, &c.vm_id, len, (st.budget)()) {
        Ok(r) => r,
        Err(e) => return status(e),
    };
    let tmp = match save(req.into_body(), &dest, len).await {
        Ok(t) => t,
        Err(e) => return status(e),
    };
    // Re-check under the lock: a finalize may have happened while the bytes streamed in (a discard or promotion does not
    // take it; the dir is then gone and the rename fails, and the hourly `discard_dead` takes any leftover).
    let (g, whole) = (st.lock.clone().lock_owned().await, comp.is_empty());
    let done = blocking(move || {
        let _g = g;
        match read_meta(&dir) {
            Some(mut m) if !m.finished => {
                // Read under the lock, so concurrent PUTs of one block id each see what the other left.
                let replaced = std::fs::metadata(&dest).map_or(0, |m| m.len());
                std::fs::rename(&tmp.0, &dest).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                if whole {
                    // Put Blob is the whole entry; it replaces anything earlier.
                    m.blocks = vec![name];
                    write_meta(&dir, &m).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }
                Ok(replaced)
            }
            _ => Err(StatusCode::FORBIDDEN),
        }
    })
    .await;
    match done {
        Some(Ok(replaced)) => {
            rsv.commit(replaced);
            azure_ok()
        }
        Some(Err(e)) => status(e),
        None => status(StatusCode::INTERNAL_SERVER_ERROR),
    }
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
    let (_, dir, m) = match entry_for(&st, peer, &headers, &id, &q).await {
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
        let Ok(md) = tokio::fs::metadata(dir.join(blk)).await else { return status(StatusCode::NOT_FOUND) };
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
        // Every segment is opened before the response starts: an eviction or a clear that unlinks a file mid-download
        // cannot cut the body short (the open descriptors keep the bytes).
        let mut files = vec![];
        for (p, off, n) in segs {
            let Ok(mut f) = tokio::fs::File::open(p).await else { return status(StatusCode::NOT_FOUND) };
            if f.seek(SeekFrom::Start(off)).await.is_err() {
                return status(StatusCode::INTERNAL_SERVER_ERROR);
            }
            files.push((f, n));
        }
        Body::from_stream(
            futures_util::stream::iter(files).map(|(f, n)| tokio_util::io::ReaderStream::with_capacity(f.take(n), 256 << 10)).flatten(),
        )
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

/// Proxy failures are logged at most once a minute: a dead upstream would otherwise fill the log with every request.
fn proxy_warn_due() -> bool {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = now_ms();
    now.saturating_sub(LAST.load(std::sync::atomic::Ordering::Relaxed)) >= 60_000
        && LAST.swap(now, std::sync::atomic::Ordering::Relaxed) != now
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
            if proxy_warn_due() {
                tracing::warn!("actions cache proxy {} {}: {}", parts.method, parts.uri.path(), e.without_url());
            }
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
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!("kiln-ghacache-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub(crate) fn caller(vm: &str, repo: &str) -> Caller {
        Caller { vm_id: vm.into(), repo: repo.into(), local: true, can_write: true }
    }

    /// A finished entry written straight to disk.
    pub(crate) fn seed(root: &FsPath, scope: &str, c: &Caller, key: &str, version: &str, created: u64, data: &[u8]) -> PathBuf {
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
            repo: c.repo.clone(),
            sig: random_hex(32),
            finished: true,
        };
        write_meta(&dir, &m).unwrap();
        dir
    }

    #[test]
    fn usage_counts_per_repo_and_a_clear_forgets_it() {
        let root = tmp();
        let (a, b) = (caller("v", "github|github.com|acme/a"), caller("v", "github|github.com|acme/b"));
        seed(&root, "trusted", &a, "k1", "v", 1, b"12345");
        seed(&root, "trusted", &a, "k2", "v", 2, b"123");
        seed(&root, "trusted", &b, "k1", "v", 1, b"1");
        seed(&root, "staged", &b, "k9", "v", 1, b"not counted");
        let (total, per) = usage(&root);
        assert_eq!((per[&a.repo].0, per[&b.repo].0), (2, 1));
        assert!(per[&a.repo].1 > per[&b.repo].1 && total == per[&a.repo].1 + per[&b.repo].1 && !per.contains_key("nobody"));
        clear_repo(&root, &a.repo).unwrap();
        assert!(!usage(&root).1.contains_key(&a.repo), "cleared at once, not after a minute");
    }

    /// `stem` is not injective ("my.repo" and "my_repo" collide); the storage key must be.
    #[test]
    fn repos_whose_stems_collide_never_see_each_other() {
        let root = tmp();
        let (a, b) = (caller("vm-a", "github|github.com|acme/my.repo"), caller("vm-b", "github|github.com|acme/my_repo"));
        assert_eq!(stem(&a.repo), stem(&b.repo), "the old key collides");
        assert_ne!(trusted_dir(&root, &a.repo), trusted_dir(&root, &b.repo));
        let dir = seed(&root, "trusted", &a, "k", "v", 1, b"a's");
        assert!(lookup(&root, &b, "k", &[], "v").is_none());
        assert!(lookup(&root, &a, "k", &[], "v").is_some());
        // Even an entry copied into the other repo's directory is refused: its stored identity is checked.
        let planted = trusted_dir(&root, &b.repo).join("0".repeat(32));
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::rename(&dir, &planted).unwrap();
        assert!(visible(&root, &b).is_empty() && visible(&root, &a).is_empty());
        // ...and so is promoting under the wrong identity: promote files an entry by the identity it carries.
        let s = seed(&root, "staged", &a, "p", "v", 2, b"p");
        assert_eq!(promote(&root, "vm-a").unwrap(), (1, 0));
        assert!(!s.exists());
        assert!(lookup(&root, &a, "p", &[], "v").is_some() && lookup(&root, &b, "p", &[], "v").is_none());
        clear_repo(&root, &b.repo).unwrap();
        assert!(lookup(&root, &a, "p", &[], "v").is_some(), "clearing one repo leaves the other");
        clear_repo(&root, &a.repo).unwrap();
        assert!(lookup(&root, &a, "p", &[], "v").is_none());
    }

    #[test]
    fn dead_vms_staged_dirs_are_discarded_and_stats_are_taken_once() {
        let root = tmp();
        let (live, dead) = (caller("vm-live", "r"), caller("vm-dead", "r"));
        let (l, d) = (seed(&root, "staged", &live, "k", "v", 1, b"x"), seed(&root, "staged", &dead, "k", "v", 1, b"x"));
        discard_dead(&root, &["vm-live".into()]);
        assert!(l.exists() && !d.exists());
        count("vm-stat", 2, 0);
        count("vm-stat", 1, 1);
        assert_eq!(take_stats("vm-stat"), (3, 1));
        assert_eq!(take_stats("vm-stat"), (0, 0));
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
        let r = router(root.clone(), Arc::new(move |_, _| w.lock().unwrap().clone()), up, Arc::new(move || budget));
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
        let (dead, _t) = listen(router(tmp(), Arc::new(|_, _| None), "http://127.0.0.1:1".into(), Arc::new(|| 1 << 30))).await;
        assert_eq!(reqwest::get(format!("{dead}/x")).await.unwrap().status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn ping_is_204_and_a_put_over_the_budget_is_refused_not_made_room_for() {
        let (rig, _) = rig(100_000).await;
        assert_eq!(rig.http.get(format!("{}/_kiln/ping", rig.base)).send().await.unwrap().status(), StatusCode::NO_CONTENT);
        seed(&rig.root, "trusted", &caller("vm-z", "acme/demo"), "old", "v", 1, &[0u8; 80_000]);
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let r = rig.http.put(&url).body(vec![0u8; 150_000]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE);
        // Staged bytes never evict a trusted entry; the refused PUT released its reservation, so a smaller one fits.
        let r = rig.http.put(&url).body(vec![0u8; 60_000]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(entries_in(&trusted_dir(&rig.root, "acme/demo")).len(), 1, "the trusted entry stays");
        let r = rig.http.put(&url).body(vec![0u8; 15_000]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        // Only a promotion (or the sweep) evicts, and only trusted entries.
        assert_eq!(evict(&rig.root, 100_000), 0);
        assert!(evict(&rig.root, 10_000) > 0);
        assert!(entries_in(&trusted_dir(&rig.root, "acme/demo")).is_empty());
        assert!(!entries_in(&staged_dir(&rig.root, "vm-a")).is_empty(), "staged uploads are not evicted");
    }

    #[test]
    fn reservations_enforce_the_vm_cap_and_the_budget_and_are_released() {
        let root = tmp();
        let r = reserve(&root, "vm-a", STAGED_CAP - 10, u64::MAX).unwrap();
        assert_eq!(reserve(&root, "vm-a", 11, u64::MAX).err(), Some(StatusCode::PAYLOAD_TOO_LARGE), "over the VM's staged cap");
        assert!(reserve(&root, "vm-b", 11, u64::MAX).is_ok(), "another VM has its own cap");
        drop(r);
        assert!(reserve(&root, "vm-a", STAGED_CAP, u64::MAX).is_ok(), "released on drop");
        let root = tmp();
        std::fs::create_dir_all(staged_dir(&root, "vm-a")).unwrap();
        std::fs::write(staged_dir(&root, "vm-a").join("blob"), [0u8; 600]).unwrap(); // seeds the account
        assert_eq!(reserve(&root, "vm-b", 401, 1000).err(), Some(StatusCode::INSUFFICIENT_STORAGE), "over the store budget");
        let r = reserve(&root, "vm-b", 400, 1000).unwrap();
        r.commit(0);
        assert_eq!(reserve(&root, "vm-b", 1, 1000).err(), Some(StatusCode::INSUFFICIENT_STORAGE), "committed bytes stay counted");
        discard(&root, "vm-a");
        assert!(reserve(&root, "vm-c", 600, 1000).is_ok(), "a discard gives the bytes back");
    }

    fn used(root: &FsPath) -> u64 {
        acct(root, |a| a.used)
    }

    #[tokio::test]
    async fn a_block_list_that_drops_a_block_gives_its_bytes_back() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        for (id, n) in [("QQ%3D%3D", 100), ("Qg%3D%3D", 5000)] {
            rig.http.put(format!("{url}&comp=block&blockid={id}")).body(vec![1u8; n]).send().await.unwrap();
        }
        assert_eq!(used(&rig.root), 5100);
        let list = "<BlockList><Latest>QQ==</Latest></BlockList>";
        assert_eq!(rig.http.put(format!("{url}&comp=blocklist")).body(list).send().await.unwrap().status(), StatusCode::CREATED);
        assert_eq!(used(&rig.root), 100, "the dropped block's bytes are released");
    }

    #[tokio::test]
    async fn concurrent_puts_of_one_block_id_leave_the_account_equal_to_the_disk() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = format!("{}&comp=block&blockid=QQ%3D%3D", j["signed_upload_url"].as_str().unwrap());
        for _ in 0..5 {
            let puts: Vec<_> = (0..2).map(|_| rig.http.put(&url).body(vec![2u8; 1000]).send()).collect();
            for r in futures_util::future::join_all(puts).await {
                assert_eq!(r.unwrap().status(), StatusCode::CREATED);
            }
            assert_eq!(used(&rig.root), 1000);
            assert_eq!(
                dir_size(&rig.root),
                1000 + std::fs::metadata(entries_in(&staged_dir(&rig.root, "vm-a"))[0].0.join("meta.json")).unwrap().len()
            );
        }
    }

    #[tokio::test]
    async fn a_block_list_with_repeats_or_too_many_blocks_is_400() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        rig.http.put(format!("{url}&comp=block&blockid=QQ%3D%3D")).body("x").send().await.unwrap();
        let bl = |xml: String| rig.http.put(format!("{url}&comp=blocklist")).body(xml).send();
        let dup = "<BlockList><Latest>QQ==</Latest><Latest>QQ==</Latest></BlockList>";
        assert_eq!(bl(dup.into()).await.unwrap().status(), StatusCode::BAD_REQUEST, "a repeated block id");
        // More blocks than allowed, every one present on disk, so only the cap can refuse it.
        let dir = entries_in(&staged_dir(&rig.root, "vm-a")).remove(0).0;
        let ids: Vec<String> = (0..=MAX_BLOCKS).map(|i| format!("id{i}")).collect();
        for i in &ids {
            std::fs::write(dir.join(block_file(i)), "x").unwrap();
        }
        let xml = format!("<BlockList>{}</BlockList>", ids.iter().map(|i| format!("<Latest>{i}</Latest>")).collect::<String>());
        assert_eq!(bl(xml).await.unwrap().status(), StatusCode::BAD_REQUEST, "too many blocks");
        let ok =
            format!("<BlockList>{}</BlockList>", ids[..MAX_BLOCKS].iter().map(|i| format!("<Latest>{i}</Latest>")).collect::<String>());
        assert_eq!(bl(ok).await.unwrap().status(), StatusCode::CREATED, "the cap itself is fine");
    }

    #[tokio::test]
    async fn create_says_skip_when_a_cap_is_already_reached() {
        let (full, _) = rig(1000).await;
        seed(&full.root, "trusted", &caller("vm-z", "acme/demo"), "old", "v", 1, &[0u8; 1000]);
        let (code, j) = full.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!((code, j), (StatusCode::OK, json!({ "ok": false })), "store full: skip saving, no export error later");
        let (capped, _) = rig(u64::MAX).await;
        let _held = reserve(&capped.root, "vm-a", STAGED_CAP, u64::MAX).unwrap();
        let (_, j) = capped.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!(j, json!({ "ok": false }), "the VM's staged cap reached");
    }

    #[tokio::test]
    async fn a_dropped_upload_leaves_no_part_file() {
        let dir = tmp();
        let slow = futures_util::stream::once(async { std::io::Result::Ok(vec![1u8; 10]) }).chain(futures_util::stream::pending());
        let r = tokio::time::timeout(std::time::Duration::from_millis(100), save(Body::from_stream(slow), &dir.join("b"), 100)).await;
        assert!(r.is_err(), "still streaming when the request is dropped");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_short_body_releases_its_reservation() {
        use tokio::io::AsyncWriteExt;
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = reqwest::Url::parse(j["signed_upload_url"].as_str().unwrap()).unwrap();
        let mut s = tokio::net::TcpStream::connect((url.host_str().unwrap(), url.port().unwrap())).await.unwrap();
        let head = format!(
            "PUT {}?{}&comp=block&blockid=QQ%3D%3D HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\nshort",
            url.path(),
            url.query().unwrap()
        );
        s.write_all(head.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        for _ in 0..50 {
            if used(&rig.root) >= 5000 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(used(&rig.root) >= 5000, "reserved while the body is owed");
        drop(s);
        for _ in 0..100 {
            if used(&rig.root) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(used(&rig.root), 0, "released after the connection broke");
        assert_eq!(std::fs::read_dir(entries_in(&staged_dir(&rig.root, "vm-a")).remove(0).0).unwrap().count(), 1, "only meta.json");
    }

    #[tokio::test]
    async fn a_vm_over_its_staged_cap_is_refused_with_413() {
        let (rig, _) = rig(u64::MAX).await;
        let _held = reserve(&rig.root, "vm-a", STAGED_CAP - 10, u64::MAX).unwrap();
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let r = rig.http.put(j["signed_upload_url"].as_str().unwrap()).body(vec![0u8; 100]).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn evict_while_a_download_streams_still_delivers() {
        let (rig, _) = rig(u64::MAX).await;
        let c = caller("vm-a", "acme/demo");
        let dir = seed(&rig.root, "trusted", &c, "big", "v", 1, b"");
        let (blk, n) = (vec![7u8; 6 << 20], 3);
        let mut m = read_meta(&dir).unwrap();
        m.blocks = (0..n).map(|i| format!("b{i}")).collect();
        m.size = (blk.len() * n) as u64;
        for b in &m.blocks {
            std::fs::write(dir.join(b), &blk).unwrap();
        }
        write_meta(&dir, &m).unwrap();
        let (_, j) = rig.twirp("GetCacheEntryDownloadURL", json!({ "key": "big", "version": "v" })).await;
        let mut r = rig.http.get(j["signed_download_url"].as_str().unwrap()).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // The headers are in; the body is not read yet. The eviction (and a clear) take the files away.
        assert!(evict(&rig.root, 0) > 0 && !dir.exists());
        let mut got = 0;
        while let Some(chunk) = r.chunk().await.unwrap() {
            got += chunk.len();
        }
        assert_eq!(got, blk.len() * n, "the whole entry still arrives");
    }

    #[test]
    fn concurrent_promotes_of_one_key_keep_one_entry() {
        let root = tmp();
        for round in 0..20 {
            let key = format!("k{round}");
            let (a, b) = (caller("vm-a", "acme/demo"), caller("vm-b", "acme/demo"));
            seed(&root, "staged", &a, &key, "v", 1, b"from a");
            seed(&root, "staged", &b, &key, "v", 2, b"from b");
            let gate = Arc::new(std::sync::Barrier::new(2));
            let hs: Vec<_> = ["vm-a", "vm-b"]
                .into_iter()
                .map(|vm| {
                    let (root, gate) = (root.clone(), gate.clone());
                    std::thread::spawn(move || {
                        gate.wait();
                        promote(&root, vm).unwrap()
                    })
                })
                .collect();
            let got: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(got.iter().map(|g| g.0).sum::<usize>(), 1, "exactly one promoted: {got:?}");
            let same = entries_in(&trusted_dir(&root, "acme/demo")).into_iter().filter(|(_, m)| m.key == key).count();
            assert_eq!(same, 1, "round {round}");
        }
    }

    #[tokio::test]
    async fn a_second_create_for_a_key_being_uploaded_is_refused() {
        let (rig, _) = rig(1 << 30).await;
        let (_, first) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!(first["ok"], true);
        let (_, second) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        assert_eq!(second, json!({ "ok": false }));
        assert_eq!(entries_in(&staged_dir(&rig.root, "vm-a")).len(), 1, "the first reservation stays");
        let url = first["signed_upload_url"].as_str().unwrap();
        assert_eq!(rig.http.put(url).body("x").send().await.unwrap().status(), StatusCode::CREATED, "and still takes the upload");
        let (_, other) = rig.twirp("CreateCacheEntry", json!({ "key": "k2", "version": "v" })).await;
        assert_eq!(other["ok"], true, "another key is unaffected");
    }

    #[tokio::test]
    async fn a_bad_block_list_is_400_and_the_entry_cannot_be_finalized() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let put = |q: &str, b: &str| rig.http.put(format!("{url}&{q}")).body(b.to_string()).send();
        assert_eq!(put("comp=block&blockid=QQ%3D%3D", "data").await.unwrap().status(), StatusCode::CREATED);
        for (what, xml) in [
            ("unknown id", "<BlockList><Latest>nope</Latest></BlockList>"),
            ("known and unknown", "<BlockList><Latest>QQ==</Latest><Latest>nope</Latest></BlockList>"),
            ("empty", ""),
            ("garbage", "\u{0}<<>>not xml at all"),
            ("no ids", "<BlockList></BlockList>"),
        ] {
            assert_eq!(put("comp=blocklist", xml).await.unwrap().status(), StatusCode::BAD_REQUEST, "{what}");
        }
        let (_, f) = rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "k", "version": "v", "size_bytes": "4" })).await;
        assert_eq!(f["ok"], false, "no block list was accepted");
        assert!(visible(&rig.root, &caller("vm-a", "acme/demo")).is_empty());
    }

    #[tokio::test]
    async fn a_read_only_caller_cannot_put() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        rig.as_caller(Some(Caller { can_write: false, ..caller("vm-a", "acme/demo") }));
        assert_eq!(rig.http.put(&url).body("x").send().await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(
            rig.http.put(format!("{url}&comp=blocklist")).body("<BlockList/>").send().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn size_bytes_as_a_number_works_and_a_missing_one_fails_the_upload() {
        let (rig, _) = rig(1 << 30).await;
        for (key, size, ok) in
            [("num", Some(json!(5)), true), ("str", Some(json!("5")), true), ("none", None, false), ("junk", Some(json!("5x")), false)]
        {
            let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": key, "version": "v" })).await;
            rig.http.put(j["signed_upload_url"].as_str().unwrap()).body("hello").send().await.unwrap();
            let mut body = json!({ "key": key, "version": "v" });
            if let Some(s) = size {
                body["size_bytes"] = s;
            }
            let (code, f) = rig.twirp("FinalizeCacheEntryUpload", body).await;
            assert_eq!((code, f["ok"].clone()), (StatusCode::OK, json!(ok)), "{key}: {f}");
        }
    }

    /// A PUT that was streaming while the entry was finalized must not add to, or change, the finished entry.
    #[tokio::test]
    async fn a_put_that_finishes_after_finalize_is_dropped() {
        let (rig, _) = rig(1 << 30).await;
        let (_, j) = rig.twirp("CreateCacheEntry", json!({ "key": "k", "version": "v" })).await;
        let url = j["signed_upload_url"].as_str().unwrap().to_string();
        let b = |id: &str| format!("{url}&comp=block&blockid={id}");
        assert_eq!(rig.http.put(b("QQ%3D%3D")).body("data").send().await.unwrap().status(), StatusCode::CREATED);
        // A second block, announced as 4 bytes, with the body held back.
        let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(2);
        let late =
            {
                let req = rig.http.put(b("Qg%3D%3D")).header("content-length", "4").body(reqwest::Body::wrap_stream(
                    futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) }),
                ));
                tokio::spawn(async move { req.send().await.unwrap().status() })
            };
        tx.send(Ok(b"la".to_vec())).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let list = "<BlockList><Latest>QQ==</Latest></BlockList>";
        assert_eq!(rig.http.put(format!("{url}&comp=blocklist")).body(list).send().await.unwrap().status(), StatusCode::CREATED);
        let (_, f) = rig.twirp("FinalizeCacheEntryUpload", json!({ "key": "k", "version": "v", "size_bytes": "4" })).await;
        assert_eq!(f["ok"], true, "{f}");
        tx.send(Ok(b"te".to_vec())).await.unwrap();
        drop(tx);
        assert_eq!(late.await.unwrap(), StatusCode::FORBIDDEN, "the late PUT is refused");
        let (dir, m) = visible(&rig.root, &caller("vm-a", "acme/demo")).remove(0);
        assert!(m.finished && m.size == 4 && m.blocks.len() == 1);
        let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        files.sort();
        assert_eq!(files.len(), 2, "meta.json and the one listed block, no stray block or .part: {files:?}");
    }
}
