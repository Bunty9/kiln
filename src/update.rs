//! Over-the-air self-update from signed GitHub releases: download, verify (Ed25519
//! signature over the tarball, then its SHA-256), drain, replace the executable and
//! re-exec in place (systemd keeps the PID). A new version that fails to start
//! `MAX_BOOTS` times is rolled back to `<exe>.prev`.

use crate::{App, now};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::process::Command;

/// Release signing key: raw Ed25519 public key, base64. A new key needs a manual install.
pub const PUBLIC_KEY: &str = "zOK6AdHJZXwFqAOUApNnaU7r5PZSCjkpAjLRu2w16ZM=";
/// Boots a pending update gets before the previous binary is restored.
const MAX_BOOTS: u32 = 2;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const MUSL: bool = cfg!(target_env = "musl");

#[derive(Clone)]
struct Release {
    version: String,
    notes: String,
    published_at: String,
    assets: Value,
}

/// "idle" | "checking" | "downloading" | "verifying" | "draining" | "applying" | "error",
/// "restarting" (a restart's drain is over), or "stopping" (SIGTERM: final, nothing new begins).
pub struct Status {
    state: &'static str,
    latest: Option<Release>,
    error: Option<String>,
    /// Drain progress, for the dashboard.
    progress: Option<String>,
    checked_at: u64,
    /// Why the last update was rolled back (<data>/update/error); cleared by the next apply.
    rollback: Option<String>,
    /// The version that was rolled back (<data>/update/skip): `auto_update` never retries
    /// it, only a newer one. Cleared by a manual apply.
    skip: Option<String>,
    /// The drain is a plain restart (same binary), not an update.
    restart: bool,
    /// "Restart now": end the drain without waiting for running VMs.
    force: bool,
}

impl Status {
    pub fn load(data: &Path) -> Self {
        let read = |f: &str| std::fs::read_to_string(data.join("update").join(f)).ok();
        Self {
            state: "idle",
            latest: None,
            error: None,
            progress: None,
            checked_at: 0,
            rollback: read("error"),
            skip: read("skip"),
            restart: false,
            force: false,
        }
    }
}

fn set(app: &App, state: &'static str, progress: Option<String>) {
    let mut s = app.update.lock().unwrap();
    if s.state == "stopping" {
        return;
    }
    s.state = state;
    s.progress = progress;
}

fn fail(app: &App, e: &anyhow::Error) {
    tracing::warn!("update: {e:#}");
    let mut s = app.update.lock().unwrap();
    if s.state != "stopping" {
        s.state = "error";
    }
    (s.progress, s.error, s.restart, s.force) = (None, Some(format!("{e:#}")), false, false);
}

/// Move from idle/error to `to`; false while another check or update runs.
fn begin(app: &App, to: &'static str) -> bool {
    let mut s = app.update.lock().unwrap();
    if !matches!(s.state, "idle" | "error") {
        return false;
    }
    s.state = to;
    true
}

/// GET /api/update.
pub fn json(app: &App) -> Value {
    let cfg = app.cfg();
    let s = app.update.lock().unwrap();
    let l = s.latest.as_ref();
    json!({
        "current": VERSION,
        "latest": l.map(|r| &r.version),
        "available": l.is_some_and(|r| newer(&r.version, VERSION)),
        "notes": l.map(|r| &r.notes),
        "published_at": l.map(|r| &r.published_at),
        "flavor": if MUSL { "musl" } else { "gnu" },
        "state": s.state,
        "error": s.error,
        "progress": s.progress,
        "rollback": s.rollback,
        "skipped": s.skip,
        "checked_at": s.checked_at,
        "auto": cfg.auto_update,
        "repo": cfg.update_repo,
    })
}

/// The `update` object of /api/state.
pub fn compact(app: &App) -> Value {
    let s = app.update.lock().unwrap();
    let latest = s.latest.as_ref().map(|r| r.version.clone());
    let available = latest.as_deref().is_some_and(|l| newer(l, VERSION));
    // A restart's drain is reported in `restart_json`, not as an update.
    let (state, progress) = if s.restart { ("idle", None) } else { (s.state, s.progress.clone()) };
    json!({ "latest": latest, "available": available, "state": state, "error": s.error, "progress": progress, "rollback": s.rollback })
}

/// The `restart` object of /api/state: saved settings that apply only after a restart
/// (`needed`), and a restart or stop in progress (`state` "draining" | "restarting" |
/// "stopping", else null) with its progress.
pub fn restart_json(app: &App, running_listen: Option<&str>) -> Value {
    let running = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).count();
    let needed = restart_needed(running_listen, &app.cfg());
    let s = app.update.lock().unwrap();
    let state = (s.restart || s.state == "stopping").then_some(s.state);
    json!({ "needed": needed, "state": state, "progress": state.and(s.progress.clone()), "running": running, "force": s.force })
}

/// Saved settings that differ from what this process started with and apply only at startup.
/// `listen` is the only one: every other setting is read where it is used.
pub fn restart_needed(running_listen: Option<&str>, cfg: &crate::Config) -> Vec<&'static str> {
    running_listen.filter(|l| *l != cfg.listen).map(|_| "listen").into_iter().collect()
}

/// Drain, then re-exec this same binary in place (POST /api/restart). `now`: do not wait
/// for running VMs (they are killed); during a restart's drain it ends the wait. False
/// while an update or an update check runs.
pub fn restart(app: &Arc<App>, now: bool) -> bool {
    {
        let mut s = app.update.lock().unwrap();
        if s.restart && s.state == "draining" {
            s.force |= now;
            return true;
        }
        if !matches!(s.state, "idle" | "error") {
            return false;
        }
        (s.state, s.restart, s.force, s.error, s.progress) = ("draining", true, now, None, None);
    }
    tracing::info!("restart requested{}", if now { " now: running jobs are killed" } else { ": draining first" });
    let app = app.clone();
    tokio::spawn(async move {
        if drain(&app, "restarting").await {
            // A binary replaced on disk since start (a manual install) is what systemd would run too.
            let exe = std::env::current_exe().unwrap_or_default();
            let exe = PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)"));
            tracing::info!("restarting kiln ({})", exe.display());
            restart_into(&app, &exe).await
        }
        let mut s = app.update.lock().unwrap();
        (s.restart, s.force) = (false, false);
        tracing::info!("restart cancelled");
    });
    true
}

/// The latest release of `update_repo` (GitHub's "latest" excludes drafts and pre-releases).
async fn fetch(app: &App) -> Result<Release> {
    let repo = app.cfg().update_repo;
    let r = app.gh.release(&format!("repos/{repo}/releases/latest"), false).await.context("checking for a kiln update")?;
    let status = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    if status == 404 {
        bail!(
            "{repo} has no release kiln can see (404). A private repo needs {}, or set update_repo to a public repo",
            if app.gh.app().is_some() { "the GitHub App installed on it" } else { "a token that can read it" }
        );
    }
    if status != 200 {
        bail!("checking {repo} for a kiln update: GitHub {status} {}", v["message"].as_str().unwrap_or(""));
    }
    let tag = v["tag_name"].as_str().unwrap_or("");
    let (a, b, c) = parse_version(tag).with_context(|| format!("the latest release of {repo} is {tag:?}, not vX.Y.Z"))?;
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    Ok(Release { version: format!("{a}.{b}.{c}"), notes: s("body"), published_at: s("published_at"), assets: v["assets"].clone() })
}

/// Check now (scheduled or on demand); the outcome lands in the status. False if busy.
pub async fn check(app: &App) -> bool {
    if !begin(app, "checking") {
        return false;
    }
    let r =
        tokio::time::timeout(Duration::from_secs(30), fetch(app)).await.unwrap_or_else(|_| Err(anyhow::anyhow!("update check timed out")));
    match r {
        Ok(rel) => {
            let mut s = app.update.lock().unwrap();
            if s.state == "checking" {
                s.state = "idle";
            }
            (s.error, s.latest, s.checked_at) = (None, Some(rel), now());
        }
        Err(e) => {
            fail(app, &e);
            app.update.lock().unwrap().checked_at = now();
        }
    }
    true
}

/// Start an update in the background; false if one (or a check) is already running.
/// `manual` (dashboard or API) also clears the rolled-back version's skip.
pub fn start(app: &Arc<App>, manual: bool) -> bool {
    if !begin(app, "downloading") {
        return false;
    }
    {
        let mut s = app.update.lock().unwrap();
        (s.error, s.rollback) = (None, None);
        if manual {
            s.skip = None;
            let _ = std::fs::remove_file(app.data.join("update/skip"));
        }
    }
    let _ = std::fs::remove_file(app.data.join("update/error"));
    let app = app.clone();
    tokio::spawn(async move {
        if let Err(e) = apply(&app, manual).await {
            app.draining.store(false, Ordering::SeqCst);
            fail(&app, &e);
        }
    });
    true
}

/// Stop a drain and resume launching; false unless draining. `restart` says which drain
/// (a restart's or an update's) may be cancelled.
pub fn cancel(app: &App, restart: bool) -> bool {
    let s = app.update.lock().unwrap();
    s.state == "draining" && s.restart == restart && app.draining.swap(false, Ordering::SeqCst)
}

/// SIGTERM: no update or restart begins or finishes from now on (one draining ends as if
/// cancelled, without resuming launches); the caller drains and shuts down.
pub fn stopping(app: &App) {
    let mut s = app.update.lock().unwrap();
    (s.state, s.progress) = ("stopping", None);
}

/// The stop drain's progress, for the dashboard.
pub fn stop_progress(app: &App, p: String) {
    app.update.lock().unwrap().progress = Some(p);
}

async fn download(app: &App, repo: &str, id: u64) -> Result<Vec<u8>> {
    let r = app.gh.release(&format!("repos/{repo}/releases/assets/{id}"), true).await?;
    if !r.status().is_success() {
        bail!("downloading release asset {id}: {}", r.status());
    }
    // ponytail: the tarball is held in memory (~10 MB); stream to disk if releases grow large.
    Ok(r.bytes().await?.to_vec())
}

/// Run `tar args` with `input` (the verified tarball, in memory) on its stdin.
async fn tar<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>, input: &[u8]) -> Result<std::process::Output> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = Command::new("tar")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("tar")?;
    let mut stdin = child.stdin.take().context("tar stdin")?;
    let input = input.to_vec();
    // Written concurrently with reading its output, so neither pipe can stall the other.
    // A write error (tar quit early) shows in tar's status.
    let writer = tokio::spawn(async move { stdin.write_all(&input).await });
    let out = child.wait_with_output().await.context("tar")?;
    let _ = writer.await;
    Ok(out)
}

/// Write `path` and flush it to disk: a counted boot or a pending update must survive a crash.
fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

/// This process's executable (/proc/self/exe), refused once it was replaced on disk.
pub fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving /proc/self/exe")?;
    if exe.to_string_lossy().ends_with(" (deleted)") {
        bail!("kiln's binary was replaced on disk since it started: restart kiln first");
    }
    Ok(exe)
}

/// Download, verify, stage next to the executable, drain, swap and re-exec.
async fn apply(app: &Arc<App>, manual: bool) -> Result<()> {
    let repo = app.cfg().update_repo;
    let rel = fetch(app).await?;
    let skip = {
        let mut s = app.update.lock().unwrap();
        s.latest = Some(rel.clone());
        s.skip.clone()
    };
    if !newer(&rel.version, VERSION) {
        bail!("kiln {VERSION} is up to date (latest release: {})", rel.version);
    }
    if !manual && !auto_apply(Some(&rel.version), VERSION, skip.as_deref()) {
        bail!("kiln {} was rolled back: auto_update skips it (apply it by hand to retry)", rel.version);
    }
    let name = asset_name(&rel.version, MUSL);
    let [tgz, sha, sig] =
        pick_assets(&rel.assets, &name).with_context(|| format!("release {} has no signed {name} (with .sha256 and .sig)", rel.version))?;
    let (tgz, sha, sig) = (download(app, &repo, tgz).await?, download(app, &repo, sha).await?, download(app, &repo, sig).await?);

    set(app, "verifying", None);
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.decode(PUBLIC_KEY)?;
    verify(&key, &tgz, &sig).with_context(|| name.clone())?;
    let digest: String = ring::digest::digest(&ring::digest::SHA256, &tgz).as_ref().iter().map(|b| format!("{b:02x}")).collect();
    if !crate::mirror::sha_matches(&String::from_utf8_lossy(&sha), &digest) {
        bail!("{name}: SHA-256 does not match {name}.sha256");
    }
    let dir = app.data.join("update");
    let x = dir.join("x");
    let _ = tokio::fs::remove_dir_all(&x).await;
    tokio::fs::create_dir_all(&x).await?;
    // tar reads the verified bytes from memory: no file that could change after the check.
    let stem = name.trim_end_matches(".tar.gz");
    let list = tar(["-tzf", "-"], &tgz).await?;
    if !list.status.success() || !archive_ok(&String::from_utf8_lossy(&list.stdout), stem) {
        bail!("{name}: unexpected archive layout");
    }
    // Only the binary is extracted: nothing else in the archive is ever written.
    let member = format!("{stem}/kiln");
    let args = [OsStr::new("--no-same-owner"), OsStr::new("-xzf"), OsStr::new("-"), OsStr::new("-C"), x.as_os_str(), OsStr::new(&member)];
    let st = tar(args, &tgz).await?.status;
    let new = x.join(&member);
    if !st.success() || !tokio::fs::symlink_metadata(&new).await.is_ok_and(|m| m.is_file()) {
        bail!("{name}: extracting {member} failed");
    }
    // kill_on_drop: a binary that hangs is killed when the timeout drops the future.
    let out = tokio::time::timeout(Duration::from_secs(10), Command::new(&new).arg("--version").kill_on_drop(true).output()).await;
    let got = out.ok().and_then(|o| o.ok()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    if got != format!("kiln {}", rel.version) {
        bail!("{name}: the new binary reports {got:?}, expected \"kiln {}\" (does it run on this host?)", rel.version);
    }
    let exe = current_exe()?;
    let staged = sibling(&exe, ".new");
    tokio::fs::copy(&new, &staged)
        .await
        .with_context(|| format!("writing {} (kiln must be able to replace its own binary)", staged.display()))?;
    let _ = tokio::fs::remove_dir_all(&x).await;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).await?;
    // On disk before the rename that makes it the binary systemd starts.
    tokio::fs::File::open(&staged).await?.sync_all().await?;

    if !drain(app, "applying").await {
        let _ = tokio::fs::remove_file(&staged).await;
        tracing::info!("update to {} cancelled", rel.version);
        return Ok(());
    }

    tracing::info!("updating kiln {VERSION} -> {}", rel.version);
    let pending = Pending { from: VERSION.into(), to: rel.version.clone(), attempts: 0 };
    write_synced(&dir.join("pending.json"), &serde_json::to_vec(&pending)?)?;
    let prev = sibling(&exe, ".prev");
    let _ = std::fs::remove_file(&prev);
    let swapped =
        std::fs::hard_link(&exe, &prev).or_else(|_| std::fs::copy(&exe, &prev).map(|_| ())).and_then(|_| std::fs::rename(&staged, &exe));
    if let Err(e) = swapped {
        let _ = std::fs::remove_file(dir.join("pending.json"));
        return Err(e).with_context(|| format!("replacing {}", exe.display()));
    }
    restart_into(app, &exe).await
}

/// Drain: no new VMs (warm included), idle ones reaped, running jobs finish, bounded by
/// the job timeout + 2 min, or not waited for once `force` is set. Ends in state `then`.
/// False if cancelled, or if kiln is stopping (SIGTERM).
async fn drain(app: &App, then: &'static str) -> bool {
    app.draining.store(true, Ordering::SeqCst);
    set(app, "draining", None);
    let what = if then == "restarting" { "restart" } else { "update" };
    let deadline = now() + app.cfg().job_timeout_mins * 60 + 120;
    let mut logged = 0;
    loop {
        let active = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).count();
        let baking = app.baking.load(Ordering::SeqCst);
        // Decided under the status lock, which `cancel`, `restart` and `stopping` take too.
        {
            let mut s = app.update.lock().unwrap();
            if s.state == "stopping" {
                return false;
            }
            if !app.draining.load(Ordering::SeqCst) {
                (s.state, s.progress) = ("idle", None);
                return false;
            }
            let deadline = if s.force { 0 } else { deadline };
            if drain_done(active, baking, now(), deadline) {
                (s.state, s.progress) = (then, None);
                return true;
            }
            let p = if now() >= deadline {
                "waiting for a bake to finish".into()
            } else {
                let bake = if baking { ", and a bake" } else { "" };
                format!("waiting for {active} VM{}{bake} to finish (at most {})", if active == 1 { "" } else { "s" }, dur(deadline - now()))
            };
            if now() >= logged + 30 {
                logged = now();
                tracing::info!("{what} draining: {p}");
            }
            s.progress = Some(p);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Shut down (VMs killed, runners deregistered) and exec `exe` in place. Never returns.
async fn restart_into(app: &Arc<App>, exe: &Path) -> ! {
    crate::shutdown(app).await;
    // The registry child is killed by its supervisor within a couple of seconds of `stopping`.
    for _ in 0..50 {
        if !app.mirror.lock().unwrap().running {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let e = reexec(exe);
    // Past shutdown there is no going back: let systemd start the binary.
    tracing::error!("re-exec {}: {e:#}; exiting so the service manager restarts kiln", exe.display());
    std::process::exit(1)
}

/// The drain is over once no VM runs, or at the deadline (shutdown stops what still runs).
/// A bake is always waited for (it has its own 30 min cap): killing it mid-way is messier.
fn drain_done(active: usize, baking: bool, t: u64, deadline: u64) -> bool {
    !baking && (active == 0 || t >= deadline)
}

fn dur(s: u64) -> String {
    if s >= 3600 { format!("{}h {}m", s / 3600, s % 3600 / 60) } else { format!("{}m", s.div_ceil(60)) }
}

/// Replace this process with `exe`, same arguments and environment; returns only on error.
/// std and tokio open every fd close-on-exec, so the listener and files do not leak.
fn reexec(exe: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let mut args = std::env::args_os();
    let arg0 = args.next().unwrap_or_default();
    std::process::Command::new(exe).arg0(arg0).args(args).exec().into()
}

/// `serve` startup: count this boot of a pending update, and after `MAX_BOOTS` failed
/// boots restore `<exe>.prev` and exec it. Returns unless it re-execs.
pub fn on_start(data: &Path) {
    let path = data.join("update/pending.json");
    let p = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    match boot(p, VERSION) {
        Boot::Normal => {}
        Boot::Clear => {
            let _ = std::fs::remove_file(&path);
        }
        Boot::Retry(p) => {
            tracing::info!("kiln {} started after an update (boot {} of {MAX_BOOTS})", p.to, p.attempts);
            let _ = write_synced(&path, &serde_json::to_vec(&p).unwrap_or_default());
        }
        Boot::Rollback(p) => {
            let _ = std::fs::remove_file(&path);
            let msg = format!("kiln {} failed to start {MAX_BOOTS} times after the update: rolled back to kiln {}", p.to, p.from);
            tracing::error!("{msg}");
            let _ = std::fs::write(data.join("update/error"), &msg);
            let _ = std::fs::write(data.join("update/skip"), &p.to);
            let exe = match current_exe() {
                Ok(e) => e,
                Err(e) => return tracing::error!("rollback: {e:#}"),
            };
            if let Err(e) = std::fs::rename(sibling(&exe, ".prev"), &exe) {
                return tracing::error!("rollback: restoring {}.prev: {e}", exe.display());
            }
            tracing::error!("rollback: re-exec {}: {:#}", exe.display(), reexec(&exe));
            std::process::exit(1);
        }
    }
}

/// Confirms a just-applied update after 60 s of serving, then checks every 6 h; with
/// `auto_update`, applies a newer release once the box is idle.
pub async fn supervise(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(60)).await;
    let _ = std::fs::remove_file(app.data.join("update/pending.json"));
    let mut next = 0;
    while !app.stopping.load(Ordering::SeqCst) {
        if now() >= next {
            next = now() + 6 * 3600;
            check(&app).await;
        }
        let ready = {
            let s = app.update.lock().unwrap();
            s.state == "idle" && auto_apply(s.latest.as_ref().map(|r| r.version.as_str()), VERSION, s.skip.as_deref())
        };
        // Warm VMs do not count (the drain reaps them); held ones do (see blocks_auto_update).
        let idle = !app.baking.load(Ordering::SeqCst) && !app.vms.lock().unwrap().iter().any(|v| v.blocks_auto_update());
        // ponytail: a failed auto-update retries only after the next check (6 h) resets the state.
        if ready && idle && app.cfg().auto_update && start(&app, false) {
            tracing::info!("auto_update: applying the new release");
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// "X.Y.Z" or "vX.Y.Z"; anything else (pre-releases included) is None.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let digits = |x: &str| x.bytes().all(|b| b.is_ascii_digit()).then(|| x.parse().ok()).flatten();
    let n: Vec<u64> = v.strip_prefix('v').unwrap_or(v).split('.').map(digits).collect::<Option<_>>()?;
    match n[..] {
        [a, b, c] => Some((a, b, c)),
        _ => None,
    }
}

/// Is `latest` a release newer than `current`? Unparseable never is.
fn newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

/// Should `auto_update` install `latest`? Only if it is newer than `current` and than the
/// version that was rolled back (`skip`), so a broken release never loops.
fn auto_apply(latest: Option<&str>, current: &str, skip: Option<&str>) -> bool {
    latest.is_some_and(|l| newer(l, current) && skip.is_none_or(|s| newer(l, s)))
}

/// Tarball of `version` for this build's libc flavor.
fn asset_name(version: &str, musl: bool) -> String {
    format!("kiln-{version}-x86_64-linux{}.tar.gz", if musl { "-musl" } else { "" })
}

/// Asset ids of `name`, `name.sha256` and `name.sig` in a release's `assets`.
fn pick_assets(assets: &Value, name: &str) -> Option<[u64; 3]> {
    let id = |n: String| assets.as_array()?.iter().find(|a| a["name"].as_str() == Some(&n))?["id"].as_u64();
    Some([id(name.into())?, id(format!("{name}.sha256"))?, id(format!("{name}.sig"))?])
}

/// Ed25519 signature of `msg` under the raw 32-byte `public_key`.
fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> anyhow::Result<()> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(msg, sig)
        .map_err(|_| anyhow::anyhow!("bad signature: the tarball is not signed with kiln's release key"))
}

/// `tar -tzf` listing: every entry is inside `stem/`, with no `..`, and `stem/kiln` is there.
fn archive_ok(listing: &str, stem: &str) -> bool {
    let dir = format!("{stem}/");
    let entries: Vec<&str> = listing.lines().filter(|l| !l.is_empty()).collect();
    entries.contains(&format!("{stem}/kiln").as_str()) && entries.iter().all(|l| l.starts_with(&dir) && !l.split('/').any(|s| s == ".."))
}

/// <data>/update/pending.json: an update was applied and is not yet confirmed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Pending {
    from: String,
    to: String,
    attempts: u32,
}

#[derive(Debug, PartialEq)]
enum Boot {
    Normal,
    /// Not the version the update installed (manual reinstall): forget it.
    Clear,
    /// Count this boot.
    Retry(Pending),
    /// Too many failed boots of the new version: restore `<exe>.prev`.
    Rollback(Pending),
}

/// What a starting kiln does about a pending update.
fn boot(p: Option<Pending>, current: &str) -> Boot {
    match p {
        None => Boot::Normal,
        Some(p) if p.to != current => Boot::Clear,
        Some(p) => {
            let p = Pending { attempts: p.attempts + 1, ..p };
            if p.attempts > MAX_BOOTS { Boot::Rollback(p) } else { Boot::Retry(p) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.10.0"), Some((0, 10, 0)));
        for v in ["v1.2", "1.2.3.4", "v1.2.3-rc1", "1.2.x", "", "v", "1..3", "+1.2.3", "v1.2.3/../x"] {
            assert_eq!(parse_version(v), None, "{v}");
        }
        assert!(newer("v0.2.0", "0.1.0"));
        assert!(newer("0.1.10", "0.1.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"));
        assert!(!newer("v0.2.0-rc1", "0.1.0"), "pre-releases are never offered");
        assert!(!newer("garbage", "0.1.0"));
    }

    #[test]
    fn assets_by_flavor() {
        assert_eq!(asset_name("0.2.0", false), "kiln-0.2.0-x86_64-linux.tar.gz");
        assert_eq!(asset_name("0.2.0", true), "kiln-0.2.0-x86_64-linux-musl.tar.gz");
        let a = json!([
            { "id": 1, "name": "kiln-0.2.0-x86_64-linux.tar.gz" },
            { "id": 2, "name": "kiln-0.2.0-x86_64-linux.tar.gz.sha256" },
            { "id": 3, "name": "kiln-0.2.0-x86_64-linux.tar.gz.sig" },
            { "id": 4, "name": "kiln-0.2.0-x86_64-linux-musl.tar.gz" },
            { "id": 5, "name": "kiln-0.2.0-x86_64-linux-musl.tar.gz.sha256" },
            { "id": 6, "name": "kiln-0.2.0-x86_64-linux-musl.tar.gz.sig" },
        ]);
        assert_eq!(pick_assets(&a, "kiln-0.2.0-x86_64-linux.tar.gz"), Some([1, 2, 3]));
        assert_eq!(pick_assets(&a, "kiln-0.2.0-x86_64-linux-musl.tar.gz"), Some([4, 5, 6]));
        // an unsigned release is never picked
        let unsigned =
            json!([{ "id": 1, "name": "kiln-0.2.0-x86_64-linux.tar.gz" }, { "id": 2, "name": "kiln-0.2.0-x86_64-linux.tar.gz.sha256" }]);
        assert_eq!(pick_assets(&unsigned, "kiln-0.2.0-x86_64-linux.tar.gz"), None);
        assert_eq!(pick_assets(&json!(null), "x"), None);
    }

    #[test]
    fn signatures() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let kp = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        let other = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        let msg = b"tarball bytes";
        let sig = kp.sign(msg);
        assert!(verify(kp.public_key().as_ref(), msg, sig.as_ref()).is_ok());
        assert!(verify(kp.public_key().as_ref(), b"tarball bytez", sig.as_ref()).is_err(), "tampered");
        assert!(verify(other.public_key().as_ref(), msg, sig.as_ref()).is_err(), "other key");
        assert!(verify(kp.public_key().as_ref(), msg, &[]).is_err(), "unsigned");
        assert!(verify(kp.public_key().as_ref(), msg, &sig.as_ref()[..63]).is_err(), "truncated");
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.decode(PUBLIC_KEY).unwrap();
        assert_eq!(key.len(), 32, "production key is a raw 32-byte Ed25519 key");
        assert!(verify(&key, msg, sig.as_ref()).is_err());
    }

    #[test]
    fn tar_allowlist() {
        let s = "kiln-0.2.0-x86_64-linux";
        let ok = "kiln-0.2.0-x86_64-linux/\nkiln-0.2.0-x86_64-linux/kiln\nkiln-0.2.0-x86_64-linux/deploy/kiln.service\n";
        assert!(archive_ok(ok, s));
        assert!(!archive_ok("kiln-0.2.0-x86_64-linux/README.md\n", s), "no binary");
        assert!(!archive_ok(&format!("{ok}kiln-0.2.0-x86_64-linux/../../.bashrc\n"), s));
        assert!(!archive_ok(&format!("{ok}/etc/passwd\n"), s));
        assert!(!archive_ok(&format!("{ok}other/kiln\n"), s));
        assert!(!archive_ok(&format!("{ok}kiln-0.2.0-x86_64-linux-evil/kiln\n"), s));
        assert!(!archive_ok("", s));
    }

    #[tokio::test]
    async fn tar_reads_the_verified_bytes_from_memory() {
        let d = std::env::temp_dir().join(format!("kiln-test-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src/k-1")).unwrap();
        std::fs::write(d.join("src/k-1/kiln"), b"binary").unwrap();
        std::fs::write(d.join("src/k-1/README"), b"doc").unwrap();
        let tgz = std::process::Command::new("tar").args(["-czf", "-", "-C"]).arg(d.join("src")).arg("k-1").output().unwrap().stdout;
        std::fs::remove_dir_all(d.join("src")).unwrap();
        let list = tar(["-tzf", "-"], &tgz).await.unwrap();
        assert!(list.status.success() && archive_ok(&String::from_utf8_lossy(&list.stdout), "k-1"));
        let x = d.join("x");
        std::fs::create_dir_all(&x).unwrap();
        let out = tar([OsStr::new("-xzf"), OsStr::new("-"), OsStr::new("-C"), x.as_os_str(), OsStr::new("k-1/kiln")], &tgz).await.unwrap();
        assert!(out.status.success());
        assert_eq!(std::fs::read(x.join("k-1/kiln")).unwrap(), b"binary");
        assert!(!x.join("k-1/README").exists(), "only the binary is extracted");
        assert!(!tar(["-tzf", "-"], b"not a tarball").await.unwrap().status.success());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn drain_waits_for_a_bake() {
        assert!(drain_done(0, false, 10, 100));
        assert!(!drain_done(1, false, 10, 100), "a VM still runs");
        assert!(drain_done(1, false, 100, 100), "deadline: VMs are stopped by shutdown");
        assert!(!drain_done(0, true, 10, 100), "a bake runs");
        assert!(!drain_done(0, true, 500, 100), "past the deadline a bake is still waited for");
        assert!(!drain_done(3, true, 500, 100));
        // "Restart now" drains with a deadline of 0: VMs are not waited for, a bake still is
        assert!(drain_done(3, false, 10, 0));
        assert!(!drain_done(3, true, 10, 0));
    }

    #[test]
    fn restart_only_settings() {
        let c = crate::Config::default();
        assert!(restart_needed(Some("0.0.0.0:7878"), &c).is_empty());
        assert_eq!(restart_needed(Some("127.0.0.1:7878"), &c), ["listen"]);
        assert!(restart_needed(None, &c).is_empty(), "not serving (bake, doctor)");
        // everything else applies live
        let live = crate::Config { max_vms: 9, poll_secs: 30, egress: "filtered".into(), stop_grace_secs: 60, ..c.clone() };
        assert!(restart_needed(Some(&c.listen), &live).is_empty());
    }

    #[test]
    fn auto_apply_skips_rolled_back() {
        assert!(auto_apply(Some("0.2.0"), "0.1.0", None));
        assert!(!auto_apply(None, "0.1.0", None));
        assert!(!auto_apply(Some("0.1.0"), "0.1.0", None), "up to date");
        // 0.2.0 was rolled back: never retried by itself, but a newer release is
        assert!(!auto_apply(Some("0.2.0"), "0.1.0", Some("0.2.0")));
        assert!(auto_apply(Some("0.2.1"), "0.1.0", Some("0.2.0")));
        assert!(!auto_apply(Some("0.1.5"), "0.1.0", Some("0.2.0")), "older than the rolled-back one");
    }

    #[test]
    fn boot_decisions() {
        let p = |attempts| Pending { from: "0.1.0".into(), to: "0.2.0".into(), attempts };
        assert_eq!(boot(None, "0.2.0"), Boot::Normal);
        assert_eq!(boot(Some(p(0)), "0.2.0"), Boot::Retry(p(1)));
        assert_eq!(boot(Some(p(1)), "0.2.0"), Boot::Retry(p(2)));
        assert_eq!(boot(Some(p(2)), "0.2.0"), Boot::Rollback(p(3)));
        assert_eq!(boot(Some(p(0)), "0.1.0"), Boot::Clear, "the old binary runs: nothing to count");
        assert_eq!(MAX_BOOTS, 2);
    }
}
