//! Docker Hub pull-through cache for job VMs. They reach it at 10.0.2.2:5000
//! (QEMU user networking = host loopback); dockerd falls back to Docker Hub
//! while it is down, so a broken mirror never breaks a job.

use crate::{App, now};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;

/// Pinned: a different tarball is refused, never installed. (url, sha256) for this host.
const RELEASE: (&str, &str) = if crate::host::ARM64 {
    (
        "https://github.com/distribution/distribution/releases/download/v3.1.2/registry_3.1.2_linux_arm64.tar.gz",
        "09d26f88d2c0f161bd1b8bfc6c123571cc3d291dcca8af5477b3cacc4ec95e73",
    )
} else {
    (
        "https://github.com/distribution/distribution/releases/download/v3.1.2/registry_3.1.2_linux_amd64.tar.gz",
        "40df2224d410f72ae425c3371873b078bbdbda3b8b612be9571f0e6751f3acc8",
    )
};
const URL: &str = RELEASE.0;
const SHA256: &str = RELEASE.1;
/// The registry has no darwin build: on macOS there is no mirror and VMs pull from Docker Hub.
const SUPPORTED: bool = !crate::host::MACOS;
const UNSUPPORTED_MSG: &str = "not available on macOS; VMs pull from Docker Hub directly";
pub const ADDR: &str = "127.0.0.1:5000";

#[derive(Default)]
pub struct Status {
    pub running: bool,
    pub error: Option<String>,
    cache_mb: Option<u64>,
    cache_at: u64,
}

fn set(app: &App, running: bool, error: Option<String>) {
    let mut s = app.mirror.lock().unwrap();
    s.running = running;
    s.error = error;
}

fn config_yaml(data: &Path) -> String {
    // {:?} gives a double-quoted string, which is valid YAML for plain paths.
    let root = format!("{:?}", data.join("registry/data").display().to_string());
    format!(
        "version: 0.1\nlog:\n  level: warn\nstorage:\n  filesystem:\n    rootdirectory: {root}\n  delete:\n    enabled: true\nhttp:\n  addr: {ADDR}\nproxy:\n  remoteurl: https://registry-1.docker.io\n  ttl: 168h\n"
    )
}

/// `sha256sum` output ("<hex>  <file>") against the pinned digest.
pub fn sha_matches(out: &str, want: &str) -> bool {
    out.split_whitespace().next().is_some_and(|h| h.eq_ignore_ascii_case(want))
}

/// `du -sm` of a directory.
async fn dir_mb(p: &Path) -> Option<u64> {
    let out = Command::new("du").arg("-sm").arg(p).output().await.ok()?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().next()?.parse().ok()
}

fn over_cap(mb: u64, gb: u32) -> bool {
    mb > gb as u64 * 1024
}

const CAP_CHECK: Duration = Duration::from_secs(600);

async fn port_busy() -> bool {
    tokio::net::TcpStream::connect(ADDR).await.is_ok()
}

/// Set once a download failed its checksum: don't re-download until restart.
static REFUSED: AtomicBool = AtomicBool::new(false);
const REFUSED_MSG: &str = "registry download failed checksum; refusing (restart kiln to retry)";

pub fn cache_mb(app: &App) -> Option<u64> {
    app.mirror.lock().unwrap().cache_mb
}

async fn ensure_binary(data: &Path) -> Result<()> {
    let bin = data.join("bin");
    if bin.join("registry").exists() {
        return Ok(());
    }
    if REFUSED.load(Ordering::SeqCst) {
        bail!(REFUSED_MSG);
    }
    tokio::fs::create_dir_all(&bin).await?;
    let part = bin.join("registry.tgz.part");
    let st = Command::new("curl")
        .args(["-fsSL", "--max-time", "300", "--speed-limit", "1024", "--speed-time", "60", "-o"])
        .arg(&part)
        .arg(URL)
        .status()
        .await
        .context("curl")?;
    if !st.success() {
        bail!("downloading registry: curl {st}");
    }
    let sum = Command::new("sha256sum").arg(&part).output().await.context("sha256sum")?;
    if !sha_matches(&String::from_utf8_lossy(&sum.stdout), SHA256) {
        let _ = tokio::fs::remove_file(&part).await;
        REFUSED.store(true, Ordering::SeqCst);
        bail!(REFUSED_MSG);
    }
    // Extract aside and rename, so a truncated binary is never left at bin/registry.
    let tmp = bin.join("tmp");
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    tokio::fs::create_dir_all(&tmp).await?;
    let st = Command::new("tar").arg("-xzf").arg(&part).arg("-C").arg(&tmp).arg("registry").status().await.context("tar")?;
    let _ = tokio::fs::remove_file(&part).await;
    let done = async {
        if !st.success() {
            bail!("extracting registry: tar {st}");
        }
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(tmp.join("registry"), std::fs::Permissions::from_mode(0o755)).await?;
        tokio::fs::rename(tmp.join("registry"), bin.join("registry")).await?;
        Ok(())
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    done
}

/// Install if needed, then spawn; Err = could not start.
async fn start(app: &App) -> Result<tokio::process::Child> {
    if port_busy().await {
        bail!("port 5000 in use");
    }
    ensure_binary(&app.data).await?;
    let dir = app.data.join("registry");
    tokio::fs::create_dir_all(dir.join("data")).await?;
    tokio::fs::write(dir.join("config.yml"), config_yaml(&app.data)).await?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("registry.log"))?;
    Command::new(app.data.join("bin/registry"))
        .arg("serve")
        .arg(dir.join("config.yml"))
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .context("spawning registry")
}

/// Keeps the registry running while `docker_mirror` is on; re-reads the flag
/// every couple of seconds so the dashboard toggle needs no restart.
pub async fn supervise(app: Arc<App>) {
    let mut fails = 0u32;
    while !app.stopping.load(std::sync::atomic::Ordering::SeqCst) {
        if !app.cfg().docker_mirror || !SUPPORTED {
            set(&app, false, None);
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        let began = Instant::now();
        let err = match start(&app).await {
            Err(e) => Some(format!("{e:#}")),
            Ok(mut child) => {
                set(&app, true, None);
                let mut err = None;
                let mut checked = Instant::now();
                loop {
                    tokio::select! {
                        s = child.wait() => {
                            err = Some(format!("registry exited: {}", s.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())));
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {
                            if !app.cfg().docker_mirror || app.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                                child.kill().await.ok();
                                break;
                            }
                            if checked.elapsed() >= CAP_CHECK {
                                checked = Instant::now();
                                let root = app.data.join("registry/data");
                                let gb = app.cfg().mirror_gb;
                                if let Some(mb) = dir_mb(&root).await && over_cap(mb, gb) {
                                    // ponytail: no LRU; wiping is fine for a pull-through cache (it refills).
                                    tracing::info!("docker mirror: {mb} MB over the {gb} GB cap: wiping the cache");
                                    child.kill().await.ok();
                                    let _ = child.wait().await;
                                    let _ = tokio::fs::remove_dir_all(&root).await;
                                    break;
                                }
                            }
                        }
                    }
                }
                err
            }
        };
        let Some(err) = err else {
            set(&app, false, None);
            continue;
        };
        tracing::warn!("docker mirror: {err}");
        set(&app, false, Some(err));
        fails = if began.elapsed() > Duration::from_secs(60) { 1 } else { fails + 1 };
        tokio::time::sleep(Duration::from_secs((5u64 << (fails - 1).min(4)).min(60))).await;
    }
}

/// The `mirror` object of /api/state. `du` runs at most once a minute.
pub async fn status_json(app: &App) -> Value {
    let stale = now() >= app.mirror.lock().unwrap().cache_at + 60;
    if stale {
        let mb = dir_mb(&app.data.join("registry/data")).await;
        let mut s = app.mirror.lock().unwrap();
        s.cache_mb = mb;
        s.cache_at = now();
    }
    let s = app.mirror.lock().unwrap();
    json!({ "enabled": app.cfg().docker_mirror && SUPPORTED, "running": s.running, "error": s.error, "cache_mb": s.cache_mb })
}

/// (ok, detail) for `kiln doctor`. A bare CLI run has no supervisor, so a
/// registry answering on the port (from a live `serve`) counts too.
pub async fn check(app: &App) -> (bool, String) {
    if !app.cfg().docker_mirror {
        return (true, "disabled".into());
    }
    if !SUPPORTED {
        return (true, UNSUPPORTED_MSG.into());
    }
    let (running, error) = {
        let s = app.mirror.lock().unwrap();
        (s.running, s.error.clone())
    };
    match (running, error) {
        (true, _) => (true, format!("registry running on {ADDR}")),
        (false, Some(e)) => (false, e),
        (false, None) if port_busy().await => (true, format!("something is answering on {ADDR}")),
        (false, None) => (false, "not running (starts with `kiln serve`)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_check() {
        assert!(sha_matches(&format!("{SHA256}  registry.tgz.part\n"), SHA256));
        assert!(sha_matches(&format!("{}  x", SHA256.to_uppercase()), SHA256));
        assert!(!sha_matches("deadbeef  x", SHA256));
        assert!(!sha_matches("", SHA256));
    }

    #[test]
    fn cap() {
        assert!(!over_cap(20 * 1024, 20));
        assert!(over_cap(20 * 1024 + 1, 20));
    }

    #[test]
    fn registry_config() {
        let y = config_yaml(Path::new("/d/kiln"));
        assert!(y.contains("rootdirectory: \"/d/kiln/registry/data\""));
        assert!(y.contains("addr: 127.0.0.1:5000"));
        assert!(y.contains("remoteurl: https://registry-1.docker.io"));
        assert!(y.contains("ttl: 168h"));
        assert!(y.contains("enabled: true"));
    }
}
