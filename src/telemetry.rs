//! Opt-in usage statistics and crash reports. Both are off until the owner turns them on
//! (the dashboard asks once, Settings › Privacy changes it). kiln sends them itself: the
//! dashboard's CSP keeps the browser offline. `DO_NOT_TRACK=1` or `KILN_TELEMETRY=0`
//! turns both off whatever config.json says.
//!
//! Nothing that names anything is sent: no repo, account, host name, IP, path, token,
//! job name or log. A random install id (`<data>/telemetry_id`, deleted when both are
//! off) groups one box's reports. GET /api/telemetry returns the exact payloads.

use crate::{App, Config, now};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Where reports go: kiln's own Cloudflare Worker (deploy/telemetry). None = send nothing.
/// `KILN_TELEMETRY_URL` overrides it (an https URL), e.g. to test a Worker.
const ENDPOINT: Option<&str> = None;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD: &str = if cfg!(target_env = "musl") { "musl" } else { "gnu" };
/// Crash files kept while unsent; a panic loop must not fill the disk.
const MAX_PENDING: usize = 20;

/// Whether the panic hook records crashes (`crash_reports` on and not disabled by env).
static CRASH_ON: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<u64> = OnceLock::new();
static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn disabled_by_env() -> bool {
    let set = |k: &str, v: &[&str]| std::env::var(k).is_ok_and(|x| v.contains(&x.trim().to_ascii_lowercase().as_str()));
    set("DO_NOT_TRACK", &["1", "true", "yes"]) || set("KILN_TELEMETRY", &["0", "false", "no", "off"])
}

fn endpoint() -> Option<String> {
    std::env::var("KILN_TELEMETRY_URL").ok().filter(|u| u.starts_with("https://")).or(ENDPOINT.map(String::from))
}

/// Call at startup and on every config save.
pub fn apply(c: &Config) {
    CRASH_ON.store(c.crash_reports == Some(true) && !disabled_by_env(), Ordering::Relaxed);
}

/// Record panics to `<data>/crash/` (while `crash_reports` is on); the default hook still runs.
pub fn install_hook(data: &Path) {
    let _ = STARTED.set(now());
    let dir = data.join("crash");
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if CRASH_ON.load(Ordering::Relaxed) {
            let loc = info.location().map(|l| format!("{}:{}:{}", short_path(l.file()), l.line(), l.column()));
            let _ = record(&dir, &crash(loc.as_deref().unwrap_or("unknown"), std::thread::current().name()));
        }
        prev(info);
    }));
}

/// A crash report. The panic message is left out: it can quote a repo, a path or a login.
/// The location plus the version is enough to find the panic site.
fn crash(location: &str, thread: Option<&str>) -> Value {
    // Thread names are kiln's or tokio's; anything else is reported as "other".
    let thread = thread.filter(|t| matches!(*t, "main" | "tokio-runtime-worker")).unwrap_or("other");
    let t = now();
    json!({
        "kind": "crash",
        "version": VERSION,
        "build": BUILD,
        "arch": std::env::consts::ARCH,
        "location": location,
        "thread": thread,
        "uptime_secs": t.saturating_sub(*STARTED.get().unwrap_or(&t)),
        "at": t,
    })
}

/// A dependency's panic location is an absolute path on the build machine
/// (`/home/runner/.cargo/registry/src/<index>/tokio-1.47.1/src/...`): keep from the crate on.
fn short_path(f: &str) -> String {
    if !f.starts_with('/') {
        return f.to_string();
    }
    let parts: Vec<&str> = f.split('/').collect();
    match parts.iter().rposition(|p| *p == "src") {
        Some(i) if i > 0 => parts[i - 1..].join("/"),
        _ => parts.last().unwrap_or(&"").to_string(),
    }
}

fn record(dir: &Path, report: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if std::fs::read_dir(dir)?.count() >= MAX_PENDING {
        return Ok(());
    }
    let name = format!("{}-{}-{}.json", now(), std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
    std::fs::write(dir.join(name), serde_json::to_vec(report)?)
}

fn pending(data: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(data.join("crash")).into_iter().flatten().flatten().map(|e| e.path()).collect();
    v.sort();
    v
}

/// The install id, created on first use. Random: nothing about the box goes into it.
fn install_id(data: &Path) -> String {
    let path = data.join("telemetry_id");
    if let Ok(s) = std::fs::read_to_string(&path)
        && s.trim().len() == 32
    {
        return s.trim().to_string();
    }
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let _ = std::fs::write(&path, &id);
    id
}

/// The daily usage report: counts and settings, never names. The Worker
/// (deploy/telemetry/worker.js) accepts exactly these fields: change both together.
fn usage(app: &App, id: &str) -> Value {
    let c = app.cfg();
    let since = now().saturating_sub(86_400);
    let (mut jobs, mut passed, mut secs) = (0u64, 0u64, 0u64);
    let mut sizes = BTreeMap::<u32, u64>::new();
    for v in app.vms.lock().unwrap().iter() {
        let (Some(b), Some(e)) = (v.busy_since, v.ended) else { continue };
        if e < since {
            continue;
        }
        jobs += 1;
        passed += u64::from(v.result.as_deref() == Some("Succeeded"));
        secs += e.saturating_sub(b);
        *sizes.entry(v.cpus).or_default() += 1;
    }
    json!({
        "kind": "usage",
        "id": id,
        "version": VERSION,
        "build": BUILD,
        "arch": std::env::consts::ARCH,
        "host_threads": crate::host_threads(),
        "host_mem_gb": crate::vm::meminfo_kb("MemTotal:") / 1_048_576,
        "auth": match app.gh.source() { "app" => "app", "none" => "none", _ => "token" },
        "repos": app.repos().len(),
        "max_vms": c.max_vms,
        "vm_cpus": c.vm_cpus,
        "warm_vms": c.warm.values().sum::<u32>(),
        "egress": if c.egress == "filtered" { "filtered" } else { "open" },
        "features": {
            "cache": c.cache,
            "docker_mirror": c.docker_mirror,
            "auto_rebake": c.auto_rebake,
            "auto_update": c.auto_update,
            "debug_hold": c.debug_hold_mins > 0,
            "confined": crate::confine::ENFORCED.load(Ordering::Relaxed),
        },
        "jobs_24h": jobs,
        "passed_24h": passed,
        "job_minutes_24h": secs / 60,
        "sizes_24h": sizes,
        "uptime_hours": now().saturating_sub(*STARTED.get().unwrap_or(&now())) / 3600,
    })
}

/// GET /api/telemetry: the settings' state and the exact bytes each report would carry.
pub fn preview(app: &App) -> Value {
    let id = install_id(&app.data);
    let mut example = crash("src/vm.rs:123:45", Some("tokio-runtime-worker"));
    example["id"] = json!(id);
    json!({
        "endpoint": endpoint(),
        "disabled_by_env": disabled_by_env(),
        "usage": usage(app, &id),
        "crash_example": example,
        "pending_crashes": pending(&app.data).len(),
    })
}

fn client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent(format!("kiln/{VERSION}"))
        .build()
}

async fn send(http: &reqwest::Client, url: &str, body: &Value) -> bool {
    match http.post(url).json(body).send().await {
        Ok(r) if r.status().is_success() => true,
        Ok(r) => {
            tracing::debug!("telemetry: {}", r.status());
            false
        }
        Err(e) => {
            tracing::debug!("telemetry: {e}");
            false
        }
    }
}

/// Usage at most once a day, pending crash reports every hour; the first round 10 minutes
/// after start, so a crash loop sends nothing.
pub async fn supervise(app: Arc<App>) {
    let Ok(http) = client() else { return };
    tokio::time::sleep(Duration::from_secs(600)).await;
    loop {
        round(&app, &http).await;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn round(app: &App, http: &reqwest::Client) {
    let c = app.cfg();
    let off = disabled_by_env();
    let (usage_on, crash_on) = (c.usage_stats == Some(true) && !off, c.crash_reports == Some(true) && !off);
    if !crash_on {
        let _ = std::fs::remove_dir_all(app.data.join("crash"));
    }
    if !usage_on && !crash_on {
        // Opting back in later starts a new id, not linked to the old reports.
        let _ = std::fs::remove_file(app.data.join("telemetry_id"));
        return;
    }
    let Some(url) = endpoint() else { return };
    let id = install_id(&app.data);
    if crash_on {
        for f in pending(&app.data) {
            let Some(mut r) = std::fs::read(&f).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
                let _ = std::fs::remove_file(&f);
                continue;
            };
            r["id"] = json!(id);
            if !send(http, &url, &r).await {
                break;
            }
            let _ = std::fs::remove_file(&f);
        }
    }
    let last = app.data.join("telemetry_last");
    let sent = std::fs::read_to_string(&last).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    // A few minutes' slack so an hourly round doesn't slip a day's report by an hour.
    if usage_on && now().saturating_sub(sent) >= 86_400 - 600 && send(http, &url, &usage(app, &id)).await {
        let _ = std::fs::write(&last, now().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_paths_lose_the_build_machine() {
        assert_eq!(short_path("src/vm.rs"), "src/vm.rs");
        assert_eq!(
            short_path("/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/task.rs"),
            "tokio-1.47.1/src/runtime/task.rs"
        );
        assert_eq!(short_path("/rustc/abc/library/core/src/option.rs"), "core/src/option.rs");
    }

    #[test]
    fn crash_report_names_nothing() {
        let r = crash("src/web.rs:1:1", Some("worker-for-acme/secret-repo"));
        assert_eq!(r["thread"], "other");
        let keys: Vec<_> = r.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["arch", "at", "build", "kind", "location", "thread", "uptime_secs", "version"]);
    }

    #[test]
    fn usage_report_names_nothing() {
        let app = crate::test_app("telemetry-usage");
        let mut c = app.cfg();
        c.repos = vec!["acme-corp/secret-repo".into()];
        c.allowed_users = vec!["alice@example.com".into()];
        c.label = "acmelabel".into();
        c.warm.insert("acme-corp/secret-repo".into(), 2);
        *app.cfg.write().unwrap() = c;
        let body = serde_json::to_string(&preview(&app)).unwrap();
        for s in ["acme", "secret", "alice", "example.com", "acmelabel", app.data.to_str().unwrap()] {
            assert!(!body.contains(s), "{s} leaked: {body}");
        }
        assert_eq!(preview(&app)["usage"]["repos"], 1);
        assert_eq!(preview(&app)["usage"]["warm_vms"], 2);
    }

    #[test]
    fn crash_files_are_capped() {
        let dir = std::env::temp_dir().join(format!("kiln-crash-test-{}", std::process::id()));
        for _ in 0..MAX_PENDING + 5 {
            record(&dir, &json!({})).unwrap();
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), MAX_PENDING);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
