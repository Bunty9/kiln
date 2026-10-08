//! Opt-in usage statistics and crash reports. Both are off until the owner turns them on
//! (the dashboard asks once, Settings › Privacy changes it). kiln sends them itself: the
//! dashboard's CSP keeps the browser offline. `DO_NOT_TRACK=1` or `KILN_TELEMETRY=0`
//! turns both off whatever config.json says.
//!
//! Nothing that names anything is sent: no repo, account, host name, IP, path on this box,
//! token, job name or log. A random install id (`<data>/telemetry_id`, made at the first
//! send, deleted as soon as both are off) groups one box's reports. GET /api/telemetry
//! returns the usage report as it would be sent and an example crash report.

use crate::{App, Config, now};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Where reports go: the maintainers' receiver (Vercel + Postgres, private repo
/// Bunty9/kiln-telemetry-api). `KILN_TELEMETRY_URL` overrides it, e.g. to test a receiver;
/// set but not https, nothing is sent.
const ENDPOINT: Option<&str> = Some("https://kiln-telemetry-api.vercel.app/v1");
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

/// A bad override never falls back to the built-in address: test traffic must not reach it.
fn endpoint() -> Option<String> {
    match std::env::var("KILN_TELEMETRY_URL") {
        Ok(u) => u.starts_with("https://").then_some(u),
        Err(_) => ENDPOINT.map(String::from),
    }
}

/// (usage, crash) switches in effect: on in the config and not disabled by env.
fn enabled(c: &Config) -> (bool, bool) {
    let off = disabled_by_env();
    (c.usage_stats == Some(true) && !off, c.crash_reports == Some(true) && !off)
}

/// Call at startup and after every config save: arms the panic hook, and forgets what a
/// switch turned off no longer needs (waiting crash files, the install id).
pub fn apply(data: &Path, c: &Config) {
    let (usage_on, crash_on) = enabled(c);
    CRASH_ON.store(crash_on, Ordering::Relaxed);
    if !crash_on {
        let _ = std::fs::remove_dir_all(data.join("crash"));
    }
    if !usage_on && !crash_on {
        // Opting back in later starts a new id, not linked to the old reports.
        let _ = std::fs::remove_file(data.join("telemetry_id"));
    }
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

const CRASH_KEYS: [&str; 8] = ["arch", "at", "build", "kind", "location", "thread", "uptime_secs", "version"];

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

/// A panic location without the build machine's paths. kiln's own files are relative
/// (`src/vm.rs`). Absolute ones keep only what names no one: from the crate directory in
/// cargo's registry (`.../registry/src/<index>/tokio-1.47.1/src/...`) or from the standard
/// library (`/rustc/<hash>/library/core/...`); anything else (generated code under a target
/// dir, a vendored or path dependency in someone's home) is reduced to its file name.
fn short_path(f: &str) -> String {
    if !f.starts_with('/') && !f.split('/').any(|p| p == "..") {
        return f.to_string();
    }
    let parts: Vec<&str> = f.split('/').collect();
    let from = |i: usize| (i < parts.len()).then(|| parts[i..].join("/"));
    let registry = parts.windows(2).position(|w| w == ["registry", "src"]).and_then(|i| from(i + 3));
    let std = (parts.get(1) == Some(&"rustc")).then(|| parts.iter().position(|p| *p == "library")).flatten().and_then(|i| from(i + 1));
    registry.or(std).unwrap_or_else(|| parts.last().unwrap_or(&"").to_string())
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

fn read_id(data: &Path) -> Option<String> {
    let s = std::fs::read_to_string(data.join("telemetry_id")).ok()?;
    let s = s.trim();
    (s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then(|| s.to_string())
}

/// The install id, made on first use. Random: nothing about the box goes into it. None when
/// it cannot be made or kept: a new id per send would count one box as many.
fn install_id(data: &Path) -> Option<String> {
    if let Some(id) = read_id(data) {
        return Some(id);
    }
    let mut b = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).ok()?;
    let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::fs::write(data.join("telemetry_id"), &id).ok()?;
    Some(id)
}

/// The daily usage report: counts and settings, never names. Job counts come from the VM
/// records kiln keeps (the last 200), so a busier box reports at most those. The receiver
/// accepts exactly these fields (its lib/validate.js): change it first, then kiln.
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

/// GET /api/telemetry: the settings' state, the usage report as it would be sent now and an
/// example crash report. It never creates the id: looking is not opting in.
pub fn preview(app: &App) -> Value {
    let id = read_id(&app.data).unwrap_or_else(|| "(random, made at the first send)".into());
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

#[derive(PartialEq)]
enum Sent {
    Ok,
    /// The receiver refused this report for good (a 4xx): resending it can't help.
    Rejected,
    /// Network trouble or a server error: try again next round.
    Retry,
}

async fn send(http: &reqwest::Client, url: &str, body: &Value) -> Sent {
    match http.post(url).json(body).send().await {
        Ok(r) if r.status().is_success() => Sent::Ok,
        Ok(r) if r.status().is_client_error() && r.status() != reqwest::StatusCode::TOO_MANY_REQUESTS => {
            tracing::warn!("telemetry: report refused ({}), dropped", r.status());
            Sent::Rejected
        }
        Ok(r) => {
            tracing::debug!("telemetry: {}", r.status());
            Sent::Retry
        }
        Err(e) => {
            tracing::debug!("telemetry: {e}");
            Sent::Retry
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
    let (usage_on, crash_on) = enabled(&app.cfg());
    if !usage_on && !crash_on {
        return;
    }
    let Some(url) = endpoint() else {
        if std::env::var_os("KILN_TELEMETRY_URL").is_some() {
            tracing::warn!("telemetry: KILN_TELEMETRY_URL must be an https:// URL; sending nothing");
        }
        return;
    };
    let last = app.data.join("telemetry_last");
    let sent = std::fs::read_to_string(&last).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    // A few minutes' slack so an hourly round doesn't slip a day's report by an hour.
    let usage_due = usage_on && now().saturating_sub(sent) >= 86_400 - 600;
    let crashes = if crash_on { pending(&app.data) } else { vec![] };
    if !usage_due && crashes.is_empty() {
        return;
    }
    // Made only now, right before the first report that carries it.
    let Some(id) = install_id(&app.data) else {
        tracing::debug!("telemetry: cannot create {}", app.data.join("telemetry_id").display());
        return;
    };
    for f in crashes {
        let r = std::fs::read(&f).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
        let Some(Value::Object(m)) = r else {
            let _ = std::fs::remove_file(&f);
            continue;
        };
        // Only crash()'s own fields leave the box, whatever a file on disk says.
        let mut r: serde_json::Map<String, Value> = m.into_iter().filter(|(k, _)| CRASH_KEYS.contains(&k.as_str())).collect();
        r.insert("id".into(), json!(id));
        let r = Value::Object(r);
        if send(http, &url, &r).await == Sent::Retry {
            break;
        }
        let _ = std::fs::remove_file(&f);
    }
    if usage_due && send(http, &url, &usage(app, &id)).await != Sent::Retry {
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
        assert_eq!(
            short_path("/home/alice/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/zstd-sys-2.0.15+zstd.1.5.7/src/lib.rs"),
            "zstd-sys-2.0.15+zstd.1.5.7/src/lib.rs"
        );
        // A self-built binary: generated code, a vendored or path dependency, a parent-relative path.
        assert_eq!(short_path("/home/alice/src/kiln/target/release/build/foo-1a2b/out/gen.rs"), "gen.rs");
        assert_eq!(short_path("/home/alice/src/acme-secret/vendor/bar/src/lib.rs"), "lib.rs");
        assert_eq!(short_path("../acme-secret/src/lib.rs"), "lib.rs");
    }

    #[test]
    fn crash_report_names_nothing() {
        let r = crash("src/web.rs:1:1", Some("worker-for-acme/secret-repo"));
        assert_eq!(r["thread"], "other");
        let keys: Vec<_> = r.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, CRASH_KEYS);
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
        assert!(!app.data.join("telemetry_id").exists(), "looking at the preview must not create the id");
    }

    /// The receiver refuses a report whose fields differ: every report would be dropped.
    #[test]
    fn usage_fields_match_the_receiver() {
        let u = usage(&crate::test_app("telemetry-shape"), "0");
        let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(
            keys(&u),
            [
                "arch",
                "auth",
                "build",
                "egress",
                "features",
                "host_mem_gb",
                "host_threads",
                "id",
                "job_minutes_24h",
                "jobs_24h",
                "kind",
                "max_vms",
                "passed_24h",
                "repos",
                "sizes_24h",
                "uptime_hours",
                "version",
                "vm_cpus",
                "warm_vms"
            ]
        );
        assert_eq!(keys(&u["features"]), ["auto_rebake", "auto_update", "cache", "confined", "debug_hold", "docker_mirror"]);
    }

    #[test]
    fn opting_out_forgets_the_box() {
        let app = crate::test_app("telemetry-optout");
        let mut c = app.cfg();
        c.usage_stats = Some(true);
        c.crash_reports = Some(true);
        apply(&app.data, &c);
        assert!(install_id(&app.data).is_some());
        std::fs::create_dir_all(app.data.join("crash")).unwrap();
        // usage still on: the waiting crash files go, the id stays
        c.crash_reports = Some(false);
        apply(&app.data, &c);
        assert!(!app.data.join("crash").exists());
        assert!(read_id(&app.data).is_some());
        // both off: the id goes too
        c.usage_stats = None;
        apply(&app.data, &c);
        assert!(!app.data.join("telemetry_id").exists());
    }

    #[test]
    fn crash_files_are_capped() {
        let dir = std::env::temp_dir().join(format!("kiln-crash-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for _ in 0..MAX_PENDING + 5 {
            record(&dir, &json!({})).unwrap();
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), MAX_PENDING);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
