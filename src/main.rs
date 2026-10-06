mod github;
mod mirror;
mod vm;
mod web;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    /// "owner/name" repos to serve jobs for.
    pub repos: Vec<String>,
    /// Jobs opt in with `runs-on: [self-hosted, <label>]`.
    pub label: String,
    pub max_vms: usize,
    pub vm_cpus: u32,
    pub vm_mem_mb: u32,
    pub vm_disk_gb: u32,
    pub poll_secs: u64,
    pub job_timeout_mins: u64,
    /// A VM that booted but never got a job (cancelled, picked by another runner) is reaped after this.
    pub idle_timeout_mins: u64,
    /// Tailnet login names allowed to use the dashboard. Empty = only the owner of this machine.
    pub allowed_users: Vec<String>,
    /// Docker Hub pull-through cache for job VMs (host loopback :5000).
    pub docker_mirror: bool,
    /// Rebake by itself when the image is stale.
    pub auto_rebake: bool,
    /// Per-repo persistent cache disk (see vm.rs: trusted writer, throwaway readers).
    pub cache: bool,
    /// Virtual size of a new repo cache; it is reset when it grows past 1.2x this.
    pub cache_gb: u32,
    /// Docker mirror storage cap; over it (checked every 10 min) the cache is wiped.
    pub mirror_gb: u32,
    /// Keep a failed job's VM this long for SSH debugging. 0 = off.
    pub debug_hold_mins: u64,
    /// Public keys allowed into a held VM (one authorized_keys line each).
    pub debug_ssh_keys: Vec<String>,
    /// Job VM network: "open" (full outbound via the host) or "filtered" (internet + mirror only).
    pub egress: String,
    /// "owner/name" -> pre-booted idle VMs of the default size kept ready (0..=4).
    pub warm: BTreeMap<String, u32>,
    /// Idle warm VMs older than this are replaced so they never go stale.
    pub warm_recycle_mins: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7878".into(),
            repos: vec![],
            label: "kiln".into(),
            max_vms: 2,
            vm_cpus: 4,
            vm_mem_mb: 8192,
            vm_disk_gb: 40,
            poll_secs: 5,
            job_timeout_mins: 60,
            idle_timeout_mins: 10,
            allowed_users: vec![],
            docker_mirror: true,
            auto_rebake: true,
            cache: true,
            cache_gb: 30,
            mirror_gb: 20,
            debug_hold_mins: 0,
            debug_ssh_keys: vec![],
            egress: "open".into(),
            warm: BTreeMap::new(),
            warm_recycle_mins: 30,
        }
    }
}

impl Config {
    /// A VM of `cpus` serves `<label>-<cpus>cpu`, and the plain label only if it is the default size.
    pub fn runner_labels(&self, cpus: u32) -> Vec<String> {
        let mut l = vec!["self-hosted".into(), "linux".into(), "x64".into(), format!("{}-{cpus}cpu", self.label)];
        if cpus == self.vm_cpus {
            l.push(self.label.clone());
        }
        l
    }

    /// Warm VMs wanted for `repo` at size `cpus`: default size only, none while paused.
    pub fn warm_target(&self, repo: &str, cpus: u32) -> usize {
        if cpus != self.vm_cpus || self.max_vms == 0 {
            return 0;
        }
        self.warm.iter().find(|(r, _)| r.eq_ignore_ascii_case(repo)).map_or(0, |(_, &n)| n as usize)
    }

    pub fn mem_mb(&self, cpus: u32) -> u32 {
        if cpus == self.vm_cpus { self.vm_mem_mb } else { github::size_mem_mb(cpus) }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_for(host_threads())
    }

    fn validate_for(&self, host: u32) -> Result<()> {
        for (i, r) in self.repos.iter().enumerate() {
            if self.repos[..i].iter().any(|p| p.eq_ignore_ascii_case(r)) {
                bail!("repo listed twice (GitHub names are case-insensitive): {r:?}");
            }
            let ok = r.split('/').count() == 2
                && r.split('/').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)));
            if !ok {
                bail!("repo must look like owner/name: {r:?}");
            }
        }
        if self.listen.parse::<std::net::SocketAddr>().is_err() {
            bail!("listen must look like 0.0.0.0:7878");
        }
        if self.label.is_empty() || !self.label.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
            bail!("label must be set, using only A-Z a-z 0-9 _ . -");
        }
        // max_vms = 0 means paused: polling continues, nothing launches.
        if self.max_vms > 64 || self.vm_cpus == 0 || self.vm_mem_mb < 1024 || self.vm_disk_gb < 10 {
            bail!("max_vms <= 64 (0 = paused), vm_cpus >= 1, vm_mem_mb >= 1024, vm_disk_gb >= 10");
        }
        if self.vm_cpus > host {
            bail!("vm_cpus must be <= {host} (this host's threads)");
        }
        if self.poll_secs < 3 {
            bail!("poll_secs must be >= 3");
        }
        if !(1..=1440).contains(&self.job_timeout_mins) || !(1..=1440).contains(&self.idle_timeout_mins) {
            bail!("job_timeout_mins and idle_timeout_mins must be 1..=1440");
        }
        if !(5..=500).contains(&self.cache_gb) {
            bail!("cache_gb must be 5..=500");
        }
        if !(1..=500).contains(&self.mirror_gb) {
            bail!("mirror_gb must be 1..=500");
        }
        if self.debug_hold_mins > 120 {
            bail!("debug_hold_mins must be 0..=120 (0 = off)");
        }
        if let Some(k) = self.debug_ssh_keys.iter().find(|k| !vm::valid_ssh_key(k)) {
            bail!("debug_ssh_keys: not a single-line ssh-/ecdsa-/sk- public key: {:?}", k.chars().take(24).collect::<String>());
        }
        if let Some((r, _)) = self.warm.iter().find(|(r, n)| **n > 4 || !self.repos.iter().any(|x| x.eq_ignore_ascii_case(r))) {
            bail!("warm: {r:?} must be a configured repo with a count of 0..=4");
        }
        if !(5..=1440).contains(&self.warm_recycle_mins) {
            bail!("warm_recycle_mins must be 5..=1440");
        }
        if !["open", "filtered"].contains(&self.egress.as_str()) {
            bail!("egress must be \"open\" or \"filtered\"");
        }
        Ok(())
    }
}

#[derive(Serialize, Default, Clone)]
pub struct PollStatus {
    pub last_ok: Option<u64>,
    pub error: Option<String>,
    pub queued: HashMap<String, usize>,
    /// repo -> vCPUs -> queued jobs of that size.
    pub queued_by_size: HashMap<String, HashMap<u32, usize>>,
    pub repo_errors: HashMap<String, String>,
    /// Why launching is held back this tick (low memory/disk).
    pub blocked: Option<String>,
}

pub struct App {
    pub data: PathBuf,
    pub cfg: RwLock<Config>,
    pub gh: github::Gh,
    pub vms: Mutex<Vec<vm::Vm>>,
    pub kills: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// "Release now" for held VMs.
    pub releases: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// Repos (lowercase) whose cache is being committed. Only touched with `vms` locked first.
    pub committing: Mutex<std::collections::HashSet<String>>,
    pub poll: Mutex<PollStatus>,
    pub baking: AtomicBool,
    /// Set on SIGTERM/SIGINT: the scheduler stops launching.
    pub stopping: AtomicBool,
    /// repo -> (consecutive launch failures, retry_at unix time).
    pub backoff: Mutex<HashMap<String, (u32, u64)>>,
    pub mirror: Mutex<mirror::Status>,
}

impl App {
    pub fn cfg(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    pub fn save_cfg(&self, c: Config) -> Result<()> {
        c.validate()?;
        let mut w = self.cfg.write().unwrap();
        let (tmp, path) = (self.data.join("config.json.tmp"), self.data.join("config.json"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(&c)?)?;
        std::fs::rename(&tmp, &path)?;
        *w = c;
        Ok(())
    }

    pub fn save_token(&self, t: String) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(self.data.join("token"))?;
        std::io::Write::write_all(&mut f, t.trim().as_bytes())?;
        self.gh.set_token(t.trim().to_string(), "file");
        Ok(())
    }
}

pub fn host_threads() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Env var, then the token file the dashboard writes, then the gh CLI login.
/// `only_file`: a token was saved from the dashboard, so only that file counts
/// (a stale env token must not take over again on reload).
fn load_token(data: &std::path::Path, only_file: bool) -> (String, &'static str) {
    let env = ["KILN_GITHUB_TOKEN", "GITHUB_TOKEN"].iter().find_map(|k| std::env::var(k).ok().filter(|t| !t.is_empty()));
    let file = std::fs::read_to_string(data.join("token")).ok();
    pick_token(env, file, only_file, || {
        std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    })
}

fn pick_token(env: Option<String>, file: Option<String>, only_file: bool, gh: impl FnOnce() -> String) -> (String, &'static str) {
    let file = file.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    if only_file {
        return file.map_or((String::new(), "none"), |t| (t, "file"));
    }
    if let Some(t) = env {
        return (t, "env");
    }
    if let Some(t) = file {
        return (t, "file");
    }
    let gh = gh();
    if gh.is_empty() { (gh, "none") } else { (gh, "gh") }
}

#[tokio::main]
async fn main() -> Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V" | "version")) {
        println!("kiln {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    let data = std::env::var_os("KILN_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/kiln"));
    std::fs::create_dir_all(data.join("vms"))?;
    std::fs::create_dir_all(data.join("images"))?;
    let cfg: Config = match std::fs::read(data.join("config.json")) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => Config::default(),
    };
    let (token, source) = load_token(&data, false);
    let app = Arc::new(App {
        gh: github::Gh::new(token, source),
        cfg: RwLock::new(cfg),
        vms: Mutex::default(),
        data,
        kills: Mutex::default(),
        releases: Mutex::default(),
        committing: Mutex::default(),
        poll: Mutex::default(),
        baking: Default::default(),
        stopping: Default::default(),
        backoff: Default::default(),
        mirror: Default::default(),
    });

    match std::env::args().nth(1).as_deref() {
        Some("bake") => vm::bake(app).await,
        Some("doctor") => {
            let checks = vm::doctor(&app, true).await;
            for c in &checks {
                println!("{} {}: {}", if c.ok { "✓" } else { "✗" }, c.name, c.detail);
            }
            if checks.iter().any(|c| !c.ok) {
                std::process::exit(1);
            }
            Ok(())
        }
        Some("serve") | None => {
            // Only serve may touch leftovers: bake/doctor can run next to a live serve.
            *app.vms.lock().unwrap() = vm::load_history(&app.data);
            if app.cfg().egress == "filtered" {
                let a = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = vm::egress_ready(&a, true).await {
                        tracing::error!("egress filtering unavailable: {e}");
                    }
                });
            }
            tokio::spawn(scheduler(app.clone()));
            tokio::spawn(mirror::supervise(app.clone()));
            tokio::select! {
                r = web::serve(app.clone()) => r,
                _ = stop_signal() => {
                    shutdown(&app).await;
                    Ok(())
                }
            }
        }
        _ => {
            eprintln!(
                "usage: kiln [serve|bake|doctor|--version]\n  serve      run scheduler + dashboard (default)\n  bake       build the base VM image\n  doctor     check host prerequisites\n  --version  print the version"
            );
            std::process::exit(2)
        }
    }
}

async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Stop launching, kill every VM and wait (<= 20s) for each one's cleanup in
/// `vm::launch`: delete disk and JIT secret, deregister the runner, persist.
async fn shutdown(app: &Arc<App>) {
    tracing::info!("kiln shutting down");
    app.stopping.store(true, Ordering::SeqCst);
    for v in app.vms.lock().unwrap().iter_mut().filter(|v| v.state.is_active()) {
        v.note = Some("kiln shutting down".into());
    }
    // `kills` empties only once launch's cleanup (runner delete, persist) is done.
    // Notify every round: a tick racing with `stopping` may have launched one more VM.
    for _ in 0..100 {
        {
            let kills = app.kills.lock().unwrap();
            if kills.is_empty() {
                break;
            }
            kills.values().for_each(|n| n.notify_one());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn scheduler(app: Arc<App>) {
    // Runners a crashed kiln left registered (offline) would otherwise linger for a day.
    if app.gh.has_token() {
        for repo in &app.cfg().repos {
            match app.gh.sweep_runners(repo).await {
                Ok(n) if n > 0 => tracing::info!("{repo}: removed {n} stale runner(s)"),
                Ok(_) => {}
                Err(e) => tracing::warn!("{repo}: runner sweep: {e:#}"),
            }
        }
    }
    while !app.stopping.load(Ordering::SeqCst) {
        let cfg = app.cfg();
        let res = tick(&app, &cfg).await;
        {
            let mut p = app.poll.lock().unwrap();
            match res {
                Ok(q) => {
                    p.last_ok = Some(now());
                    p.error = None;
                    p.queued = q.iter().map(|(r, s)| (r.clone(), s.values().sum())).collect();
                    p.queued_by_size = q;
                }
                Err(e) => p.error = Some(format!("{e:#}")),
            }
        }
        let rate = *app.gh.rate.lock().unwrap();
        tokio::time::sleep(Duration::from_secs(poll_sleep(cfg.poll_secs, rate))).await;
    }
}

/// Seconds to wait between ticks. in_progress runs of hosted runners keep
/// changing, so their jobs responses are 200 (not free 304s) and drain the
/// budget: slow down when under 20% is left.
fn poll_sleep(poll_secs: u64, rate: Option<(u64, u64, u64)>) -> u64 {
    match rate {
        Some((rem, lim, _)) if rem * 5 < lim => 30,
        _ => poll_secs.max(3),
    }
}

/// Pick up a token that appeared (keyring unlocked, env fixed) or was rotated.
async fn reload_token(app: &Arc<App>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let bad = !app.gh.has_token() || app.poll.lock().unwrap().error.as_deref().is_some_and(|e| e.contains("401"));
    if !bad || now() < LAST.load(Ordering::Relaxed) + 60 {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    let data = app.data.clone();
    let only_file = app.gh.source() == "file";
    if let Ok((t, src)) = tokio::task::spawn_blocking(move || load_token(&data, only_file)).await
        && !t.is_empty()
    {
        app.gh.set_token(t, src);
    }
}

/// Not more than every 6h (a failing bake must not loop). Running VMs keep the
/// old base inode and the swap is atomic, so baking next to jobs is safe.
fn should_rebake(cfg: &Config, stale: bool, baking: bool, t: u64, last: u64) -> bool {
    cfg.auto_rebake && stale && !baking && t >= last + 6 * 3600
}

fn auto_rebake(app: &Arc<App>, cfg: &Config) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let stale = vm::image_info(&app.data, app.gh.latest_cached())["stale"] == true;
    let baking = app.baking.load(Ordering::SeqCst);
    if !should_rebake(cfg, stale, baking, now(), LAST.load(Ordering::Relaxed)) {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    tracing::info!("base image is stale: rebaking");
    let app = app.clone();
    tokio::spawn(async move {
        if let Err(e) = vm::bake(app).await {
            tracing::error!("auto-rebake failed: {e:#}");
        }
    });
}

/// One poll: per repo and VM size, boot as many VMs as there are queued jobs
/// not already covered by a VM of that size that is booting or idle. A JIT
/// runner may take any queued job with matching labels, not necessarily the
/// one that triggered it, so we match on counts, never on job ids.
/// Returns queued job counts per repo and size.
async fn tick(app: &Arc<App>, cfg: &Config) -> Result<HashMap<String, HashMap<u32, usize>>> {
    static TICK: AtomicUsize = AtomicUsize::new(0);
    reload_token(app).await;
    if !app.gh.has_token() {
        bail!("no GitHub token: set one in the dashboard, export KILN_GITHUB_TOKEN, or `gh auth login`");
    }
    if let Some(t) = app.gh.paused_until() {
        bail!("GitHub rate limit: paused until {t}");
    }
    if !vm::image_ready(&app.data) {
        bail!("base image not baked yet: run `kiln bake` or use the dashboard");
    }
    app.gh.refresh_latest().await;
    // Launching during a bake is fine: new VMs use the old base until the atomic swap.
    auto_rebake(app, cfg);
    let (mem_avail, disk) = (vm::mem_avail_mb(), vm::disk_free_gb(&app.data).await);
    // Shown on the dashboard; each size is gated on its own memory below.
    let mirror_mb = cfg.docker_mirror.then(|| mirror::cache_mb(app)).flatten();
    let cache_mb = Some(vm::cache_dir_mb(&app.data)).filter(|&m| m > 0);
    // Fail closed: filtered jobs never fall back to open networking.
    let egress_err = if cfg.egress == "filtered" { vm::egress_ready(app, false).await.err() } else { None };
    let mut blocked = egress_err
        .as_ref()
        .map(|e| format!("egress filtering unavailable: {e}"))
        .or_else(|| vm::launch_gate(mem_avail, cfg.vm_mem_mb, disk, mirror_mb, cache_mb));
    let mut budget = {
        let vms = app.vms.lock().unwrap();
        let act = vms.iter().filter(|v| v.state.is_active());
        let (mb, cpus) = act.fold((0, 0), |(m, c), v| (m + v.mem_mb as u64, c + v.cpus as u64));
        vm::Budget::new(vm::meminfo_kb("MemTotal:") / 1024, mb, cpus, host_threads())
    };

    let mut queued_by_repo = HashMap::new();
    let mut errors = vec![];
    let mut repo_errors = HashMap::new();
    // Rotate the start so the first repo doesn't always win scarce slots.
    let start = TICK.fetch_add(1, Ordering::Relaxed) % cfg.repos.len().max(1);
    for repo in cfg.repos.iter().cycle().skip(start).take(cfg.repos.len()) {
        let (by_size, runners) = match app.gh.queued_jobs(repo, &cfg.label, cfg.vm_cpus).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{repo}: {e:#}"));
                repo_errors.insert(repo.clone(), format!("{e:#}"));
                continue;
            }
        };
        attach_jobs(app, &runners);
        let backed_off = app.backoff.lock().unwrap().get(repo).is_some_and(|&(_, at)| at > now());
        vm::recycle_warm(app, repo, cfg.warm_recycle_mins).await;
        vm::recycle_stale_policy(app, repo, &vm::policy_id(cfg)).await;
        // A parked cache save whose readers are gone (or that hit a lock last time).
        vm::commit_pending(app, repo, "").await;
        // Sizes with demand, plus sizes with waiting VMs (which may now be surplus).
        let mut sizes: Vec<u32> = by_size.keys().copied().collect();
        if cfg.warm_target(repo, cfg.vm_cpus) > 0 {
            sizes.push(cfg.vm_cpus);
        }
        sizes.extend(app.vms.lock().unwrap().iter().filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.state.is_waiting()).map(|v| v.cpus));
        sizes.sort_unstable();
        sizes.dedup();
        for n in sizes {
            let queued = by_size.get(&n).copied().unwrap_or(0);
            let (waiting, active) = {
                let vms = app.vms.lock().unwrap();
                let waiting = vms.iter().filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.cpus == n && v.state.is_waiting()).count();
                (waiting, vms.iter().filter(|v| v.state.is_active()).count())
            };
            let target = cfg.warm_target(repo, n);
            let surplus = vm::surplus(waiting, queued, target);
            if surplus > 0 {
                vm::reap(app, repo, n, surplus).await;
            }
            let gate = vm::launch_gate(mem_avail, cfg.mem_mb(n), disk, mirror_mb, cache_mb);
            if queued > waiting && blocked.is_none() {
                blocked = gate.clone();
            }
            let held = backed_off || gate.is_some() || egress_err.is_some() || app.stopping.load(Ordering::SeqCst);
            let (demand, mut warm) = vm::launch_split(queued, waiting, target);
            // Replacements wait for a cache commit so they boot on the new cache.
            if warm > 0 && vm::cache_busy(app, repo) {
                warm = 0;
            }
            let want = if held { 0 } else { (demand + warm).min(cfg.max_vms.saturating_sub(active)) };
            // QEMU allocates lazily, so MemAvailable alone lets a burst overcommit.
            let (want, limit) = budget.take(want, cfg.mem_mb(n), n);
            if blocked.is_none() {
                blocked = limit;
            }
            for i in 0..want {
                vm::launch(app.clone(), repo.clone(), n, i >= demand);
            }
        }
        queued_by_repo.insert(repo.clone(), by_size);
    }
    {
        let mut p = app.poll.lock().unwrap();
        p.repo_errors = repo_errors;
        p.blocked = blocked;
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(queued_by_repo)
}

/// Copy job page and queue time onto the VM whose runner picked the job up.
fn attach_jobs(app: &App, runners: &HashMap<String, (String, u64)>) {
    let changed: Vec<vm::Vm> = app
        .vms
        .lock()
        .unwrap()
        .iter_mut()
        .filter_map(|v| {
            let (url, at) = runners.get(&v.id)?;
            if v.job_url.as_deref() == Some(url) && v.queued_at == Some(*at) {
                return None;
            }
            v.job_url = Some(url.clone());
            v.queued_at = Some(*at);
            Some(v.clone())
        })
        .collect();
    for v in &changed {
        vm::persist(app, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation() {
        let ok = |f: fn(&mut Config)| {
            let mut c = Config::default();
            f(&mut c);
            c.validate_for(8).is_ok()
        };
        assert!(ok(|_| {}));
        assert!(ok(|c| c.max_vms = 0));
        assert!(!ok(|c| c.max_vms = 65));
        assert!(!ok(|c| c.listen = "nope".into()));
        assert!(!ok(|c| c.poll_secs = 2));
        assert!(!ok(|c| c.job_timeout_mins = 0));
        assert!(!ok(|c| c.idle_timeout_mins = 1441));
        assert!(!ok(|c| c.vm_disk_gb = 9));
        assert!(!ok(|c| c.label = "a b".into()));
        assert!(!ok(|c| c.label = "".into()));
        assert!(ok(|c| c.vm_cpus = 8));
        assert!(!ok(|c| c.vm_cpus = 9));
        assert!(ok(|c| c.repos = vec!["a/b".into(), "a/c".into()]));
        assert!(!ok(|c| c.repos = vec!["Bunty9/Kiln".into(), "bunty9/kiln".into()]));
        assert!(ok(|c| c.cache_gb = 500));
        assert!(!ok(|c| c.cache_gb = 4));
        assert!(!ok(|c| c.cache_gb = 501));
        assert!(ok(|c| c.mirror_gb = 500));
        assert!(!ok(|c| c.mirror_gb = 0));
        assert!(!ok(|c| c.mirror_gb = 501));
        assert!(ok(|c| c.debug_hold_mins = 120));
        assert!(!ok(|c| c.debug_hold_mins = 121));
        assert!(ok(|c| c.debug_ssh_keys = vec!["ssh-ed25519 AAAA me@x".into()]));
        assert!(!ok(|c| c.debug_ssh_keys = vec!["rm -rf /".into()]));
        assert!(ok(|c| c.egress = "filtered".into()));
        assert!(!ok(|c| c.egress = "closed".into()));
        let warm = |repos: &[&str], r: &str, n: u32| {
            let mut c = Config { repos: repos.iter().map(|s| s.to_string()).collect(), ..Config::default() };
            c.warm.insert(r.into(), n);
            c.validate_for(8).is_ok()
        };
        assert!(warm(&["a/b"], "A/B", 4));
        assert!(warm(&["a/b"], "a/b", 0));
        assert!(!warm(&["a/b"], "a/b", 5));
        assert!(!warm(&["a/b"], "x/y", 1));
        assert!(ok(|c| c.warm_recycle_mins = 5));
        assert!(!ok(|c| c.warm_recycle_mins = 4));
        assert!(!ok(|c| c.warm_recycle_mins = 1441));
    }

    #[test]
    fn size_labels_and_memory() {
        let c = Config::default();
        assert_eq!(c.runner_labels(4), ["self-hosted", "linux", "x64", "kiln-4cpu", "kiln"]);
        assert_eq!(c.runner_labels(8), ["self-hosted", "linux", "x64", "kiln-8cpu"]);
        assert_eq!((c.mem_mb(4), c.mem_mb(2), c.mem_mb(16)), (8192, 4096, 24576));
        assert_eq!(c.poll_secs, 5);
    }

    #[test]
    fn warm_target_rules() {
        let mut c = Config { repos: vec!["a/b".into()], ..Config::default() };
        c.warm.insert("a/b".into(), 2);
        assert_eq!((c.warm_target("A/B", 4), c.warm_target("a/b", 8), c.warm_target("x/y", 4)), (2, 0, 0));
        c.max_vms = 0;
        assert_eq!(c.warm_target("a/b", 4), 0);
    }

    #[test]
    fn rebake_rules() {
        let c = Config::default();
        let h = 3600;
        assert!(should_rebake(&c, true, false, 7 * h, 0));
        assert!(!should_rebake(&c, true, false, 5 * h, 0));
        assert!(!should_rebake(&c, false, false, 7 * h, 0));
        assert!(!should_rebake(&c, true, true, 7 * h, 0));
        let off = Config { auto_rebake: false, ..Config::default() };
        assert!(!should_rebake(&off, true, false, 7 * h, 0));
    }

    #[test]
    fn token_precedence() {
        let s = |x: &str| Some(x.to_string());
        let pick = |env, file, only_file| pick_token(env, file, only_file, || "ghtok".into());
        assert_eq!(pick(s("e"), s("f\n"), false), ("e".into(), "env"));
        assert_eq!(pick(None, s(" f\n"), false), ("f".into(), "file"));
        assert_eq!(pick(None, s("  "), false), ("ghtok".into(), "gh"));
        // saved from the dashboard: a stale env token never wins again
        assert_eq!(pick(s("e"), s("f"), true), ("f".into(), "file"));
        assert_eq!(pick(s("e"), None, true), ("".into(), "none"));
    }

    #[test]
    fn poll_pacing() {
        assert_eq!(poll_sleep(5, None), 5);
        assert_eq!(poll_sleep(5, Some((1000, 5000, 0))), 5);
        assert_eq!(poll_sleep(5, Some((999, 5000, 0))), 30);
        assert_eq!(poll_sleep(1, Some((5000, 5000, 0))), 3);
    }
}
