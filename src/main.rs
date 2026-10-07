mod app_auth;
mod github;
mod mirror;
mod update;
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
    /// vCPUs -> memory MB of that size, overriding the built-in min(N x 2048, 24576).
    /// The default size uses `vm_mem_mb`.
    pub size_mem_mb: BTreeMap<u32, u32>,
    pub poll_secs: u64,
    pub job_timeout_mins: u64,
    /// A VM that booted but never got a job (cancelled, picked by another runner) is reaped after this.
    pub idle_timeout_mins: u64,
    /// Tailnet login names allowed to use the dashboard. Empty = only the owner of this machine.
    pub allowed_users: Vec<String>,
    /// GitHub App mode: accounts (user or org logins) whose installations are served,
    /// besides the App owner's. Empty = the owner's only.
    pub app_accounts: Vec<String>,
    /// Docker Hub pull-through cache for job VMs (host loopback :5000).
    pub docker_mirror: bool,
    /// Rebake by itself when the image is stale.
    pub auto_rebake: bool,
    /// Node versions baked into the tool cache ("20" = newest 20.x, or exact "20.19.5").
    /// The newest is the bare `node`. Takes effect at the next bake.
    pub bake_node_versions: Vec<String>,
    /// Extra apt packages installed into the base image. Takes effect at the next bake.
    pub bake_apt_packages: Vec<String>,
    /// Per-repo persistent cache disk (see vm.rs: trusted writer, throwaway readers).
    pub cache: bool,
    /// "owner/name" -> branches whose successful pushes may also save the cache,
    /// besides the default branch (e.g. an integration branch like "dev").
    pub cache_branches: BTreeMap<String, Vec<String>>,
    /// Virtual size of a new repo cache; it is reset when it grows past 1.2x this.
    pub cache_gb: u32,
    /// "owner/name" -> cache size in GB for that repo, overriding `cache_gb`.
    pub repo_cache_gb: BTreeMap<String, u32>,
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
    /// Apply a newer signed release by itself when the box is idle.
    pub auto_update: bool,
    /// "owner/name" whose GitHub releases kiln updates from.
    pub update_repo: String,
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
            size_mem_mb: BTreeMap::new(),
            poll_secs: 5,
            job_timeout_mins: 60,
            idle_timeout_mins: 10,
            allowed_users: vec![],
            app_accounts: vec![],
            docker_mirror: true,
            auto_rebake: true,
            bake_node_versions: vec!["24".into()],
            bake_apt_packages: vec![],
            cache: true,
            cache_branches: BTreeMap::new(),
            cache_gb: 30,
            repo_cache_gb: BTreeMap::new(),
            mirror_gb: 20,
            debug_hold_mins: 0,
            debug_ssh_keys: vec![],
            egress: "open".into(),
            warm: BTreeMap::new(),
            warm_recycle_mins: 30,
            auto_update: false,
            update_repo: "Bunty9/kiln".into(),
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

    /// Extra cache-writer branches of `repo` (the default branch always writes).
    pub fn cache_branches(&self, repo: &str) -> Vec<String> {
        self.cache_branches.iter().find(|(r, _)| r.eq_ignore_ascii_case(repo)).map(|(_, b)| b.clone()).unwrap_or_default()
    }

    pub fn mem_mb(&self, cpus: u32) -> u32 {
        if cpus == self.vm_cpus {
            self.vm_mem_mb
        } else {
            self.size_mem_mb.get(&cpus).copied().unwrap_or_else(|| github::size_mem_mb(cpus))
        }
    }

    /// Cache disk size of `repo`: its `repo_cache_gb` entry, else `cache_gb`.
    pub fn cache_gb_for(&self, repo: &str) -> u32 {
        self.repo_cache_gb.iter().find(|(r, _)| r.eq_ignore_ascii_case(repo)).map_or(self.cache_gb, |(_, &g)| g)
    }

    /// Per-repo maps (`warm`, `cache_branches`, `repo_cache_gb`) may name repos that are
    /// not served (removed, or a GitHub App no longer installed there): lookups ignore them.
    pub fn validate(&self) -> Result<()> {
        self.validate_for(host_threads())
    }

    fn validate_for(&self, host: u32) -> Result<()> {
        for (i, r) in self.repos.iter().enumerate() {
            if self.repos[..i].iter().any(|p| p.eq_ignore_ascii_case(r)) {
                bail!("repo listed twice (GitHub names are case-insensitive): {r:?}");
            }
            if !valid_repo(r) {
                bail!("repo must look like owner/name: {r:?}");
            }
        }
        if !valid_repo(&self.update_repo) {
            bail!("update_repo must look like owner/name: {:?}", self.update_repo);
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
        if let Some((r, _)) = self.repo_cache_gb.iter().find(|(_, g)| !(5..=500).contains(*g)) {
            bail!("repo_cache_gb: {r:?} must be 5..=500 GB");
        }
        if let Some((n, _)) = self.size_mem_mb.iter().find(|(n, m)| !(1..=host).contains(*n) || !(1024..=1_048_576).contains(*m)) {
            bail!("size_mem_mb: size {n} must be 1..={host} vCPUs with 1024..=1048576 MB");
        }
        // A trailing '-' makes apt-get install *remove* the package (and '+' is an action too).
        let apt_ok = |p: &String| {
            p.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && !p.ends_with(['-', '+'])
                && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".+-".contains(c))
        };
        if self.bake_apt_packages.len() > 32 || !self.bake_apt_packages.iter().all(apt_ok) {
            bail!("bake_apt_packages: up to 32 apt package names (a-z 0-9 . + -, not ending in - or +)");
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
        if let Some((r, _)) = self.warm.iter().find(|(_, n)| **n > 4) {
            bail!("warm: {r:?} must have a count of 0..=4");
        }
        for bs in self.cache_branches.values() {
            if let Some(b) = bs.iter().find(|b| !valid_branch(b)) {
                bail!("cache_branches: {b:?} is not a branch name");
            }
        }
        let node_ok = |v: &String| {
            let p: Vec<&str> = v.split('.').collect();
            (p.len() == 1 || p.len() == 3) && p.iter().all(|x| !x.is_empty() && x.len() <= 4 && x.bytes().all(|b| b.is_ascii_digit()))
        };
        if !(1..=4).contains(&self.bake_node_versions.len()) || !self.bake_node_versions.iter().all(node_ok) {
            bail!("bake_node_versions: 1 to 4 entries, each a major (\"20\") or an exact version (\"20.19.5\")");
        }
        if !(5..=1440).contains(&self.warm_recycle_mins) {
            bail!("warm_recycle_mins must be 5..=1440");
        }
        if !["open", "filtered"].contains(&self.egress.as_str()) {
            bail!("egress must be \"open\" or \"filtered\"");
        }
        if let Some(a) = self.app_accounts.iter().find(|a| !valid_login(a)) {
            bail!("app_accounts: {a:?} is not a GitHub user or org login (letters, digits, single hyphens, at most 39)");
        }
        Ok(())
    }
}

/// "owner/name" of plain characters, no dot segments.
fn valid_repo(r: &str) -> bool {
    r.split('/').count() == 2
        && r.split('/').all(|p| !p.is_empty() && p != "." && p != ".." && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)))
}

/// GitHub login: 1-39 alphanumerics or single hyphens, not at either end.
fn valid_login(l: &str) -> bool {
    (1..=39).contains(&l.len())
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !l.starts_with('-')
        && !l.ends_with('-')
        && !l.contains("--")
}

/// Conservative git branch name check: no spaces, no ref syntax, no "..".
fn valid_branch(b: &str) -> bool {
    !b.is_empty()
        && !b.contains("..")
        && !b.starts_with(['/', '-', '.'])
        && !b.ends_with(['/', '.'])
        && b.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
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
    /// What `blocked` is: "draining", "old_image", "github_api", "egress", "memory", "disk", "budget" or "held".
    pub blocked_kind: Option<String>,
    /// repo -> queued fork pull request jobs kiln refuses to run.
    pub refused_forks: HashMap<String, usize>,
}

/// Pause after the n-th consecutive GitHub-wide registration failure: 1, 2, 5, then 10 min.
fn api_backoff_secs(fails: u32) -> u64 {
    match fails {
        0 => 0,
        1 => 60,
        2 => 120,
        3 => 300,
        _ => 600,
    }
}

/// GitHub-wide runner registration failures (5xx or unreachable): unlike a repo's own
/// failures, retrying another repo or job would only fail the same way, so every launch waits.
#[derive(Default, Clone)]
pub struct ApiBackoff {
    pub fails: u32,
    pub retry_at: u64,
    /// Last HTTP status (None = GitHub unreachable).
    pub status: Option<u16>,
}

impl ApiBackoff {
    /// Record a failure at `t`. Returns true when it starts a new backoff step (log it).
    /// A failure inside the current pause is a sibling launch of the same batch: no escalation.
    pub fn fail(&mut self, status: Option<u16>, t: u64) -> bool {
        self.status = status;
        if t < self.retry_at {
            return false;
        }
        self.fails += 1;
        self.retry_at = t + api_backoff_secs(self.fails);
        true
    }

    pub fn held(&self, t: u64) -> bool {
        t < self.retry_at
    }

    /// Launches allowed of `want`: all while healthy; while failing, one probe once the
    /// pause is over and no earlier launch is still minting (`probing`). One mint attempt per
    /// step, so a batch does not fail N times; the rest wait for a mint to succeed.
    pub fn allow(&self, t: u64, want: usize, probing: bool) -> usize {
        match self.fails {
            0 => want,
            _ if self.held(t) || probing => 0,
            _ => want.min(1),
        }
    }

    /// The Overview banner (`PollStatus.blocked`) until a mint succeeds again.
    pub fn banner(&self, t: u64) -> Option<String> {
        if self.fails == 0 {
            return None;
        }
        let what = match self.status {
            Some(s) => format!("GitHub is rejecting runner registration (HTTP {s})"),
            None => "GitHub is unreachable for runner registration".into(),
        };
        Some(if self.held(t) {
            format!("{what} — launches paused, retrying in {} min", (self.retry_at - t).div_ceil(60))
        } else {
            format!("{what} — retrying with the next launch")
        })
    }
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
    /// GitHub-wide registration failures: hold every launch.
    pub api_backoff: Mutex<ApiBackoff>,
    pub mirror: Mutex<mirror::Status>,
    /// One-time states of GitHub App manifest flows in progress.
    pub app_states: Mutex<app_auth::States>,
    /// An update is draining: launch nothing (warm included), reap idle VMs.
    pub draining: AtomicBool,
    pub update: Mutex<update::Status>,
}

impl App {
    pub fn cfg(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    pub fn save_cfg(&self, c: Config) -> Result<()> {
        c.validate()?;
        *self.gh.app_accounts.write().unwrap() = c.app_accounts.clone();
        let mut w = self.cfg.write().unwrap();
        let (tmp, path) = (self.data.join("config.json.tmp"), self.data.join("config.json"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(&c)?)?;
        std::fs::rename(&tmp, &path)?;
        *w = c;
        Ok(())
    }

    /// Repos kiln serves: the App's installations in App mode, else the configured list.
    pub fn repos(&self) -> Vec<String> {
        match self.gh.app() {
            Some(a) => a.names.read().unwrap().clone(),
            None => self.cfg().repos,
        }
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
    // First, before anything that can fail (a bad config.json included), so a new version
    // that dies early still counts its boots and gets rolled back. CLI runs never count.
    if is_serve(std::env::args().nth(1).as_deref()) {
        update::on_start(&data);
    }
    std::fs::create_dir_all(data.join("vms"))?;
    std::fs::create_dir_all(data.join("images"))?;
    std::fs::create_dir_all(data.join("update"))?;
    let cfg: Config = match std::fs::read(data.join("config.json")) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => Config::default(),
    };
    let (token, source) = load_token(&data, false);
    let gh = github::Gh::new(token, source);
    *gh.app_accounts.write().unwrap() = cfg.app_accounts.clone();
    match app_auth::load(&data) {
        Some(Ok(a)) => gh.set_app(Some(Arc::new(a))),
        Some(Err(e)) => tracing::error!("GitHub App configured but unusable, using token auth: {e:#}"),
        None => {}
    }
    let app = Arc::new(App {
        gh,
        cfg: RwLock::new(cfg),
        vms: Mutex::default(),
        kills: Mutex::default(),
        releases: Mutex::default(),
        committing: Mutex::default(),
        poll: Mutex::default(),
        baking: Default::default(),
        stopping: Default::default(),
        backoff: Default::default(),
        api_backoff: Default::default(),
        mirror: Default::default(),
        app_states: Mutex::new(app_auth::States::open(data.join("app_states.json"))),
        draining: Default::default(),
        update: Mutex::new(update::Status::load(&data)),
        data,
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
        a if is_serve(a) => {
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
            tokio::spawn(update::supervise(app.clone()));
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

/// `kiln` or `kiln serve`: the service (what systemd runs, and what an update re-execs).
fn is_serve(arg: Option<&str>) -> bool {
    matches!(arg, Some("serve") | None)
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

/// Seconds between App discoveries: 30 while it serves no repo or has never discovered
/// successfully (so a fresh install shows up quickly), else 5 minutes.
fn app_refresh_secs(repos: usize, ever_ok: bool) -> u64 {
    if repos == 0 || !ever_ok { 30 } else { 300 }
}

/// App mode: refresh which repos the App is installed on (see `app_refresh_secs`).
/// A failure keeps the previous list (a GitHub hiccup must not unschedule every repo).
async fn refresh_app(app: &Arc<App>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let Some(a) = app.gh.app() else { return };
    let every = app_refresh_secs(a.names.read().unwrap().len(), a.discovered_at.load(Ordering::Relaxed) != 0);
    if now() < LAST.load(Ordering::Relaxed) + every {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    match app.gh.discover_now().await {
        Ok(n) => {
            tracing::info!("GitHub App: {n} repo(s) installed");
            // Per-installation failures and ignored installations.
            if let Some(e) = a.error.lock().unwrap().clone() {
                tracing::warn!("GitHub App discovery: {e}");
            }
        }
        Err(e) => tracing::warn!("GitHub App discovery: {e:#}"),
    }
}

async fn scheduler(app: Arc<App>) {
    refresh_app(&app).await;
    // Runners a crashed kiln left registered (offline) would otherwise linger for a day.
    if app.gh.has_token() {
        for repo in &app.repos() {
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
        let rate = app.gh.rate();
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

/// `blocked_kind` of a `vm::launch_gate` reason.
fn gate_kind(m: &str) -> &'static str {
    if m.starts_with("low disk") { "disk" } else { "memory" }
}

/// The `held` banner when queued jobs (`demand`) find no free slot and debug holds take some:
/// the queue is waiting on holds, which looks like an outage unless said.
fn held_block(demand: usize, max_vms: usize, active: usize, held: usize) -> Option<String> {
    (demand > 0 && max_vms > 0 && held > 0 && active >= max_vms)
        .then(|| format!("{held} of {max_vms} slots held for debugging — jobs are waiting"))
}

/// Pick up a token that appeared (keyring unlocked, env fixed) or was rotated.
async fn reload_token(app: &Arc<App>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    if app.gh.app().is_some() {
        return;
    }
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
    let stale = vm::image_info(&app.data, app.gh.latest_cached(), cfg)["stale"] == true;
    // vm::bake would refuse: do not spend the 6 h slot on it.
    let baking = app.baking.load(Ordering::SeqCst) || app.draining.load(Ordering::SeqCst);
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
    refresh_app(app).await;
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
    // An image from an older recipe may lack the fork-refusal hook: launch nothing, warm included.
    let old_image = !vm::image_recipe_ok(&vm::image_info(&app.data, None, cfg));
    let draining = app.draining.load(Ordering::SeqCst);
    let api = app.api_backoff.lock().unwrap().clone();
    // A launch still minting is the probe of this backoff step.
    let mut probing = api.fails > 0 && app.vms.lock().unwrap().iter().any(|v| v.state == vm::State::Booting && v.runner_id.is_none());
    let mut any_queued = false;
    let gated = |g: Option<String>| g.map(|m| (gate_kind(&m), m));
    let mut blocked = draining
        .then(|| ("draining", "draining for a kiln update: running jobs finish, then kiln restarts".to_string()))
        .or_else(|| old_image.then(|| ("old_image", "base image predates kiln's fork-refusal hook: rebake (Settings › Image)".to_string())))
        .or_else(|| api.banner(now()).filter(|_| api.held(now())).map(|m| ("github_api", m)))
        .or_else(|| egress_err.as_ref().map(|e| ("egress", format!("egress filtering unavailable: {e}"))))
        .or_else(|| gated(vm::launch_gate(mem_avail, cfg.vm_mem_mb, disk, mirror_mb, cache_mb)));
    let mut budget = {
        let vms = app.vms.lock().unwrap();
        let act = vms.iter().filter(|v| v.state.is_active());
        let (mb, cpus) = act.fold((0, 0), |(m, c), v| (m + v.mem_mb as u64, c + v.cpus as u64));
        vm::Budget::new(vm::meminfo_kb("MemTotal:") / 1024, mb, cpus, host_threads())
    };

    let mut queued_by_repo = HashMap::new();
    let mut errors = vec![];
    let mut repo_errors = HashMap::new();
    let mut refused_forks = HashMap::new();
    let mut released = false;
    // Rotate the start so the first repo doesn't always win scarce slots.
    let repos = app.repos();
    let start = TICK.fetch_add(1, Ordering::Relaxed) % repos.len().max(1);
    for repo in repos.iter().cycle().skip(start).take(repos.len()) {
        // App mode: only the repos of a rate-limited installation wait.
        if let Some(m) = app.gh.repo_paused(repo) {
            errors.push(format!("{repo}: {m}"));
            repo_errors.insert(repo.clone(), m);
            continue;
        }
        let (by_size, runners, forks) = match app.gh.queued_jobs(repo, &cfg.label, cfg.vm_cpus).await {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{repo}: {e:#}"));
                repo_errors.insert(repo.clone(), format!("{e:#}"));
                continue;
            }
        };
        if forks > 0 {
            refused_forks.insert(repo.clone(), forks);
        }
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
            let (waiting, active, holds) = {
                let vms = app.vms.lock().unwrap();
                let waiting = vms.iter().filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.cpus == n && v.state.is_waiting()).count();
                let holds = vms.iter().filter(|v| v.state == vm::State::Held).count();
                (waiting, vms.iter().filter(|v| v.state.is_active()).count(), holds)
            };
            // Draining: every waiting VM is surplus, and none are kept warm.
            let target = if draining { 0 } else { cfg.warm_target(repo, n) };
            let surplus = if draining { waiting } else { vm::surplus(waiting, queued, target) };
            if surplus > 0 {
                vm::reap(app, repo, n, surplus).await;
            }
            let gate = vm::launch_gate(mem_avail, cfg.mem_mb(n), disk, mirror_mb, cache_mb);
            if queued > waiting && blocked.is_none() {
                blocked = gated(gate.clone());
            }
            any_queued |= queued > 0;
            let held = backed_off || old_image || gate.is_some() || egress_err.is_some() || draining || app.stopping.load(Ordering::SeqCst);
            let (demand, mut warm) = vm::launch_split(queued, waiting, target);
            // Replacements wait for a cache commit so they boot on the new cache.
            if warm > 0 && vm::cache_busy(app, repo) {
                warm = 0;
            }
            let want = if held { 0 } else { (demand + warm).min(cfg.max_vms.saturating_sub(active)) };
            let want = api.allow(now(), want, probing);
            probing |= want > 0;
            // A debug hold must not keep a queued job waiting: end the oldest (one per tick).
            if let (false, Some(m)) = (held, held_block(demand, cfg.max_vms, active, holds)) {
                released = released || vm::release_oldest_hold(app);
                if blocked.is_none() {
                    blocked = Some(("held", m));
                }
            }
            // QEMU allocates lazily, so MemAvailable alone lets a burst overcommit.
            let (want, limit) = budget.take(want, cfg.mem_mb(n), n);
            if blocked.is_none() {
                blocked = limit.map(|m| ("budget", m));
            }
            for i in 0..want {
                vm::launch(app.clone(), repo.clone(), n, i >= demand);
            }
        }
        queued_by_repo.insert(repo.clone(), by_size);
    }
    // Pause over: the banner stays only while a job waits on the probe, not indefinitely.
    if blocked.is_none() && any_queued {
        blocked = api.banner(now()).map(|m| ("github_api", m));
    }
    {
        let mut p = app.poll.lock().unwrap();
        p.repo_errors = repo_errors;
        p.refused_forks = refused_forks;
        p.blocked_kind = blocked.as_ref().map(|b| b.0.to_string());
        p.blocked = blocked.map(|b| b.1);
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(queued_by_repo)
}

/// Copy job page and queue time onto the VM whose runner picked the job up.
/// A fork PR job that reached one of our runners anyway (a JIT runner takes any
/// matching job) is killed. The guest's pre-job hook fails it before its first
/// step; this kill is the backstop.
fn attach_jobs(app: &App, runners: &HashMap<String, (String, u64, bool)>) {
    for (id, _) in runners.iter().filter(|(_, r)| r.2) {
        let hit = app.vms.lock().unwrap().iter_mut().find(|v| &v.id == id && v.state.is_active()).map(|v| {
            v.note = Some("refused: pull request from a fork".into());
        });
        if hit.is_some()
            && let Some(k) = app.kills.lock().unwrap().get(id)
        {
            k.notify_one();
        }
    }
    let changed: Vec<vm::Vm> = app
        .vms
        .lock()
        .unwrap()
        .iter_mut()
        .filter_map(|v| {
            let (url, at, _) = runners.get(&v.id)?;
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
    fn gate_kinds() {
        assert_eq!(gate_kind(&vm::launch_gate(0, 2048, Some(500), None, None).unwrap()), "memory");
        assert_eq!(gate_kind(&vm::launch_gate(1 << 20, 2048, Some(1), None, None).unwrap()), "disk");
    }

    #[test]
    fn held_slots_block_queued_jobs() {
        // max_vms 2: one busy, one held, a job queued -> the hold is in the way
        assert_eq!(held_block(1, 2, 2, 1).unwrap(), "1 of 2 slots held for debugging — jobs are waiting");
        assert!(held_block(1, 2, 1, 1).is_none()); // a slot is free: it launches
        assert!(held_block(0, 2, 2, 1).is_none()); // nothing queued
        assert!(held_block(1, 2, 2, 0).is_none()); // full, but not because of holds
        assert!(held_block(1, 0, 1, 1).is_none()); // paused: holds are not why
    }

    #[test]
    fn only_serve_counts_update_boots() {
        assert!(is_serve(None));
        assert!(is_serve(Some("serve")));
        for a in ["bake", "doctor", "--version", "-V", "version", "help", ""] {
            assert!(!is_serve(Some(a)), "{a}");
        }
    }

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
        assert!(warm(&["a/b"], "x/y", 1), "unserved repos are ignored, not rejected");
        let branches = |r: &str, b: &str| {
            let mut c = Config { repos: vec!["a/b".into()], ..Config::default() };
            c.cache_branches.insert(r.into(), vec![b.into()]);
            c.validate_for(8).is_ok()
        };
        assert!(branches("A/B", "dev"));
        assert!(!branches("a/b", "dev/") && !branches("a/b", ".dev") && !branches("a/b", "dev?x") && !branches("a/b", "release/*"));
        let sized = |r: &str, g: u32| {
            let mut c = Config { repos: vec!["a/b".into()], ..Config::default() };
            c.repo_cache_gb.insert(r.into(), g);
            c.validate_for(8).is_ok()
        };
        assert!(sized("A/B", 60) && sized("a/b", 5) && sized("a/b", 500));
        assert!(sized("x/y", 60) && !sized("a/b", 4) && !sized("a/b", 501));
        let mut c = Config::default();
        c.cache_branches.insert("Owner/Repo".into(), vec!["dev".into()]);
        assert_eq!(c.cache_branches("owner/repo"), ["dev"]);
        assert!(c.cache_branches("other/repo").is_empty());
        assert!(branches("a/b", "release/1.x"));
        assert!(branches("x/y", "dev"));
        assert!(!branches("a/b", ""));
        assert!(!branches("a/b", "a..b"));
        assert!(!branches("a/b", "dev branch"));
        assert!(!branches("a/b", "-dev"));
        assert!(ok(|c| c.bake_node_versions = vec!["20".into(), "24.21.0".into()]));
        assert!(ok(|c| c.bake_apt_packages = vec!["chromium".into(), "libnss3".into(), "g++-12".into(), "fonts-liberation2".into()]));
        assert!(!ok(|c| c.bake_apt_packages = vec!["Chromium".into()]));
        assert!(!ok(|c| c.bake_apt_packages = vec!["-y".into()]));
        assert!(!ok(|c| c.bake_apt_packages = vec!["a; reboot".into()]));
        assert!(!ok(|c| c.bake_apt_packages = vec!["".into()]));
        // apt-get install reads a trailing '-' as "remove" ('+' as install, '=' / '/' as version / release)
        for p in ["openssh-server-", "docker.io-", "libc6+", "libc6=2.39", "libc6/noble"] {
            let c = Config { bake_apt_packages: vec![p.into()], ..Config::default() };
            assert!(c.validate_for(8).is_err(), "{p}");
        }
        assert!(!ok(|c| c.bake_apt_packages = (0..33).map(|i| format!("p{i}")).collect()));
        assert!(ok(|c| c.size_mem_mb = [(8, 12288), (2, 1024)].into()));
        assert!(!ok(|c| c.size_mem_mb = [(9, 12288)].into()));
        assert!(!ok(|c| c.size_mem_mb = [(0, 12288)].into()));
        assert!(!ok(|c| c.size_mem_mb = [(8, 1000)].into()));
        assert!(!ok(|c| c.bake_node_versions = vec![]));
        assert!(!ok(|c| c.bake_node_versions = vec!["v20".into()]));
        assert!(!ok(|c| c.bake_node_versions = vec!["20.1".into()]));
        assert!(!ok(|c| c.bake_node_versions = vec!["20; rm -rf /".into()]));
        assert!(ok(|c| c.warm_recycle_mins = 5));
        assert!(!ok(|c| c.warm_recycle_mins = 4));
        assert!(!ok(|c| c.warm_recycle_mins = 1441));
        assert_eq!((Config::default().update_repo.as_str(), Config::default().auto_update), ("Bunty9/kiln", false));
        assert!(ok(|c| c.update_repo = "my-org/kiln.fork".into()));
        for r in ["", "kiln", "a/b/c", "a/../b", "a/b?x", "/kiln"] {
            let c = Config { update_repo: r.into(), ..Config::default() };
            assert!(c.validate_for(8).is_err(), "{r}");
        }
    }

    #[test]
    fn unserved_per_repo_keys_never_block_saves() {
        // After Remove App (or when app.pem stops loading) the keys set in App mode
        // stay in config.json; they must not lock every later save or bake.
        let mut c = Config { repos: vec!["a/b".into()], ..Config::default() };
        c.warm.insert("other/repo".into(), 1);
        c.cache_branches.insert("other/repo".into(), vec!["dev".into()]);
        c.repo_cache_gb.insert("other/repo".into(), 60);
        assert!(c.validate_for(8).is_ok());
    }

    #[test]
    fn app_mode_per_repo_keys() {
        // In App mode the served repos come from the installation, so per-repo keys
        // for repos not (or no longer) installed are kept and ignored, not rejected.
        let mut c = Config::default();
        c.warm.insert("gone/repo".into(), 1);
        c.cache_branches.insert("gone/repo".into(), vec!["dev".into()]);
        c.repo_cache_gb.insert("gone/repo".into(), 60);
        assert!(c.validate_for(8).is_ok());
        // shape is still checked
        c.cache_branches.insert("gone/repo".into(), vec!["bad branch".into()]);
        assert!(c.validate_for(8).is_err());
    }

    #[test]
    fn app_accounts_are_github_logins() {
        let ok =
            |a: &[&str]| Config { app_accounts: a.iter().map(|s| s.to_string()).collect(), ..Config::default() }.validate_for(8).is_ok();
        assert!(ok(&[]));
        assert!(ok(&["Bunty9", "my-org", &"a".repeat(39)]));
        assert!(!ok(&[""]));
        assert!(!ok(&["-org"]));
        assert!(!ok(&["org-"]));
        assert!(!ok(&["my--org"]));
        assert!(!ok(&["my_org"]));
        assert!(!ok(&["o/rg"]));
        assert!(!ok(&[&"a".repeat(40)]));
    }

    #[test]
    fn size_labels_and_memory() {
        let c = Config::default();
        assert_eq!(c.runner_labels(4), ["self-hosted", "linux", "x64", "kiln-4cpu", "kiln"]);
        assert_eq!(c.runner_labels(8), ["self-hosted", "linux", "x64", "kiln-8cpu"]);
        assert_eq!((c.mem_mb(4), c.mem_mb(2), c.mem_mb(16)), (8192, 4096, 24576));
        let c = Config { size_mem_mb: [(8, 12288), (4, 1024)].into(), ..Config::default() };
        // overrides apply to non-default sizes only; the default size is vm_mem_mb
        assert_eq!((c.mem_mb(8), c.mem_mb(4), c.mem_mb(2)), (12288, 8192, 4096));
        let mut c = Config { cache_gb: 30, ..Config::default() };
        c.repo_cache_gb.insert("Owner/Repo".into(), 80);
        assert_eq!((c.cache_gb_for("owner/repo"), c.cache_gb_for("other/repo")), (80, 30));
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
    fn app_refresh_cadence() {
        assert_eq!(app_refresh_secs(0, false), 30, "never discovered");
        assert_eq!(app_refresh_secs(3, false), 30, "only an old map, never a successful discovery");
        assert_eq!(app_refresh_secs(0, true), 30, "installed nowhere yet: pick up a new install quickly");
        assert_eq!(app_refresh_secs(3, true), 300);
    }

    #[test]
    fn github_wide_backoff() {
        assert_eq!([1, 2, 3, 4, 9].map(api_backoff_secs), [60, 120, 300, 600, 600]);
        let mut b = ApiBackoff::default();
        assert!(!b.held(0) && b.banner(0).is_none());
        // First failure: pause 1 min, and say so once.
        assert!(b.fail(Some(500), 1000));
        assert!(b.held(1059) && !b.held(1060));
        // A sibling launch of the same batch failing inside the pause neither escalates nor logs again.
        assert!(!b.fail(Some(500), 1001));
        assert_eq!((b.fails, b.retry_at), (1, 1060));
        assert_eq!(
            b.banner(1000).as_deref(),
            Some("GitHub is rejecting runner registration (HTTP 500) — launches paused, retrying in 1 min")
        );
        // Each retry that fails again escalates: 2, 5, then 10 min, capped.
        assert!(b.fail(Some(502), 1060));
        assert_eq!(b.retry_at, 1180);
        assert!(b.fail(Some(500), 1180) && b.fail(None, 1480) && b.fail(None, 2080));
        assert_eq!((b.fails, b.retry_at), (5, 2680));
        assert_eq!(b.banner(2081).as_deref(), Some("GitHub is unreachable for runner registration — launches paused, retrying in 10 min"));
        // Pause over, no new launch yet: still not healthy, but not paused either.
        assert_eq!(b.banner(2680).as_deref(), Some("GitHub is unreachable for runner registration — retrying with the next launch"));
        // The first successful mint clears it.
        b = ApiBackoff::default();
        assert!(!b.held(2680) && b.banner(2680).is_none());
    }

    #[test]
    fn github_wide_backoff_probes_one_launch_at_a_time() {
        let mut b = ApiBackoff::default();
        // Healthy: launch everything wanted.
        assert_eq!(b.allow(0, 5, false), 5);
        b.fail(Some(500), 1000);
        // Paused: nothing.
        assert_eq!(b.allow(1059, 5, false), 0);
        // Pause over: one probe, and none while a probe is still minting.
        assert_eq!(b.allow(1060, 5, false), 1);
        assert_eq!(b.allow(1060, 0, false), 0);
        assert_eq!(b.allow(1060, 5, true), 0);
    }

    #[test]
    fn poll_pacing() {
        assert_eq!(poll_sleep(5, None), 5);
        assert_eq!(poll_sleep(5, Some((1000, 5000, 0))), 5);
        assert_eq!(poll_sleep(5, Some((999, 5000, 0))), 30);
        assert_eq!(poll_sleep(1, Some((5000, 5000, 0))), 3);
    }
}
