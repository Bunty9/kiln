mod app_auth;
mod audit;
mod boot;
mod cli;
mod confine;
mod forge;
#[cfg(test)]
mod forge_test_mock;
mod github;
mod history;
mod host;
mod mirror;
#[cfg(test)]
mod mixed_tests;
mod notify;
mod platform;
mod resil;
mod telemetry;
mod update;
mod vm;
mod web;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    /// Most VMs of one repo at once (0 = unlimited). `repo_max_vms` overrides it per repo.
    pub max_vms_per_repo: usize,
    /// "owner/name" -> `max_vms_per_repo` for that repo (0 = unlimited).
    pub repo_max_vms: BTreeMap<String, usize>,
    /// Hold launches while CPU / IO pressure (PSI `some avg10`, percent) is above this and a job VM runs. 0 = off.
    pub psi_hold_cpu: u32,
    pub psi_hold_io: u32,
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
    /// Which finished jobs notify which destinations (see notify.rs).
    pub notify_rules: Vec<notify::Rule>,
    /// GitHub App mode: accounts (user or org logins) whose installations are served,
    /// besides the App owner's. Empty = the owner's only.
    pub app_accounts: Vec<String>,
    /// Docker Hub pull-through cache for job VMs (host loopback :5000).
    pub docker_mirror: bool,
    /// Rebake by itself when the image is stale.
    pub auto_rebake: bool,
    /// Force-cancel the GitHub run whose job kiln lost (a crash, a restart, a timeout kill) so it does not hang.
    pub reclaim_lost_jobs: bool,
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
    /// Opt-in daily usage report (see telemetry.rs). None = not asked yet: the dashboard asks.
    pub usage_stats: Option<bool>,
    /// Opt-in crash reports (no panic message; see telemetry.rs). None = not asked yet.
    pub crash_reports: Option<bool>,
    /// SIGTERM (`systemctl restart`/`stop`): seconds running jobs get to finish before
    /// their VMs are killed. Must fit the unit's TimeoutStopSec, with ~30 s to spare.
    pub stop_grace_secs: u64,
    /// Extra forges (GitLab, Gitea) and their repos. Absent = GitHub only, from `repos`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forges: Option<Vec<forge::ForgeCfg>>,
    /// Top-level keys this version does not know (a newer kiln's, e.g. `forges`). Kept on load
    /// and written back on save, so a rollback followed by a settings save does not drop them.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7878".into(),
            repos: vec![],
            label: "kiln".into(),
            max_vms: 2,
            max_vms_per_repo: 0,
            repo_max_vms: BTreeMap::new(),
            psi_hold_cpu: 0,
            psi_hold_io: 0,
            vm_cpus: 4,
            vm_mem_mb: 8192,
            vm_disk_gb: 40,
            size_mem_mb: BTreeMap::new(),
            poll_secs: 5,
            job_timeout_mins: 60,
            idle_timeout_mins: 10,
            allowed_users: vec![],
            notify_rules: vec![],
            app_accounts: vec![],
            docker_mirror: true,
            auto_rebake: true,
            reclaim_lost_jobs: true,
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
            usage_stats: None,
            crash_reports: None,
            stop_grace_secs: 25,
            forges: None,
            extra: Default::default(),
        }
    }
}

impl Config {
    /// A VM of `cpus` serves `<label>-<cpus>cpu`, and the plain label only if it is the default size.
    /// On an arm64 host the label is `<label>-arm64`, so x64 jobs never land on it.
    pub fn runner_labels(&self, cpus: u32) -> Vec<String> {
        self.labels_for(cpus, platform::ARM64)
    }

    fn labels_for(&self, cpus: u32, arm64: bool) -> Vec<String> {
        let label = crate::forge::arch_label(&self.label, arm64);
        let arch = if arm64 { "ARM64" } else { "x64" };
        let mut l = vec!["self-hosted".into(), "linux".into(), arch.into(), format!("{label}-{cpus}cpu")];
        if cpus == self.vm_cpus {
            l.push(label);
        }
        l
    }

    /// What jobs put in `runs-on` for this host's default size: `<label>`, or `<label>-arm64`.
    pub fn job_label(&self) -> String {
        crate::forge::arch_label(&self.label, platform::ARM64)
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

    /// Most VMs `repo` may have at once: its `repo_max_vms` entry, else `max_vms_per_repo`; None = unlimited.
    pub fn repo_cap(&self, repo: &str) -> Option<usize> {
        let n = self.repo_max_vms.iter().find(|(r, _)| r.eq_ignore_ascii_case(repo)).map_or(self.max_vms_per_repo, |(_, &n)| n);
        (n > 0).then_some(n)
    }

    pub fn mem_mb(&self, cpus: u32) -> u32 {
        if cpus == self.vm_cpus { self.vm_mem_mb } else { self.size_mem_mb.get(&cpus).copied().unwrap_or_else(|| forge::size_mem_mb(cpus)) }
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
        forge::validate(&self.forges, &self.repos)?;
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
        if self.psi_hold_cpu > 100 || self.psi_hold_io > 100 {
            bail!("psi_hold_cpu and psi_hold_io must be 0..=100 (0 = off)");
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
        if self.notify_rules.len() > 50 {
            bail!("notify_rules: at most 50");
        }
        let wf_ok = |w: &str, pipeline: bool| {
            w == "*"
                || (w.len() <= 100
                    && (pipeline || w.ends_with(".yml") || w.ends_with(".yaml"))
                    && w.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
        };
        for r in &self.notify_rules {
            // Membership in the served repos is checked in web::set_config (App mode learns them at runtime).
            let other = forge::RepoRef::parse(&r.repo).ok().filter(|rr| rr.forge.as_str() != "github");
            if r.repo != "*" && !valid_repo(&r.repo) && other.is_none() {
                bail!("notify_rules: repo must be \"*\" or look like owner/name (forge-id:path on another forge): {:?}", r.repo);
            }
            // A GitLab repo has no workflow file: its rule names the pipeline.
            let gitlab = other.is_some_and(|rr| self.forges.iter().flatten().any(|f| f.id == rr.forge && f.kind == forge::Kind::GitLab));
            if !wf_ok(&r.workflow, gitlab) {
                bail!(
                    "notify_rules: workflow must be \"*\" or a file name like release.yml (a pipeline name for GitLab): {:?}",
                    r.workflow
                );
            }
            if !["success", "failure", "any"].contains(&r.outcome.as_str()) {
                bail!("notify_rules: outcome must be success, failure or any");
            }
            if r.to.is_empty() || r.to.len() > 20 || !r.to.iter().all(|t| t.len() == 8 && t.bytes().all(|b| b.is_ascii_hexdigit())) {
                bail!("notify_rules: each rule needs 1 to 20 destinations");
            }
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
        if self.stop_grace_secs > 570 {
            bail!("stop_grace_secs must be 0..=570 (kiln.service's TimeoutStopSec=600 minus ~30 s of cleanup)");
        }
        if !["open", "filtered"].contains(&self.egress.as_str()) {
            bail!("egress must be \"open\" or \"filtered\"");
        }
        if self.egress == "filtered" && platform::MACOS {
            bail!("{}", vm::FILTERED_LINUX_ONLY);
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
    /// What `blocked` is: "draining", "old_image", "github_api", "egress", "memory", "load", "disk", "budget" or "held".
    pub blocked_kind: Option<String>,
    /// repo -> queued fork pull request jobs kiln refuses to run.
    pub refused_forks: HashMap<String, usize>,
    /// Repos with a fork job queued (Gitea runners take the oldest job). Informational: launches go on.
    pub fork_queued: Vec<String>,
    /// Every launch blocker active this tick, (kind, message), in priority order.
    pub health: Vec<(String, String)>,
    /// Queued jobs that got no VM this tick, per repo and size, with why. Normal busyness (`slots_full`) is not in `blocked`.
    pub waiting: Vec<Waiting>,
}

/// Queued jobs of one repo and VM size that could not get a VM this tick.
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct Waiting {
    pub repo: String,
    pub jobs: usize,
    pub cpus: u32,
    /// `repo_backoff`, `host_hold`, `old_image`, `launch_gate`, `egress`, `draining`, `github_api`, `repo_cap`, `slots_full`, `held` or `budget`.
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Journal lines for what changed between two ticks' waiting lists, per repo: a new or changed reason, or none left.
fn waiting_changes(old: &[Waiting], new: &[Waiting]) -> Vec<String> {
    let reasons =
        |w: &[Waiting]| -> std::collections::BTreeMap<String, &'static str> { w.iter().map(|w| (w.repo.clone(), w.reason)).collect() };
    let (o, n) = (reasons(old), reasons(new));
    let mut out = vec![];
    for (repo, why) in &n {
        if o.get(repo) != Some(why) {
            let w = new.iter().find(|w| &w.repo == repo && w.reason == *why).unwrap();
            let d = w.detail.as_deref().map(|d| format!(": {d}")).unwrap_or_default();
            out.push(format!("{repo}: queued jobs are waiting ({why}){d}"));
        }
    }
    out.extend(o.keys().filter(|r| !n.contains_key(*r)).map(|r| format!("{r}: no queued jobs are waiting any more")));
    out
}

/// Why `jobs` queued jobs got no VM: the first gate that holds, in the order the launch gates run.
#[derive(Default)]
struct WaitCtx {
    backed_off: bool,
    host_hold: bool,
    old_image: bool,
    gate: Option<String>,
    egress: Option<String>,
    draining: bool,
    api_cut: bool,
    repo_cap: Option<usize>,
    slots_full: bool,
    holds: usize,
    max_vms: usize,
    budget: Option<String>,
}

impl WaitCtx {
    fn reason(self) -> (&'static str, Option<String>) {
        if self.backed_off {
            ("repo_backoff", Some("the repo's launches failed and are retried after a pause".into()))
        } else if self.host_hold {
            ("host_hold", Some("memory, cpu or io pressure, or the io_uring limit, holds launches".into()))
        } else if self.old_image {
            ("old_image", Some("rebake the base image".into()))
        } else if self.gate.is_some() {
            ("launch_gate", self.gate)
        } else if self.egress.is_some() {
            ("egress", self.egress)
        } else if self.draining {
            ("draining", None)
        } else if self.api_cut {
            ("github_api", Some("the forge is rejecting runner registration".into()))
        } else if let Some(n) = self.repo_cap {
            ("repo_cap", Some(format!("the repo already has its limit of {n} VMs")))
        } else if self.slots_full && self.holds > 0 {
            ("held", Some(format!("{} of {} slots held for debugging", self.holds, self.max_vms)))
        } else if self.slots_full {
            ("slots_full", Some(if self.max_vms == 0 { "paused (max_vms = 0)".into() } else { format!("all {} slots busy", self.max_vms) }))
        } else {
            ("budget", self.budget)
        }
    }
}

/// How a forge is named in messages: "GitHub", else its id.
fn forge_name(id: &forge::ForgeId) -> String {
    if id.as_str() == "github" { "GitHub".into() } else { id.as_str().into() }
}

/// The `PollStatus.blocked_kind` of a forge's registration backoff.
fn api_kind(id: &forge::ForgeId) -> &'static str {
    if id.as_str() == "github" { "github_api" } else { "forge_api" }
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
    /// `who` names the forge ("GitHub" for GitHub, else its id).
    pub fn banner(&self, t: u64, who: &str) -> Option<String> {
        if self.fails == 0 {
            return None;
        }
        let what = match self.status {
            Some(s) => format!("{who} is rejecting runner registration (HTTP {s})"),
            None => format!("{who} is unreachable for runner registration"),
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
    pub gh: Arc<github::Gh>,
    pub forges: forge::Forges,
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
    /// (consecutive launches that found the io_uring locked-memory limit exhausted, retry_at): holds every launch.
    pub io_uring: Mutex<(u32, u64)>,
    /// Per forge: registration failures that hold every launch on it.
    pub api_backoff: Mutex<HashMap<forge::ForgeId, ApiBackoff>>,
    pub mirror: Mutex<mirror::Status>,
    /// One-time states of GitHub App manifest flows in progress.
    pub app_states: Mutex<app_auth::States>,
    /// An update, restart or stop is draining: launch nothing (warm included), reap idle VMs.
    pub draining: AtomicBool,
    pub update: Mutex<update::Status>,
    /// Outbound webhook notifications (destinations, queues, delivery status).
    pub notify: notify::Hub,
    /// Background problems nobody is waiting on (a cache that will not save, a cleanup that keeps failing), by what
    /// raised them: the tick adds them to the health list. Cleared by whoever raised them when it works again.
    pub notices: Mutex<std::collections::BTreeMap<String, (&'static str, String)>>,
    /// The `qemu-img` binary; tests point it at a script or at nothing.
    pub qemu_img: PathBuf,
    /// Fixed machine readings for tests: a tick gates launches on them, and a loaded or small box must not change a result.
    pub host_fixed: Option<HostReadings>,
}

/// What a tick reads from the machine.
#[derive(Clone, Copy)]
pub struct HostReadings {
    pub mem_total_mb: u64,
    pub mem_avail_mb: u64,
    pub disk_free_gb: Option<u64>,
    pub threads: u32,
    /// PSI `some avg10` of memory, in percent (Linux with PSI).
    pub mem_psi: Option<f64>,
    /// PSI `some avg10` of CPU and IO, in percent.
    pub cpu_psi: Option<f64>,
    pub io_psi: Option<f64>,
}

impl HostReadings {
    /// A roomy, fixed host for tests: 8 threads, 64 GB of memory, 500 GB of disk.
    #[cfg(test)]
    pub const TEST: HostReadings = HostReadings {
        mem_total_mb: 65536,
        mem_avail_mb: 65536,
        disk_free_gb: Some(500),
        threads: 8,
        mem_psi: None,
        cpu_psi: None,
        io_psi: None,
    };
}

impl App {
    /// An App on a unique temp data dir (parallel tests each get their own).
    #[cfg(test)]
    pub fn for_tests() -> Arc<App> {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("kiln-test-app-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // A default config must validate on a small host (a 3-core CI Mac) too.
        let cfg = Config { vm_cpus: host_threads().min(4), ..Config::default() };
        let mut app = App::new(d, cfg, github::Gh::new(String::new(), "none"));
        (app.qemu_img, app.host_fixed) = ("/nonexistent/qemu-img".into(), Some(HostReadings::TEST));
        Arc::new(app)
    }

    fn new(data: PathBuf, cfg: Config, gh: github::Gh) -> Self {
        let gh = Arc::new(gh);
        let forges = forge::Forges::default();
        forges.sync(&forge::effective(&cfg.forges, &cfg.repos), &gh, &data);
        forges.load_tokens(&data);
        App {
            gh,
            forges,
            cfg: RwLock::new(cfg),
            vms: Mutex::default(),
            kills: Mutex::default(),
            releases: Mutex::default(),
            committing: Mutex::default(),
            poll: Mutex::default(),
            baking: Default::default(),
            stopping: Default::default(),
            backoff: Default::default(),
            io_uring: Default::default(),
            api_backoff: Default::default(),
            mirror: Default::default(),
            app_states: Mutex::new(app_auth::States::open(data.join("app_states.json"))),
            draining: Default::default(),
            update: Mutex::new(update::Status::load(&data)),
            notify: Default::default(),
            notices: Mutex::default(),
            qemu_img: "qemu-img".into(),
            host_fixed: None,
            data,
        }
    }

    pub fn notice(&self, key: &str, kind: &'static str, msg: impl Into<String>) {
        self.notices.lock().unwrap().insert(key.into(), (kind, msg.into()));
    }

    pub fn clear_notice(&self, key: &str) {
        self.notices.lock().unwrap().remove(key);
    }

    /// The machine's memory, disk and thread count now (or the fixed readings of a test).
    async fn host_readings(&self) -> HostReadings {
        match self.host_fixed {
            Some(h) => h,
            None => HostReadings {
                mem_total_mb: platform::mem_total_mb(),
                mem_avail_mb: platform::mem_avail_mb(),
                disk_free_gb: vm::disk_free_gb(&self.data).await,
                threads: host_threads(),
                mem_psi: resil::memory_psi(),
                cpu_psi: resil::psi("cpu"),
                io_psi: resil::psi("io"),
            },
        }
    }

    pub fn cfg(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    pub fn save_cfg(&self, c: Config) -> Result<()> {
        c.validate()?;
        *self.gh.app_accounts.write().unwrap() = c.app_accounts.clone();
        self.forges.sync(&forge::effective(&c.forges, &c.repos), &self.gh, &self.data);
        self.forges.load_tokens(&self.data);
        let mut w = self.cfg.write().unwrap();
        let (tmp, path) = (self.data.join("config.json.tmp"), self.data.join("config.json"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(&c)?)?;
        std::fs::rename(&tmp, &path)?;
        telemetry::apply(&self.data, &c);
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

    /// Every repo kiln serves, GitHub's and each other forge's (`id:path`).
    pub fn all_repos(&self) -> Vec<String> {
        let other = self.cfg().forges.unwrap_or_default().into_iter().filter(|f| f.kind != forge::Kind::GitHub);
        self.repos().into_iter().chain(other.flat_map(|f| f.repos.into_iter().map(move |r| format!("{}:{r}", f.id.as_str())))).collect()
    }

    pub fn save_token(&self, t: String) -> Result<()> {
        app_auth::write_private(&self.data.join("token"), t.trim().as_bytes())?;
        self.gh.set_token(t.trim().to_string(), "file");
        Ok(())
    }
}

pub fn host_threads() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// GitHub tokens the environment may hold. kiln reads the first two itself; `GH_TOKEN` reaches
/// it only through `gh auth token`, last. Children kiln starts for VMs inherit none of them
/// (see `vm::no_secrets`).
pub const TOKEN_ENV: [&str; 3] = ["KILN_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"];

/// Env var, then the token file the dashboard writes, then the gh CLI login.
/// `only_file`: a token was saved from the dashboard, so only that file counts
/// (a stale env token must not take over again on reload).
fn load_token(data: &std::path::Path, only_file: bool) -> (String, &'static str) {
    let env = TOKEN_ENV[..2].iter().find_map(|k| std::env::var(k).ok().filter(|t| !t.is_empty()));
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

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    // Before any runtime thread exists: confines itself, then execs a job VM's QEMU.
    if args.next().is_some_and(|a| a == confine::ARG) {
        confine::main(args);
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V" | "version")) {
        println!("kiln {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    // Before logging, telemetry and the token: a CLI call only talks to the running kiln.
    if let Some(code) = cli::dispatch(&std::env::args().skip(1).collect::<Vec<_>>()) {
        std::process::exit(code);
    }
    tracing_subscriber::fmt().with_target(false).init();
    resil::lower_memlock();
    let data = std::env::var_os("KILN_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/kiln"));
    // Absolute: paths built from it go into Landlock rules and QEMU arguments.
    let data = std::path::absolute(&data)?;
    // First, before anything likely to fail (a bad config.json included), so a new version
    // that dies early still counts its boots and gets rolled back. CLI runs never count.
    if is_serve(std::env::args().nth(1).as_deref()) {
        update::on_start(&data);
    }
    std::fs::create_dir_all(data.join("vms"))?;
    std::fs::create_dir_all(data.join("images"))?;
    std::fs::create_dir_all(data.join("update"))?;
    // Job logs, repo caches and the key files all live here: other local users stay out,
    // whatever the umask was when it was created.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", data.display()))?;
    }
    let cfg = load_config(&data)?;
    telemetry::apply(&data, &cfg);
    telemetry::install_hook(&data);
    let (token, source) = load_token(&data, false);
    let gh = github::Gh::new(token, source);
    *gh.app_accounts.write().unwrap() = cfg.app_accounts.clone();
    match app_auth::load(&data) {
        Some(Ok(a)) => gh.set_app(Some(Arc::new(a))),
        Some(Err(e)) => tracing::error!("GitHub App configured but unusable, using token auth: {e:#}"),
        None => {}
    }
    let app = Arc::new(App::new(data, cfg, gh));

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
            // Before reap_scopes: a second serve must not kill the live one's VM scopes.
            lock_serve(&app.data)?;
            if let Some(p) = confine::exposed(&app.data) {
                bail!("data directory {} is under {p}, which job VMs' QEMU may read: move it (KILN_DATA) elsewhere", app.data.display());
            }
            // Only serve may touch leftovers: bake/doctor can run next to a live serve.
            // Job VMs run in scopes that outlive the service: none can belong to this start.
            resil::reap_scopes().await;
            *app.vms.lock().unwrap() = vm::load_history(&app.data);
            tokio::spawn(host::run(app.clone()));
            notify::start(&app);
            for v in vm::take_newly_lost() {
                notify::job_ended(&app, &v);
            }
            let (ok, d) = confine::probe();
            confine::ENFORCED.store(ok && !platform::MACOS, std::sync::atomic::Ordering::Relaxed);
            match ok {
                true if !d.starts_with("warning") => tracing::info!("{d}"),
                _ => tracing::warn!("job VM confinement: {d}"),
            }
            // Starts the grace period in which a missing network reads as "starting", not failed.
            let a = app.clone();
            boot::watch(move || vm::probe_host(&a.cfg()));
            if app.cfg().egress == "filtered" {
                let a = app.clone();
                tokio::spawn(async move {
                    // The scheduler's ticks retry it with backoff, so a failure here may be only "not yet".
                    if let Err(e) = vm::egress_ready(&a, true).await {
                        if boot::starting() {
                            tracing::info!("egress filtering not available yet, retrying: {e}");
                        } else {
                            tracing::error!("egress filtering unavailable: {e}");
                        }
                    }
                });
            }
            if std::env::var_os("INVOCATION_ID").is_some() {
                let t = unit_stop_timeout().await;
                let _ = UNIT_STOP_TIMEOUT.set(t);
                if let Some(p) = unit_timeout_problem(app.cfg().stop_grace_secs, t) {
                    tracing::warn!("{p}");
                }
            }
            let sched = tokio::spawn(scheduler(app.clone()));
            tokio::spawn(mirror::supervise(app.clone()));
            tokio::spawn(update::supervise(app.clone()));
            tokio::spawn(telemetry::supervise(app.clone()));
            // In its own task: the dashboard keeps serving while a stop drains.
            let web = tokio::spawn(web::serve(app.clone()));
            tokio::select! {
                r = web => r?,
                // It only returns when kiln stops; a panic would otherwise end all scheduling while the dashboard stays up.
                r = sched => {
                    // A stop or an update restart (`restart_into`) already shut down: the scheduler ending is
                    // expected, and that path finishes the exit or the re-exec.
                    if scheduler_fault(app.stopping.load(std::sync::atomic::Ordering::SeqCst), &r) {
                        let e = scheduler_ended(r);
                        tracing::error!("{e}");
                        // Shut down (no grace drain), then a non-zero exit: systemd restarts kiln, and its startup cleanup runs.
                        shutdown(&app).await;
                        Err(e)
                    } else {
                        std::future::pending::<Result<()>>().await
                    }
                }
                _ = stop_signal() => {
                    stop_drain(&app).await;
                    shutdown(&app).await;
                    Ok(())
                }
            }
        }
        _ => {
            eprintln!(
                "usage: kiln [serve|bake|doctor|status|jobs|logs|wait|rerun|--version]\n  serve      run scheduler + dashboard (default)\n  bake       build the base VM image\n  doctor     check host prerequisites\n  status     the running kiln's state (--json, --doctor)\n  jobs       recent jobs (--repo --pr --sha --branch --limit)\n  logs <vm>  a VM's log (--console --failed --follow)\n  wait <run-id|sha>  block until the run(s) finish; exit code says how\n  rerun <run-id>     rerun a run (--failed)\n  --version  print the version"
            );
            std::process::exit(2)
        }
    }
}

/// `<data>/config.json`, validated: a hand-edited typo must not fail open (an `egress` of
/// "Filtered" quietly meaning open). Only a missing file means the defaults, which the
/// dashboard's first save adjusts to the host; an unreadable one is an error, not "open".
fn load_config(data: &std::path::Path) -> Result<Config> {
    match std::fs::read(data.join("config.json")) {
        Ok(b) => {
            let c: Config = serde_json::from_slice(&b).context("config.json")?;
            // Host-size bounds are checked when saving: a box that later shows fewer CPUs
            // (affinity, cpuset, a move) must still start, and only launches what fits.
            c.validate_for(u32::MAX).context("config.json is invalid; fix it or remove it to start from the defaults")?;
            Ok(c)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).context("reading config.json"),
    }
}

/// Whether the scheduler task ending should end kiln: always for a panic, otherwise only when not stopping.
fn scheduler_fault(stopping: bool, r: &Result<(), tokio::task::JoinError>) -> bool {
    r.is_err() || !stopping
}

/// Takes an exclusive lock on `<data>/serve.lock` for the life of the process, so a second `kiln serve`
/// on the same data directory fails before it can touch the live one's VMs. The fd is close-on-exec:
/// an update re-exec releases the lock and the new image takes it again.
fn lock_serve(data: &std::path::Path) -> Result<()> {
    static HELD: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
    let f = try_lock(&data.join("serve.lock"))?;
    let _ = HELD.set(f);
    Ok(())
}

fn try_lock(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another kiln serve is running on this data directory ({})", path.display());
    }
    Ok(f)
}

/// Why the scheduler task ended while kiln was still serving.
fn scheduler_ended(r: Result<(), tokio::task::JoinError>) -> anyhow::Error {
    match r {
        Err(e) => anyhow::anyhow!("the scheduler task died ({e}): exiting so the service restarts"),
        Ok(()) => anyhow::anyhow!("the scheduler task returned: exiting so the service restarts"),
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

/// VMs the stop drain waits for. Held VMs are not (they keep a finished job for
/// debugging); waiting ones are reaped by the draining scheduler meanwhile.
pub fn stop_waits_for(s: vm::State) -> bool {
    s.is_active() && s != vm::State::Held
}

/// kiln.service's TimeoutStopSec in seconds, read at startup when systemd runs kiln.
static UNIT_STOP_TIMEOUT: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
/// What kiln needs after the stop grace: kill VMs, deregister runners, exit.
const STOP_CLEANUP_SECS: u64 = 25;

/// The stop grace that still leaves cleanup time before systemd SIGKILLs kiln.
fn clamp_grace(grace: u64, unit_timeout: Option<u64>) -> u64 {
    unit_timeout.map_or(grace, |t| grace.min(t.saturating_sub(STOP_CLEANUP_SECS)))
}

/// A systemd timespan ("30s", "1min 30s", "infinity") in whole seconds.
fn parse_timespan(s: &str) -> Option<u64> {
    if s == "infinity" {
        return Some(u64::MAX);
    }
    let mut us: u64 = 0;
    for part in s.split_whitespace() {
        let i = part.find(|c: char| !c.is_ascii_digit())?;
        let n: u64 = part[..i].parse().ok()?;
        let unit = match &part[i..] {
            "us" => 1,
            "ms" => 1_000,
            "s" => 1_000_000,
            "min" => 60_000_000,
            "h" => 3_600_000_000,
            "d" => 86_400_000_000,
            "w" => 604_800_000_000,
            _ => return None,
        };
        us = us.checked_add(n.checked_mul(unit)?)?;
    }
    (!s.trim().is_empty()).then_some(us / 1_000_000)
}

/// TimeoutStopUSec from `systemctl show -p LoadState -p TimeoutStopUSec`, if the unit exists.
fn unit_timeout(show: &str) -> Option<u64> {
    let prop = |k: &str| show.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('='));
    prop("LoadState").filter(|s| *s == "loaded")?;
    parse_timespan(prop("TimeoutStopUSec")?)
}

/// kiln.service's (user unit) stop timeout in seconds; None without systemd or the unit.
pub async fn unit_stop_timeout() -> Option<u64> {
    let args = ["--user", "show", "-p", "LoadState", "-p", "TimeoutStopUSec", "kiln"];
    let o = web::bounded("systemctl", &args, Duration::from_secs(5)).await.ok().filter(|o| o.status.success())?;
    unit_timeout(&String::from_utf8_lossy(&o.stdout))
}

/// Doctor and startup: a unit timeout too short for `grace` (an old 30 s unit).
pub fn unit_timeout_problem(grace: u64, unit_timeout: Option<u64>) -> Option<String> {
    let t = unit_timeout?;
    (clamp_grace(grace, Some(t)) < grace).then(|| {
        format!(
            "kiln.service TimeoutStopSec={t}s is shorter than stop_grace_secs ({grace} s) + {STOP_CLEANUP_SECS} s cleanup, so stops wait only {} s: reinstall the unit (see docs/configuration.md)",
            clamp_grace(grace, Some(t))
        )
    })
}

/// After the first SIGTERM/SIGINT: launch nothing (idle VMs are reaped) and give running
/// jobs up to `stop_grace_secs` to finish. A second signal ends the wait.
async fn stop_drain(app: &Arc<App>) {
    update::stopping(app);
    app.draining.store(true, Ordering::SeqCst);
    let grace = clamp_grace(app.cfg().stop_grace_secs, UNIT_STOP_TIMEOUT.get().copied().flatten());
    let deadline = now() + grace;
    let again = stop_signal();
    tokio::pin!(again);
    let mut logged = 0;
    loop {
        let running = app.vms.lock().unwrap().iter().filter(|v| stop_waits_for(v.state)).count();
        if running == 0 || now() >= deadline {
            if running > 0 {
                tracing::warn!("stop grace ({grace} s) is over: killing {running} running VM(s)");
            }
            return;
        }
        let p = format!("waiting for {running} running VM{} (at most {} s more)", if running == 1 { "" } else { "s" }, deadline - now());
        if now() >= logged + 5 {
            logged = now();
            tracing::info!("stopping: {p}; signal again to stop now");
        }
        update::stop_progress(app, p);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = &mut again => {
                tracing::warn!("second stop signal: killing {running} running VM(s) now");
                return;
            }
        }
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
    notify::flush(app).await;
}

/// Seconds between App discoveries: 30 while it serves no repo or has never discovered
/// successfully (so a fresh install shows up quickly), else 5 minutes.
/// After `fails` failed discoveries in a row (GitHub or the network down) it is retried quickly,
/// 5 s growing to a minute, so a box that booted before its network is serving within seconds of it.
fn app_refresh_secs(repos: usize, ever_ok: bool, fails: u32) -> u64 {
    if fails > 0 {
        boot::retry_secs(fails, 60)
    } else if repos == 0 || !ever_ok {
        30
    } else {
        300
    }
}

/// App mode: refresh which repos the App is installed on (see `app_refresh_secs`).
/// A failure keeps the previous list (a GitHub hiccup must not unschedule every repo).
async fn refresh_app(app: &Arc<App>) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static FAILS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let Some(a) = app.gh.app() else { return };
    let every =
        app_refresh_secs(a.names.read().unwrap().len(), a.discovered_at.load(Ordering::Relaxed) != 0, FAILS.load(Ordering::Relaxed));
    if now() < LAST.load(Ordering::Relaxed) + every {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    match app.gh.discover_now().await {
        Ok(n) => {
            FAILS.store(0, Ordering::Relaxed);
            tracing::info!("GitHub App: {n} repo(s) installed");
            // Per-installation failures and ignored installations.
            if let Some(e) = a.error.lock().unwrap().clone() {
                tracing::warn!("GitHub App discovery: {e}");
            }
        }
        Err(e) if boot::waiting_for_network() => {
            FAILS.fetch_add(1, Ordering::Relaxed);
            tracing::info!("GitHub App discovery waits for the network: {e:#}");
        }
        Err(e) => {
            FAILS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("GitHub App discovery: {e:#}");
        }
    }
}

const SWEEP_EVERY: u64 = 3600;

/// The hourly sweep; `fails` counts the consecutive failed hours. True when no sweep failed.
async fn sweep_runners(app: &App, gated_only: bool, fails: u32) -> bool {
    sweep_pending(app, gated_only, &mut Default::default(), fails).await
}

/// Sweeps the repos not in `done` yet and adds each that worked, so a repo whose sweep failed
/// (no network yet) or that was not known yet (an App not discovered yet) is tried again.
/// True when no sweep failed. `fails`: how many rounds failed before this one; a retry's failures are not
/// worth a warning each time (every tenth is), but a sweep that keeps failing becomes a health item.
async fn sweep_pending(app: &App, gated_only: bool, done: &mut std::collections::HashSet<String>, fails: u32) -> bool {
    let quiet = !fails.is_multiple_of(10);
    let cfg = app.cfg();
    let cfgs = forge::effective(&cfg.forges, &cfg.repos);
    let mut ok = true;
    for f in app.forges.all().iter().filter(|f| f.has_credential() && (f.gated() || !gated_only)) {
        for rr in cfgs.iter().find(|c| c.id == f.id()).map(|c| f.repos(c)).unwrap_or_default() {
            let repo = rr.key();
            if done.contains(&repo) {
                continue;
            }
            // Looked up per repo: a VM launched since the last one has its runner registered, offline while it boots.
            let keep = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).map(|v| v.id.clone()).collect();
            match f.sweep(&rr, &keep).await {
                Ok(n) => {
                    done.insert(repo.clone());
                    app.clear_notice(&format!("sweep:{repo}"));
                    if n > 0 {
                        tracing::info!("{repo}: removed {n} stale runner(s)");
                    }
                }
                Err(e) => {
                    ok = false;
                    note_cleanup_failure(
                        app,
                        &format!("sweep:{repo}"),
                        &format!("runner cleanup of {repo}"),
                        fails,
                        &format!("{e:#}"),
                        boot::starting(),
                    );
                    if boot::waiting_for_network() {
                        tracing::info!("{repo}: runner sweep waits for the network: {e:#}");
                    } else if quiet {
                        tracing::debug!("{repo}: runner sweep: {e:#}");
                    } else {
                        tracing::warn!("{repo}: runner sweep: {e:#}");
                    }
                }
            }
        }
    }
    ok
}

/// A cleanup step that failed `fails + 1` rounds in a row, outside the boot grace, is a health item (cleared when it works).
fn note_cleanup_failure(app: &App, key: &str, what: &str, fails: u32, why: &str, starting: bool) {
    if fails >= 2 && !starting {
        // The cause stays in kiln's log: a health item goes to webhook destinations, and forge errors carry URLs.
        tracing::warn!("{what}: {why}");
        app.notice(key, "cleanup", format!("{what} keeps failing ({} attempts); see kiln's log", fails + 1));
    }
}

/// Seconds before the n-th retry of a failed startup cleanup.
fn cleanup_retry_secs(fails: u32) -> u64 {
    boot::retry_secs(fails, 300)
}

/// What kiln must do once after a start to clear the previous run's leftovers from the forges,
/// retried until it worked: the network or the GitHub App's repo list may not be there yet at boot.
#[derive(Default)]
struct Cleanup {
    /// The runners of VMs the last run lost are deleted.
    retired: bool,
    /// Repos whose orphaned runners were swept.
    swept: std::collections::HashSet<String>,
    fails: u32,
    next: u64,
}

impl Cleanup {
    async fn step(&mut self, app: &App) {
        if now() < self.next {
            return;
        }
        if !self.retired {
            self.retired = vm::retire_ended(app).await;
            if self.retired {
                app.clear_notice("retire");
            } else {
                note_cleanup_failure(
                    app,
                    "retire",
                    "deleting the runners of ended VMs",
                    self.fails,
                    "the forge refused or was unreachable",
                    boot::starting(),
                );
            }
        }
        let swept = sweep_pending(app, false, &mut self.swept, self.fails).await;
        if self.retired && swept {
            if self.fails > 0 {
                tracing::info!("startup cleanup of stale runners done after {} retries", self.fails);
            }
            (self.fails, self.next) = (0, 0);
        } else {
            self.fails += 1;
            self.next = now() + cleanup_retry_secs(self.fails);
        }
    }
}

async fn scheduler(app: Arc<App>) {
    refresh_app(&app).await;
    // Runners a crashed kiln or a reboot left registered (offline) would otherwise linger for a day: those of the
    // VMs it lost, a gated forge's ended VMs (never removed by the runner itself), then every repo's
    // orphans. Before the first tick, so nothing launched since is swept; retried while the network is not up.
    let mut cleanup = Cleanup::default();
    cleanup.step(&app).await;
    let (mut swept, mut sweep_fails) = (now(), 0u32);
    while !app.stopping.load(Ordering::SeqCst) {
        cleanup.step(&app).await;
        // GitLab and Gitea runners that a failed delete left behind; GitHub's JIT runners go by the startup sweep alone.
        if now() >= swept + SWEEP_EVERY {
            swept = now();
            sweep_fails = if sweep_runners(&app, true, sweep_fails).await { 0 } else { sweep_fails + 1 };
        }
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
                Err(e) if boot::waiting_for_network() => p.error = Some(boot::waiting_msg(&format!("{e:#}"))),
                Err(e) => p.error = Some(format!("{e:#}")),
            }
        }
        let (health, poll_error) = {
            let p = app.poll.lock().unwrap();
            (p.health.clone(), p.error.clone())
        };
        let load_error = app.notify.load_error.lock().unwrap().clone();
        let problems = health_list(
            &health,
            poll_error.as_deref(),
            confine::ENFORCED.load(Ordering::Relaxed),
            load_error.as_deref(),
            &notify::failing(&app),
        );
        notify::health(&app, problems, now());
        // The slowest-needing forge sets the pace for all (per-forge polling is a follow-up).
        let sleep =
            app.forges.all().iter().map(|f| poll_sleep(cfg.poll_secs, f.rate())).max().unwrap_or_else(|| poll_sleep(cfg.poll_secs, None));
        tokio::time::sleep(Duration::from_secs(sleep)).await;
    }
}

/// The notices grouped by kind, their messages joined (the health tracker holds one message per kind).
fn notice_kinds(n: &std::collections::BTreeMap<String, (&'static str, String)>) -> Vec<(&'static str, String)> {
    let mut by: Vec<(&'static str, Vec<&str>)> = vec![];
    for (kind, msg) in n.values() {
        match by.iter_mut().find(|(k, _)| k == kind) {
            Some((_, v)) => v.push(msg),
            None => by.push((kind, vec![msg])),
        }
    }
    by.into_iter().map(|(k, v)| (k, v.join("; "))).collect()
}

/// Everything the box health tracker sees this tick. A poll error adds to the tick's blockers
/// instead of replacing them. "draining" is left out: health state is in memory, so a restart
/// would orphan its raise with no clear. What only says "starting: ..." (the network is not up yet,
/// see `boot`) is no problem to alert on: if it lasts, the message turns into the real error.
fn health_list(
    health: &[(String, String)],
    poll_error: Option<&str>,
    landlock: bool,
    load_error: Option<&str>,
    failing: &[(String, String)],
) -> Vec<(String, String)> {
    let mut l: Vec<_> = health.iter().filter(|h| h.0 != "draining").cloned().collect();
    if let Some(e) = poll_error {
        l.push(("poll".into(), e.into()));
    }
    if !landlock {
        l.push(("landlock".into(), "job VMs' QEMU runs unconfined: this kernel has no Landlock".into()));
    }
    if let Some(e) = load_error {
        l.push(("notify_failing".into(), e.into()));
    }
    if !failing.is_empty() {
        let f = failing.iter().map(|f| f.1.as_str()).collect::<Vec<_>>().join("; ");
        l.push(("notify_failing".into(), format!("notifications failing: {f}")));
    }
    l.retain(|h| !h.1.starts_with("starting:"));
    l
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
    match tokio::task::spawn_blocking(move || load_token(&data, only_file)).await {
        Ok((t, src)) if !t.is_empty() => app.gh.set_token(t, src),
        Ok(_) => {}
        Err(e) => tracing::warn!("GitHub token reload: {e}"),
    }
}

const REBAKE_EVERY: u64 = 6 * 3600;

/// Not more than every 6h (a failing bake must not loop). Running VMs keep the
/// old base inode and the swap is atomic, so baking next to jobs is safe.
fn should_rebake(cfg: &Config, stale: bool, baking: bool, t: u64, last: u64) -> bool {
    cfg.auto_rebake && stale && !baking && t >= last + REBAKE_EVERY
}

/// The `last` that lets a bake that failed at `t` (the `fails`-th time in a row) be tried again in
/// 5 minutes, doubling up to the 6 h: one that failed because the network was not up yet (a boot
/// that finds the image stale) must not wait the whole 6 h.
fn rebake_last_after_failure(t: u64, fails: u32) -> u64 {
    (t + boot::retry_secs(fails, REBAKE_EVERY / 60) * 60).saturating_sub(REBAKE_EVERY)
}

fn auto_rebake(app: &Arc<App>, cfg: &Config) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static FAILS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let stale = vm::image_info(&app.data, app.gh.latest_cached(), cfg)["stale"] == true;
    // vm::bake would refuse: do not spend the 6 h slot on it.
    // Nor before the network is up at boot: it would only fail on the first download.
    let baking = app.baking.load(Ordering::SeqCst) || app.draining.load(Ordering::SeqCst) || boot::waiting_for_network();
    if !should_rebake(cfg, stale, baking, now(), LAST.load(Ordering::Relaxed)) {
        return;
    }
    LAST.store(now(), Ordering::Relaxed);
    tracing::info!("base image is stale: rebaking");
    let app = app.clone();
    tokio::spawn(async move {
        match vm::bake(app).await {
            Ok(()) => FAILS.store(0, Ordering::Relaxed),
            Err(e) => {
                let fails = FAILS.fetch_add(1, Ordering::Relaxed) + 1;
                LAST.store(rebake_last_after_failure(now(), fails), Ordering::Relaxed);
                tracing::error!("auto-rebake failed (trying again in {} min): {e:#}", boot::retry_secs(fails, REBAKE_EVERY / 60));
            }
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
    app.forges.reload_changed(&app.data);
    refresh_app(app).await;
    // A forge with no credential or rate-limited skips its repos; when none can poll the tick fails.
    let (live, down): (Vec<_>, Vec<_>) = app.forges.all().into_iter().partition(|f| f.health().is_none());
    if live.is_empty() && !down.is_empty() {
        bail!(down.iter().filter_map(|f| f.health()).collect::<Vec<_>>().join("; "));
    }
    if !vm::image_ready(&app.data) {
        bail!("base image not baked yet: run `kiln bake` or use the dashboard");
    }
    for f in &live {
        f.refresh().await;
    }
    // Launching during a bake is fine: new VMs use the old base until the atomic swap.
    auto_rebake(app, cfg);
    let host = app.host_readings().await;
    let (mem_avail, disk) = (host.mem_avail_mb, host.disk_free_gb);
    // Shown on the dashboard; each size is gated on its own memory below.
    let mirror_mb = cfg.docker_mirror.then(|| mirror::cache_mb(app)).flatten();
    let cache_mb = Some(vm::cache_dir_mb(&app.data)).filter(|&m| m > 0);
    // Fail closed: filtered jobs never fall back to open networking.
    let egress_err = if cfg.egress == "filtered" { vm::egress_ready(app, false).await.err() } else { None };
    // An image from an older recipe may lack the job hooks (fork refusal, cold release builds): launch nothing, warm included.
    let old_image = !vm::image_recipe_ok(&vm::image_info(&app.data, None, cfg));
    let draining = app.draining.load(Ordering::SeqCst);
    let apis = app.api_backoff.lock().unwrap().clone();
    // A launch still minting is the probe of its forge's backoff step.
    let mut probing: std::collections::HashSet<forge::ForgeId> = {
        let vms = app.vms.lock().unwrap();
        vms.iter()
            .filter(|v| v.state == vm::State::Booting && v.runner_id.is_none())
            .map(|v| forge::RepoRef::parse(&v.repo).map_or_else(|_| forge::ForgeId::github(), |r| r.forge))
            .filter(|id| apis.get(id).is_some_and(|a| a.fails > 0))
            .collect()
    };
    let mut any_queued = false;
    let gated = |g: Option<String>| g.map(|m| (gate_kind(&m), m));
    let mut problems: Vec<(&str, String)> = vec![];
    if draining {
        problems.push(("draining", "draining: running jobs finish, then kiln restarts or stops".to_string()));
    }
    if old_image {
        problems.push(("old_image", "base image predates kiln's current job hooks: rebake (Settings › Image)".to_string()));
    }
    for f in &down {
        problems.push(("forge", format!("{}: {}", forge_name(&f.id()), f.health().unwrap_or_default())));
    }
    let cfgs = forge::effective(&cfg.forges, &cfg.repos);
    for c in cfgs.iter().filter(|c| app.forges.get(&c.id).is_none()) {
        problems.push(("forge", format!("forge {}: {:?} could not be set up (check its url)", c.id.as_str(), c.kind)));
    }
    let mut ids: Vec<_> = apis.keys().collect();
    ids.sort_by_key(|id| id.as_str());
    for id in ids {
        if let Some(m) = apis[id].banner(now(), &forge_name(id)).filter(|_| apis[id].held(now())) {
            problems.push((api_kind(id), m));
        }
    }
    if let Some(e) = egress_err.as_ref() {
        // Retried with backoff: during the first minutes it is "starting", which raises no alert.
        problems.push((
            "egress",
            if boot::starting() { boot::waiting_for("filtered egress", e) } else { format!("egress filtering unavailable: {e}") },
        ));
    }
    if let Some(g) = gated(vm::launch_gate(mem_avail, cfg.vm_mem_mb, disk, mirror_mb, cache_mb)) {
        problems.push(g);
    }
    // Memory stalls (PSI) and an exhausted io_uring limit hold launches host-wide, however much memory is free.
    let mem_hold = resil::pressure_gate("memory", host.mem_psi, resil::PSI_HOLD_PCT);
    if let Some(m) = mem_hold.clone() {
        problems.push(("memory", m));
    }
    // CPU/IO holds limit overlap, so they apply only while a job VM runs (a busy desktop can't hold kiln at zero VMs).
    let running = app.vms.lock().unwrap().iter().filter(|v| v.state == vm::State::Busy).count();
    let load_hold = [("cpu", host.cpu_psi, cfg.psi_hold_cpu), ("io", host.io_psi, cfg.psi_hold_io)]
        .into_iter()
        .find_map(|(res, p, limit)| resil::load_gate(res, p, limit, running));
    if let Some(m) = load_hold.clone() {
        problems.push(("load", m));
    }
    let (uring_fails, uring_at) = *app.io_uring.lock().unwrap();
    if uring_fails > 0 && uring_at > now() {
        problems.push(("io_uring", format!("{}; launches paused, retry in {} s", resil::io_uring_banner(), uring_at - now())));
    }
    let host_hold = problems.iter().any(|(k, _)| matches!(*k, "io_uring")) || mem_hold.is_some() || load_hold.is_some();
    let mut blocked = problems.first().cloned();
    // Background failures (cache saves, the startup cleanup), one health item per kind.
    for (kind, msgs) in notice_kinds(&app.notices.lock().unwrap()) {
        problems.push((kind, msgs));
    }
    let mut budget = {
        let vms = app.vms.lock().unwrap();
        let act = vms.iter().filter(|v| v.state.is_active());
        let (mb, cpus) = act.fold((0, 0), |(m, c), v| (m + v.mem_mb as u64, c + v.cpus as u64));
        vm::Budget::new(host.mem_total_mb, mb, cpus, host.threads)
    };

    let mut queued_by_repo = HashMap::new();
    let mut errors = vec![];
    let mut repo_errors = HashMap::new();
    let mut refused_forks = HashMap::new();
    let mut fork_queued = vec![];
    let mut waiting_list: Vec<Waiting> = vec![];
    let mut pending_msgs: Vec<String> = vec![];
    // Queued jobs this tick that found every slot taken while holds take some.
    let mut waiting_on_holds = 0;
    // Rotate the start so the first repo doesn't always win scarce slots.
    let repos: Vec<_> = live
        .iter()
        .flat_map(|f| {
            let rs = cfgs.iter().find(|c| c.id == f.id()).map(|c| f.repos(c)).unwrap_or_default();
            rs.into_iter().map(|r| (f.clone(), r))
        })
        .collect();
    let start = TICK.fetch_add(1, Ordering::Relaxed) % repos.len().max(1);
    for (forge, rr) in repos.iter().cycle().skip(start).take(repos.len()) {
        let repo = &rr.key();
        let api = apis.get(&forge.id()).cloned().unwrap_or_default();
        let probing = &mut probing;
        // App mode: only the repos of a rate-limited installation wait.
        if let Some(m) = forge.repo_paused(rr) {
            errors.push(format!("{repo}: {m}"));
            repo_errors.insert(repo.clone(), m);
            continue;
        }
        let (by_size, runners, forks, fork_job, lookup_error, pending) = match forge
            .demand(rr, &cfg.label, cfg.vm_cpus)
            .await
            .map(|d| (d.by_size, d.claimed, d.refused_forks, d.fork_queued, d.lookup_error, d.pending))
        {
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
        if let Some(m) = lookup_error {
            errors.push(format!("{repo}: {m}"));
            repo_errors.insert(repo.clone(), m);
        }
        // Informational only: a VM that is handed the fork job is refused by the exec gate and
        // killed, so a queued fork job can burn one VM but never stops the repo's launches.
        if fork_job {
            fork_queued.push(repo.clone());
        }
        attach_jobs(app, repo, &runners);
        let backed_off = app.backoff.lock().unwrap().get(repo).is_some_and(|&(_, at)| at > now());
        vm::recycle_warm(app, repo, cfg.warm_recycle_mins).await;
        vm::recycle_stale_policy(app, repo, &vm::policy_id(cfg)).await;
        // A parked cache save whose readers are gone (or that hit a lock last time).
        if let Some((vm::CacheUse::Discarded, Some(why))) = vm::commit_pending(app, repo, "").await {
            tracing::warn!("{repo}: parked cache commit: {why}");
        }
        vm::check_parked(app, repo);
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
            let held = backed_off
                || host_hold
                || old_image
                || gate.is_some()
                || egress_err.is_some()
                || draining
                || app.stopping.load(Ordering::SeqCst);
            let (demand, mut warm) = vm::launch_split(queued, waiting, target);
            // Replacements wait for a cache commit so they boot on the new cache.
            if warm > 0 && vm::cache_busy(app, repo) {
                warm = 0;
            }
            let want = if held { 0 } else { (demand + warm).min(cfg.max_vms.saturating_sub(active)) };
            // The per-repo cap counts the repo's active VMs (warm ones too), not debug holds: nothing would release them for it.
            let repo_room = cfg.repo_cap(repo).map(|cap| {
                let n = app
                    .vms
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.state.is_active() && v.state != vm::State::Held)
                    .count();
                (cap, cap.saturating_sub(n))
            });
            let want = repo_room.map_or(want, |(_, room)| want.min(room));
            let cap_short = repo_room.filter(|&(_, room)| room < demand).map(|(cap, _)| cap);
            let room_short = cfg.max_vms.saturating_sub(active) < demand;
            let allowed = api.allow(now(), want, probing.contains(&forge.id()));
            let api_cut = allowed < want;
            let want = allowed;
            // After an io_uring pause one launch tests whether the limit has cleared.
            let want = if uring_fails > 0 { want.min(1) } else { want };
            if want > 0 {
                probing.insert(forge.id());
            }
            // A debug hold must not keep a queued job waiting: end the oldest, one per waiting job.
            // Not while GitHub is refusing runner registration: the freed slot couldn't be used.
            if let (false, Some(m)) = (held || api.fails > 0, held_block(demand, cfg.max_vms, active, holds)) {
                waiting_on_holds += demand;
                vm::release_oldest_hold(app, waiting_on_holds);
                if blocked.is_none() {
                    blocked = Some(("held", m));
                }
            }
            // QEMU allocates lazily, so MemAvailable alone lets a burst overcommit.
            let (want, limit) = budget.take(want, cfg.mem_mb(n), n);
            if blocked.is_none() {
                blocked = limit.clone().map(|m| ("budget", m));
            }
            let short = demand.saturating_sub(want);
            if short > 0 {
                let (reason, detail) = WaitCtx {
                    backed_off,
                    host_hold: host_hold || uring_fails > 0,
                    old_image,
                    gate: gate.clone(),
                    egress: egress_err.as_ref().map(|e| e.to_string()),
                    draining: draining || app.stopping.load(Ordering::SeqCst),
                    api_cut,
                    repo_cap: cap_short,
                    slots_full: room_short,
                    holds,
                    max_vms: cfg.max_vms,
                    budget: limit,
                }
                .reason();
                waiting_list.push(Waiting { repo: repo.clone(), jobs: short, cpus: n, reason, detail });
            }
            for i in 0..want {
                vm::launch(app.clone(), repo.clone(), n, i >= demand);
            }
        }
        // GitHub holds a run as pending (a concurrency group or an approval) while kiln has free slots and nothing of
        // this repo waits on kiln: say so, since only the user can cancel and re-run it.
        let idle = blocked.is_none()
            && cfg.max_vms > app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).count()
            && !waiting_list.iter().any(|w| &w.repo == repo);
        if let (true, Some(p)) = (idle, pending.iter().min_by_key(|p| p.since))
            && now().saturating_sub(p.since) > 600
        {
            pending_msgs.push(format!(
                "GitHub has held run {} #{} in {repo} as pending for {} min (a concurrency group or approval wait); kiln has free slots. Cancel and re-run it on GitHub if it should run.",
                p.workflow,
                p.number,
                (now() - p.since) / 60
            ));
        }
        queued_by_repo.insert(repo.clone(), by_size);
    }
    if !pending_msgs.is_empty() {
        problems.push(("github_pending", pending_msgs.join(" ")));
    }
    // Pause over: the banner stays only while a job waits on the probe, not indefinitely.
    if blocked.is_none() && any_queued {
        let mut ids: Vec<_> = apis.keys().collect();
        ids.sort_by_key(|id| id.as_str());
        blocked = ids.into_iter().find_map(|id| apis[id].banner(now(), &forge_name(id)).map(|m| (api_kind(id), m)));
    }
    {
        let mut p = app.poll.lock().unwrap();
        p.repo_errors = repo_errors;
        p.refused_forks = refused_forks;
        p.fork_queued = fork_queued;
        p.health = problems.iter().map(|(k, m)| (k.to_string(), m.clone())).collect();
        for line in waiting_changes(&p.waiting, &waiting_list) {
            tracing::info!("{line}");
        }
        p.waiting = waiting_list;
        p.blocked_kind = blocked.as_ref().map(|b| b.0.to_string());
        p.blocked = blocked.map(|b| b.1);
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(queued_by_repo)
}

/// Copy job page, queue time and run (branch, commit, PR) onto the VM whose runner picked the job up.
/// A VM binds to the first job id it is seen with; a second, different id means the runner took a
/// job it was not minted for: the VM is killed and its cache overlay discarded (trust follows the
/// job that ran, never a later one).
/// A fork PR job that reached one of our runners anyway (a JIT runner takes any
/// matching job) is killed. The guest's pre-job hook fails it before its first
/// step; this kill is the backstop.
fn attach_jobs(app: &App, repo: &str, runners: &HashMap<String, forge::JobInfo>) {
    let mut kill = vec![];
    let changed: Vec<vm::Vm> = app
        .vms
        .lock()
        .unwrap()
        .iter_mut()
        // A job listing speaks only for the repo it was read from: another repo's runner may carry any name.
        .filter(|v| v.repo.eq_ignore_ascii_case(repo))
        .filter_map(|v| {
            let job = runners.get(&v.id)?;
            // A gated forge's job id comes from the console alone: it starts the verdict gate.
            // The API only compares: a mismatch is a second job, but a lagging console must not be beaten to the id.
            let gated = vm::forge_for(app, &v.repo).is_ok_and(|(f, _)| f.gated());
            if v.job_id.as_deref().is_some_and(|id| id != job.id) {
                if v.cache == vm::CacheUse::Read {
                    v.cache = vm::CacheUse::Discarded;
                    v.cache_note = Some("cache not saved: a second job reached this runner".into());
                }
                if !v.state.is_active() {
                    return None;
                }
                v.note = Some("killed: a second job reached this runner".into());
                kill.push(v.id.clone());
                return Some(v.clone());
            }
            if job.fork && v.state.is_active() {
                v.note = Some("refused: pull request from a fork".into());
                kill.push(v.id.clone());
            }
            if (gated || v.job_id.as_deref() == Some(&job.id))
                && v.job_url.as_deref() == Some(&job.url)
                && v.queued_at == Some(job.queued_at)
                && v.run.as_ref() == Some(&job.run)
                && v.fork == job.fork
            {
                return None;
            }
            v.fork = job.fork;
            if !gated {
                v.job_id = Some(job.id.clone());
            }
            v.job_url = Some(job.url.clone());
            v.queued_at = Some(job.queued_at);
            v.run = Some(job.run.clone());
            Some(v.clone())
        })
        .collect();
    for id in kill {
        if let Some(k) = app.kills.lock().unwrap().get(&id) {
            k.notify_one();
        }
    }
    for v in &changed {
        vm::persist(app, v);
    }
}

/// An App on a fresh temp data dir, listening (if ever) on an ephemeral loopback port.
#[cfg(test)]
pub fn test_app(name: &str) -> Arc<App> {
    let data = std::env::temp_dir().join(format!("kiln-test-app-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(data.join("update")).unwrap();
    let cfg = Config { listen: "127.0.0.1:0".into(), ..Config::default() };
    Arc::new(App::new(data, cfg, github::Gh::new(String::new(), "none")))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_panicking_scheduler_is_reported() {
        let e = scheduler_ended(tokio::spawn(async { panic!("boom") }).await);
        assert!(format!("{e}").contains("scheduler task died"), "{e}");
        assert!(format!("{}", scheduler_ended(Ok(()))).contains("returned"));
    }

    #[tokio::test]
    async fn scheduler_ending_while_stopping_is_not_a_fault() {
        assert!(!scheduler_fault(true, &Ok(())));
        assert!(scheduler_fault(false, &Ok(())));
        let panicked = tokio::spawn(async { panic!("boom") }).await;
        assert!(scheduler_fault(true, &panicked), "a panic always exits");
    }

    #[test]
    fn second_serve_lock_fails_while_first_is_held() {
        let p = std::env::temp_dir().join(format!("kiln-lock-test-{}", std::process::id()));
        let first = try_lock(&p).unwrap();
        let e = try_lock(&p).unwrap_err().to_string();
        assert!(e.contains("another kiln serve"), "{e}");
        drop(first);
        try_lock(&p).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_clock_before_1970_is_zero_not_a_panic() {
        // now() itself cannot be faked; this pins the saturating form it uses.
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(5);
        assert_eq!(before.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()), 0);
    }

    #[test]
    fn a_cleanup_that_keeps_failing_becomes_a_health_item() {
        let app = App::for_tests();
        note_cleanup_failure(&app, "sweep:a", "runner cleanup of a", 1, "403", false);
        assert!(app.notices.lock().unwrap().is_empty(), "two failures are not yet a pattern");
        note_cleanup_failure(&app, "sweep:a", "runner cleanup of a", 2, "403", true);
        assert!(app.notices.lock().unwrap().is_empty(), "not while the box is still starting");
        note_cleanup_failure(&app, "sweep:a", "runner cleanup of a", 2, "403", false);
        let kinds = notice_kinds(&app.notices.lock().unwrap());
        assert_eq!(kinds.len(), 1);
        assert!(
            kinds[0].0 == "cleanup" && kinds[0].1.contains("keeps failing (3 attempts); see") && !kinds[0].1.contains("403"),
            "{kinds:?}"
        );
    }

    use super::*;

    #[test]
    fn attach_jobs_marks_fork_vms() {
        let app = test_app("attach-fork");
        let mut v: vm::Vm = serde_json::from_value(serde_json::json!({
            "id": "kiln-5-0", "repo": "acme/kiln", "runner_id": 1, "state": "busy", "job": "t", "result": null,
            "started": 1, "busy_since": 2, "ended": null, "note": null
        }))
        .unwrap();
        app.vms.lock().unwrap().push(v.clone());
        v.id = "kiln-5-1".into();
        app.vms.lock().unwrap().push(v);
        let r = |fork| forge::JobInfo {
            id: "2".into(),
            url: "https://github.com/acme/kiln/actions/runs/1/job/2".to_string(),
            queued_at: 1,
            fork,
            run: vm::Run::default(),
        };
        attach_jobs(&app, "acme/kiln", &HashMap::from([("kiln-5-0".to_string(), r(true)), ("kiln-5-1".to_string(), r(false))]));
        let vms = app.vms.lock().unwrap();
        assert!(vms[0].fork && vms[0].note.as_deref() == Some("refused: pull request from a fork"));
        assert!(!vms[1].fork && vms[1].note.is_none());
    }

    /// Another repo's job listing may name this VM's runner (VM ids are guessable): nothing happens to the VM.
    #[tokio::test]
    async fn another_repos_job_naming_this_vm_changes_nothing() {
        let app = test_app("attach-foreign");
        let v: vm::Vm = serde_json::from_value(serde_json::json!({
            "id": "kiln-5-0", "repo": "gitea:acme/demo", "runner_id": 1, "state": "busy", "job": "t", "result": null,
            "started": 1, "busy_since": 2, "ended": null, "note": null, "cache": "read", "job_id": "2"
        }))
        .unwrap();
        app.vms.lock().unwrap().push(v);
        let kill = Arc::new(tokio::sync::Notify::new());
        app.kills.lock().unwrap().insert("kiln-5-0".into(), kill.clone());
        // A different job id and a fork flag: both would kill the VM if the listing counted.
        let job =
            forge::JobInfo { id: "9".into(), url: "https://x.example/job/9".into(), queued_at: 1, fork: true, run: vm::Run::default() };
        let runners = HashMap::from([("kiln-5-0".to_string(), job)]);
        attach_jobs(&app, "acme/demo", &runners);
        attach_jobs(&app, "gitlab:acme/demo", &runners);
        let v = app.vms.lock().unwrap()[0].clone();
        assert_eq!((v.job_id.as_deref(), v.cache, v.note, v.fork, v.job_url), (Some("2"), vm::CacheUse::Read, None, false, None));
        assert!(tokio::time::timeout(Duration::from_millis(50), kill.notified()).await.is_err());
    }

    #[tokio::test]
    async fn a_second_job_id_discards_the_cache_overlay_and_kills_the_vm() {
        let app = test_app("attach-second-id");
        let v: vm::Vm = serde_json::from_value(serde_json::json!({
            "id": "kiln-5-0", "repo": "acme/kiln", "runner_id": 1, "state": "busy", "job": "t", "result": null,
            "started": 1, "busy_since": 2, "ended": null, "note": null, "cache": "read"
        }))
        .unwrap();
        app.vms.lock().unwrap().push(v);
        let kill = Arc::new(tokio::sync::Notify::new());
        app.kills.lock().unwrap().insert("kiln-5-0".into(), kill.clone());
        let job = |id: &str| forge::JobInfo {
            id: id.into(),
            url: format!("https://github.com/acme/kiln/actions/runs/1/job/{id}"),
            queued_at: 1,
            fork: false,
            run: vm::Run::default(),
        };
        let attach = |id: &str| attach_jobs(&app, "acme/kiln", &HashMap::from([("kiln-5-0".to_string(), job(id))]));
        // The first id binds; repeating it changes nothing.
        attach("2");
        attach("2");
        let v = app.vms.lock().unwrap()[0].clone();
        assert_eq!((v.job_id.as_deref(), v.cache, v.note.as_deref()), (Some("2"), vm::CacheUse::Read, None));
        assert!(tokio::time::timeout(Duration::from_millis(50), kill.notified()).await.is_err());
        // A second id: the binding and job page stay, the overlay is discarded, the VM is killed.
        attach("3");
        let v = app.vms.lock().unwrap()[0].clone();
        assert_eq!((v.job_id.as_deref(), v.cache), (Some("2"), vm::CacheUse::Discarded));
        assert_eq!(v.job_url.as_deref(), Some("https://github.com/acme/kiln/actions/runs/1/job/2"));
        assert!(tokio::time::timeout(Duration::from_millis(50), kill.notified()).await.is_ok());
    }

    #[tokio::test]
    async fn a_gated_forge_never_gets_its_job_id_from_attach_jobs() {
        let m = forge_test_mock::Mock::github().await;
        let app = forge_test_mock::app("attach-gated", &m, Config::default());
        let cfg: forge::ForgeCfg =
            serde_json::from_str(r#"{"id":"gitea","kind":"gitea","url":"https://gitea.example.org","repos":["acme/demo"]}"#).unwrap();
        app.forges.insert(cfg, forge::Forge::Gitea(Box::new(forge::gitea::Gitea::for_mock("https://gitea.example.org", &m.base, "tok"))));
        let v: vm::Vm = serde_json::from_value(serde_json::json!({
            "id": "kiln-5-0", "repo": "gitea:acme/demo", "runner_id": 1, "state": "idle", "job": null, "result": null,
            "started": 1, "busy_since": null, "ended": null, "note": null, "cache": "read"
        }))
        .unwrap();
        app.vms.lock().unwrap().push(v);
        let kill = Arc::new(tokio::sync::Notify::new());
        app.kills.lock().unwrap().insert("kiln-5-0".into(), kill.clone());
        let job = |id: &str| forge::JobInfo {
            id: id.into(),
            url: format!("https://gitea.example.org/acme/demo/actions/runs/1/jobs/{id}"),
            queued_at: 1,
            fork: false,
            run: vm::Run::default(),
        };
        // The API saw the job first: the page shows, but the console's `JobStart` is still the one to bind the id.
        attach_jobs(&app, "gitea:acme/demo", &HashMap::from([("kiln-5-0".to_string(), job("2"))]));
        let v = app.vms.lock().unwrap()[0].clone();
        assert_eq!((v.job_id, v.cache), (None, vm::CacheUse::Read));
        assert!(v.job_url.is_some());
        assert!(tokio::time::timeout(Duration::from_millis(50), kill.notified()).await.is_err());
        // Once the console bound an id, a different API id is a second job.
        app.vms.lock().unwrap()[0].job_id = Some("2".into());
        app.vms.lock().unwrap()[0].state = vm::State::Busy;
        attach_jobs(&app, "gitea:acme/demo", &HashMap::from([("kiln-5-0".to_string(), job("3"))]));
        assert_eq!(app.vms.lock().unwrap()[0].job_id.as_deref(), Some("2"));
        assert!(tokio::time::timeout(Duration::from_millis(50), kill.notified()).await.is_ok());
    }

    /// The seam for tick tests (`mixed_tests` builds on it): a baked image so the tick runs, `max_vms: 0` so it
    /// never reaches QEMU. Everything else in `tick` is the real code against the mock forge.
    pub(crate) fn tick_app(name: &str, m: &forge_test_mock::Mock, forges: Option<Vec<forge::ForgeCfg>>) -> (Arc<App>, Config) {
        // vm_cpus fits a 3-thread host (a hosted Mac runner), or the fixture's default-size jobs would not count.
        let cfg = Config {
            repos: vec!["acme/demo".into()],
            max_vms: 0,
            vm_cpus: host_threads().min(4),
            auto_rebake: false,
            forges,
            ..Config::default()
        };
        let app = forge_test_mock::app(name, m, cfg.clone());
        let img = app.data.join("images");
        std::fs::create_dir_all(&img).unwrap();
        for f in ["base.qcow2", "base.vmlinuz"] {
            std::fs::write(img.join(f), "").unwrap();
        }
        std::fs::write(img.join("base.json"), r#"{"recipe":999}"#).unwrap();
        (app, cfg)
    }

    #[tokio::test]
    async fn a_tick_runs_the_forge_split_and_the_repo_loop() {
        let m = forge_test_mock::Mock::github().await;
        let (app, cfg) = tick_app("tick-ok", &m, None);
        let queued = tick(&app, &cfg).await.unwrap();
        // The request sequence for one repo: the runner-release lookup, then the demand reads.
        let reqs = m.requests();
        assert_eq!(reqs[0], "GET /repos/actions/runner/releases/latest");
        assert!(reqs[1].starts_with("GET /repos/acme/demo/actions/runs?status=queued"), "{reqs:?}");
        assert!(reqs.iter().all(|r| r.starts_with("GET ")), "a tick only reads (max_vms 0 launches nothing): {reqs:?}");
        // What queued_jobs found for the fixture: two sized queues and one refused fork PR job.
        assert_eq!(queued["acme/demo"].len(), 2);
        let p = app.poll.lock().unwrap();
        assert_eq!(p.refused_forks["acme/demo"], 1);
        assert!(p.repo_errors.is_empty(), "{:?}", p.repo_errors);
        assert!(!p.health.iter().any(|(k, _)| k == "forge" || k == "github_api"), "{:?}", p.health);
        assert!(app.vms.lock().unwrap().is_empty());
        // max_vms 0: every queued job waits on the slot cap, but that is no banner.
        assert!(p.waiting.iter().all(|w| w.reason == "slots_full" && w.repo == "acme/demo"), "{:?}", p.waiting);
        assert_eq!(p.waiting.iter().map(|w| w.jobs).sum::<usize>(), 3);
        assert!(p.blocked_kind.as_deref() != Some("slots_full"));
    }

    /// One tick of the fixture (three queued jobs) with `f` applied to the app and config first: the waiting reasons.
    async fn waiting_reasons(name: &str, f: impl FnOnce(&mut Arc<App>, &mut Config)) -> Vec<&'static str> {
        let m = forge_test_mock::Mock::github().await;
        let (mut app, mut cfg) = tick_app(name, &m, None);
        f(&mut app, &mut cfg);
        let _ = tick(&app, &cfg).await;
        let w = app.poll.lock().unwrap().waiting.clone();
        w.iter().map(|w| w.reason).collect()
    }

    #[tokio::test]
    async fn waiting_reasons_follow_the_gates() {
        let n = |r: &'static str| vec![r; 2];
        assert_eq!(waiting_reasons("wait-slots", |_, _| {}).await, n("slots_full"));
        assert_eq!(
            waiting_reasons("wait-backoff", |a, c| {
                c.max_vms = 4;
                a.backoff.lock().unwrap().insert("acme/demo".into(), (1, now() + 600));
            })
            .await,
            n("repo_backoff")
        );
        assert_eq!(
            waiting_reasons("wait-drain", |a, c| {
                c.max_vms = 4;
                a.draining.store(true, Ordering::SeqCst);
            })
            .await,
            n("draining")
        );
        assert_eq!(
            waiting_reasons("wait-psi", |a, c| {
                c.max_vms = 4;
                Arc::get_mut(a).unwrap().host_fixed = Some(HostReadings { mem_psi: Some(45.0), ..HostReadings::TEST });
            })
            .await,
            n("host_hold")
        );
        assert_eq!(
            waiting_reasons("wait-cap", |_, c| {
                c.max_vms = 4;
                c.max_vms_per_repo = 1;
                c.repo_max_vms.insert("other/repo".into(), 9);
            })
            .await
            .first(),
            Some(&"repo_cap")
        );
        // A debug hold doesn't count against the cap: nothing would release it for the repo.
        let held = waiting_reasons("wait-cap-held", |a, c| {
            c.max_vms = 4;
            c.max_vms_per_repo = 2;
            let v: vm::Vm = serde_json::from_value(serde_json::json!({
                "id": "kiln-7-0", "repo": "acme/demo", "runner_id": 1, "state": "held", "job": "j", "result": "Failed",
                "started": 1, "busy_since": 1, "ended": null, "note": null
            }))
            .unwrap();
            a.vms.lock().unwrap().push(v);
        })
        .await;
        // Counted, the hold would leave room for one of the two small jobs: both sizes would wait.
        assert_eq!(held, ["repo_cap"], "only the large job waits");
        assert_eq!(
            waiting_reasons("wait-mem", |a, c| {
                c.max_vms = 4;
                Arc::get_mut(a).unwrap().host_fixed = Some(HostReadings { mem_avail_mb: 10, ..HostReadings::TEST });
            })
            .await,
            n("launch_gate")
        );
        assert_eq!(
            waiting_reasons("wait-api", |a, c| {
                c.max_vms = 4;
                a.api_backoff.lock().unwrap().entry(forge::ForgeId::github()).or_default().fail(Some(503), now());
            })
            .await,
            n("github_api")
        );
        assert_eq!(
            waiting_reasons("wait-image", |a, c| {
                c.max_vms = 4;
                std::fs::write(a.data.join("images/base.json"), r#"{"recipe":1}"#).unwrap();
            })
            .await,
            n("old_image")
        );
    }

    #[test]
    fn waiting_is_logged_on_change_only() {
        let w = |repo: &str, reason| Waiting { repo: repo.into(), jobs: 1, cpus: 2, reason, detail: None };
        let a = vec![w("a/b", "slots_full")];
        assert_eq!(waiting_changes(&[], &a).len(), 1);
        assert!(waiting_changes(&a, &a).is_empty());
        // Another size or count of the same reason is no change.
        assert!(waiting_changes(&a, &[Waiting { jobs: 5, cpus: 4, ..w("a/b", "slots_full") }]).is_empty());
        let l = waiting_changes(&a, &[w("a/b", "budget")]);
        assert!(l.len() == 1 && l[0].contains("budget"), "{l:?}");
        let l = waiting_changes(&a, &[]);
        assert!(l.len() == 1 && l[0].contains("no queued jobs are waiting"), "{l:?}");
    }

    #[test]
    fn waiting_serializes_additively() {
        let mut p = PollStatus::default();
        p.waiting.push(Waiting { repo: "a/b".into(), jobs: 2, cpus: 4, reason: "budget", detail: None });
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["waiting"][0], serde_json::json!({"repo": "a/b", "jobs": 2, "cpus": 4, "reason": "budget"}));
        assert!(v["queued"].is_object() && v["health"].is_array());
    }

    #[tokio::test]
    async fn a_pending_run_is_raised_only_while_kiln_has_idle_slots() {
        let empty = r#"{"workflow_runs":[]}"#;
        let pending = |at: &str| format!(r#"{{"workflow_runs":[{{"id":9,"name":"Release","run_number":7,"created_at":"{at}"}}]}}"#);
        let run = |name: &'static str, at: &'static str, slots: usize| async move {
            let m = forge_test_mock::Mock::github().await;
            let (app, mut cfg) = tick_app(name, &m, None);
            cfg.max_vms = slots;
            for s in ["queued", "in_progress"] {
                m.route("GET", &format!("/repos/acme/demo/actions/runs?status={s}&per_page=30"), 200, empty);
            }
            m.route("GET", "/repos/acme/demo/actions/runs?status=pending&per_page=30", 200, pending(at));
            tick(&app, &cfg).await.unwrap();
            let h = app.poll.lock().unwrap().health.clone();
            h.into_iter().find(|(k, _)| k == "github_pending").map(|h| h.1)
        };
        let msg = run("pend-old", "2026-01-01T00:00:00Z", 2).await.expect("raised");
        assert!(msg.starts_with("GitHub has held run Release #7 in acme/demo as pending for "), "{msg}");
        assert!(msg.contains("kiln has free slots"));
        // Not yet 10 minutes old (a future timestamp), or kiln has no slot to give.
        assert_eq!(run("pend-new", "2099-01-01T00:00:00Z", 2).await, None);
        assert_eq!(run("pend-full", "2026-01-01T00:00:00Z", 0).await, None);
    }

    #[tokio::test]
    async fn a_tick_reports_backoff_per_forge_and_unsupported_forges() {
        let m = forge_test_mock::Mock::github().await;
        let forges: Vec<forge::ForgeCfg> = serde_json::from_str(
            r#"[{"id":"github","kind":"github"},{"id":"gl","kind":"gitlab","url":"ftp://gitlab.example.org","repos":["x/y"]}]"#,
        )
        .unwrap();
        let (app, cfg) = tick_app("tick-backoff", &m, Some(forges));
        // A 5xx on GitHub's registration holds GitHub; a GitLab failure holds only GitLab.
        {
            let mut b = app.api_backoff.lock().unwrap();
            b.entry(forge::ForgeId::github()).or_default().fail(Some(503), now());
            b.entry(forge::ForgeId::new("gl").unwrap()).or_default().fail(None, now());
        }
        tick(&app, &cfg).await.unwrap();
        let mut p = app.poll.lock().unwrap().clone();
        // Host-resource entries (memory, disk) depend on the machine running the test.
        p.health.retain(|(k, _)| k != "memory" && k != "disk");
        let kinds: Vec<_> = p.health.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, ["forge", "github_api", "forge_api"], "{:?}", p.health);
        assert!(p.health[0].1.contains("gl") && p.health[0].1.contains("could not be set up"), "{:?}", p.health[0]);
        assert_eq!(p.health[1].1.split(" — ").next().unwrap(), "GitHub is rejecting runner registration (HTTP 503)");
        assert!(p.health[2].1.starts_with("gl is unreachable for runner registration"), "{:?}", p.health[2]);
        // The first problem is what blocks, and the kind says whose.
        assert_eq!(p.blocked_kind.as_deref(), Some("forge"));
        // Clearing GitHub's entry leaves GitLab's.
        app.api_backoff.lock().unwrap().remove(&forge::ForgeId::github());
        tick(&app, &cfg).await.unwrap();
        let kinds: Vec<_> =
            app.poll.lock().unwrap().health.iter().map(|(k, _)| k.clone()).filter(|k| k != "memory" && k != "disk").collect();
        assert_eq!(kinds, ["forge", "forge_api"]);
    }

    #[tokio::test]
    async fn memory_pressure_and_an_exhausted_io_uring_hold_launches() {
        let m = forge_test_mock::Mock::github().await;
        let (mut app, cfg) = tick_app("tick-resil", &m, None);
        Arc::get_mut(&mut app).unwrap().host_fixed = Some(HostReadings { mem_psi: Some(45.0), ..HostReadings::TEST });
        tick(&app, &cfg).await.unwrap();
        let p = app.poll.lock().unwrap().clone();
        assert_eq!(p.blocked_kind.as_deref(), Some("memory"));
        assert!(p.blocked.unwrap().contains("holding launches"));
        // Calm again, but the last launch hit the io_uring limit: held until the retry time.
        Arc::get_mut(&mut app).unwrap().host_fixed = Some(HostReadings::TEST);
        *app.io_uring.lock().unwrap() = (1, now() + 100);
        tick(&app, &cfg).await.unwrap();
        let p = app.poll.lock().unwrap().clone();
        assert_eq!(p.blocked_kind.as_deref(), Some("io_uring"));
        assert!(p.blocked.unwrap().contains("RLIMIT_MEMLOCK"));
        // Past the retry time nothing blocks (one probe launch is allowed).
        *app.io_uring.lock().unwrap() = (1, now() - 1);
        tick(&app, &cfg).await.unwrap();
        assert_eq!(app.poll.lock().unwrap().blocked_kind, None);
    }

    #[tokio::test]
    async fn a_queued_fork_job_is_reported_but_blocks_no_launches() {
        let m = forge_test_mock::Mock::github().await;
        // A launch that mints nothing: the GitHub VM below dies at registration, long before QEMU.
        m.route("POST", "/repos/acme/demo/actions/runners/generate-jitconfig", 404, "{}");
        // GitHub's queue is empty, so its demand never competes with the Gitea pool for the cpu budget (the repo order rotates).
        for st in ["queued", "in_progress"] {
            m.route(
                "GET",
                &format!("/repos/acme/demo/actions/runs?status={st}&per_page=30"),
                200,
                r#"{"workflow_runs":[],"total_count":0}"#,
            );
        }
        let forges: Vec<forge::ForgeCfg> = serde_json::from_str(
            r#"[{"id":"github","kind":"github","repos":["acme/demo"]},{"id":"gitea","kind":"gitea","url":"https://gitea.example.org","repos":["acme/demo"]}]"#,
        )
        .unwrap();
        let (app, mut cfg) = tick_app("tick-fork-queued", &m, Some(forges.clone()));
        cfg.max_vms = 4;
        cfg.vm_mem_mb = 64;
        cfg.vm_cpus = 1; // two warm VMs and GitHub's must fit the cpu budget of a 3-thread host
        cfg.warm.insert("gitea:acme/demo".into(), 2);
        let g = forge::gitea::Gitea::for_mock("https://gitea.example.org", &m.base, "tok");
        app.forges.insert(forges[1].clone(), forge::Forge::Gitea(Box::new(g)));
        let gt = |f: &str| forge_test_mock::fixture_in("gitea", f);
        let api = "/api/v1/repos/acme/demo/actions";
        m.route("GET", "/api/v1/version", 200, gt("version.json"));
        for id in 70..=78 {
            m.route("GET", &format!("{api}/runs/{id}"), 200, gt(&format!("run_{id}.json")));
        }
        // Job 91 of this fixture is a queued pull_request_target fork job.
        m.route("GET", &format!("{api}/jobs?status=queued&limit=50&page=1"), 200, gt("jobs_queued_a.json"));
        // An idle warm VM of the Gitea repo, which the fork job could reach.
        let warm: vm::Vm = serde_json::from_value(serde_json::json!({
            "id": "kiln-1-0", "repo": "gitea:acme/demo", "runner_id": 5, "state": "idle", "job": null, "result": null,
            "started": now(), "online_at": now(), "busy_since": null, "ended": null, "note": null, "cpus": cfg.vm_cpus, "warm": true,
            "policy": vm::policy_id(&cfg)
        }))
        .unwrap();
        app.vms.lock().unwrap().push(warm);
        let count = |app: &App, repo: &str| app.vms.lock().unwrap().iter().filter(|v| v.repo == repo).count();

        tick(&app, &cfg).await.unwrap();
        // The banner names the Gitea repo, but nothing is held: the warm pool refills like any other repo's.
        assert_eq!(app.poll.lock().unwrap().fork_queued, ["gitea:acme/demo"]);
        assert!(
            count(&app, "gitea:acme/demo") >= 2,
            "the warm pool refills despite the queued fork job: {:?}",
            app.poll.lock().unwrap().blocked
        );
        // A warm VM that the fork job reaches is still refused and killed, and an idle one is not retired beforehand.
        assert!(!m.requests().iter().any(|r| r.contains("/api/v1/repos/acme/demo/actions/runners/5")), "{:?}", m.requests());
        let fork = forge::JobInfo { id: "91".into(), url: "u".into(), queued_at: 1, fork: true, run: vm::Run::default() };
        attach_jobs(&app, "gitea:acme/demo", &HashMap::from([("kiln-1-0".to_string(), fork)]));
        let v = app.vms.lock().unwrap().iter().find(|v| v.id == "kiln-1-0").unwrap().clone();
        assert!(v.fork && v.note.as_deref() == Some("refused: pull request from a fork"));
    }

    #[tokio::test]
    async fn a_rate_limited_forge_reports_through_health_and_fails_the_tick() {
        let m = forge_test_mock::Mock::github().await;
        let (app, cfg) = tick_app("tick-limit", &m, None);
        m.fail("GET", "/repos/acme/demo/actions/runs?status=queued&per_page=30", 403, "You have exceeded a Secondary Rate Limit.");
        let e = tick(&app, &cfg).await.unwrap_err().to_string();
        assert!(e.contains("acme/demo"), "{e}");
        assert!(app.poll.lock().unwrap().repo_errors.contains_key("acme/demo"));
        // The limit paused the forge: the next tick has no live forge and says why.
        assert!(app.forges.get(&forge::ForgeId::github()).unwrap().health().unwrap().contains("rate limit"));
        let e = tick(&app, &cfg).await.unwrap_err().to_string();
        assert!(e.contains("rate limit"), "{e}");
    }

    #[tokio::test]
    async fn a_tick_of_polling_fills_vm_fields() {
        // queued_jobs against the mock forge, then attach_jobs: what the dashboard shows per VM.
        let m = forge_test_mock::Mock::github().await;
        let app = forge_test_mock::app("attach-tick", &m, Config::default());
        let rec = |id: &str| -> vm::Vm {
            serde_json::from_value(serde_json::json!({
                "id": id, "repo": "acme/demo", "runner_id": 1, "state": "busy", "job": "t", "result": null,
                "started": 1, "busy_since": 2, "ended": null, "note": null
            }))
            .unwrap()
        };
        for id in ["kiln-7-0", "kiln-9-0", "kiln-8-0"] {
            std::fs::create_dir_all(app.data.join("vms").join(id)).unwrap();
            app.vms.lock().unwrap().push(rec(id));
        }
        let (by_size, runners, forks, _) = app.gh.queued_jobs("acme/demo", "kiln", 1).await.unwrap();
        assert_eq!((by_size.len(), forks), (2, 1));
        attach_jobs(&app, "acme/demo", &runners);
        let vms = app.vms.lock().unwrap().clone();
        let by = |id: &str| vms.iter().find(|v| v.id == id).unwrap().clone();
        let ok = by("kiln-7-0");
        // Cache trust keys on the job id first, so the characterization pins it too.
        assert_eq!(ok.job_id.as_deref(), Some("5201"));
        assert_eq!(ok.job_url.as_deref(), Some("https://github.com/acme/demo/actions/runs/1004/job/5201"));
        assert_eq!(ok.queued_at, Some(github::parse_rfc3339("2026-10-11T09:00:00Z").unwrap()));
        let run = ok.run.as_ref().unwrap();
        assert_eq!(
            (run.branch.as_str(), run.pr, run.event.as_str(), run.workflow.as_str(), run.number),
            ("fix-login", Some(7), "pull_request", "Release", 43)
        );
        assert!(!ok.fork && ok.note.is_none());
        // The fork PR job that reached our runner anyway is flagged (and its VM killed by the caller's kill handle).
        let fork = by("kiln-9-0");
        assert!(fork.fork && fork.note.as_deref() == Some("refused: pull request from a fork"));
        assert_eq!(fork.run.as_ref().unwrap().number, 42);
        // A runner GitHub does not list yet is untouched.
        assert!(by("kiln-8-0").run.is_none() && by("kiln-8-0").job_url.is_none());
        // Persisted for the next start.
        let meta: vm::Vm = serde_json::from_slice(&std::fs::read(app.data.join("vms/kiln-7-0/meta.json")).unwrap()).unwrap();
        assert_eq!(meta.run, ok.run);
        // Unchanged input writes nothing new.
        std::fs::remove_file(app.data.join("vms/kiln-7-0/meta.json")).unwrap();
        attach_jobs(&app, "acme/demo", &runners);
        assert!(!app.data.join("vms/kiln-7-0/meta.json").exists());
    }

    #[test]
    fn config_json_golden() {
        // The defaults as saved to config.json (App::save_cfg writes pretty JSON).
        let text = serde_json::to_string_pretty(&Config::default()).unwrap();
        forge_test_mock::golden("config.json", &text);
        // Loading it back changes nothing, and so does a hand-written minimal file plus a save.
        let back: Config = serde_json::from_str(&text).unwrap();
        assert_eq!(serde_json::to_string_pretty(&back).unwrap(), text);
        let min: Config = serde_json::from_str(r#"{"repos":["acme/demo"]}"#).unwrap();
        let mut want: serde_json::Value = serde_json::from_str(&text).unwrap();
        want["repos"] = serde_json::json!(["acme/demo"]);
        assert_eq!(serde_json::to_value(&min).unwrap(), want);
    }

    #[test]
    fn notify_rules_validate() {
        let mut c = Config { repos: vec!["acme/kiln".into()], ..Default::default() };
        let rule = |repo: &str, wf: &str, oc: &str, to: Vec<&str>| notify::Rule {
            repo: repo.into(),
            workflow: wf.into(),
            outcome: oc.into(),
            to: to.into_iter().map(String::from).collect(),
        };
        c.notify_rules = vec![rule("acme/kiln", "release.yml", "any", vec!["a1b2c3d4"]), rule("*", "*", "failure", vec!["a1b2c3d4"])];
        assert!(c.validate_for(8).is_ok());
        for bad in [
            rule("not a repo", "*", "any", vec!["a1b2c3d4"]),
            rule("*", "../x.yml", "any", vec!["a1b2c3d4"]),
            rule("*", "release.txt", "any", vec!["a1b2c3d4"]),
            rule("*", "*", "sometimes", vec!["a1b2c3d4"]),
            rule("*", "*", "any", vec![]),
            rule("*", "*", "any", vec!["NOT-HEX!"]),
        ] {
            c.notify_rules = vec![bad.clone()];
            assert!(c.validate_for(8).is_err(), "{bad:?}");
        }
        // Other forges: a `forge-id:path` repo key; GitLab's workflow is a pipeline name, the others' a file.
        c.forges = Some(serde_json::from_str(r#"[{"id":"github","kind":"github"},{"id":"gl","kind":"gitlab","url":"https://gitlab.example.com","repos":["g/p"]},{"id":"ge","kind":"gitea","url":"https://gitea.example.com","repos":["o/n"]}]"#).unwrap());
        c.notify_rules = vec![rule("gl:g/p", "pipeline", "any", vec!["a1b2c3d4"]), rule("ge:o/n", "ci.yml", "any", vec!["a1b2c3d4"])];
        assert!(c.validate_for(8).is_ok());
        c.notify_rules = vec![rule("ge:o/n", "pipeline", "any", vec!["a1b2c3d4"])];
        assert!(c.validate_for(8).is_err(), "Gitea matches by file");
        c.notify_rules = vec![rule("gl:g/../p", "*", "any", vec!["a1b2c3d4"])];
        assert!(c.validate_for(8).is_err());
        c.notify_rules = vec![rule("*", "*", "any", vec!["a1b2c3d4"]); 51];
        assert!(c.validate_for(8).is_err(), "at most 50");
    }

    #[test]
    fn config_unknown_keys_survive_load_and_save() {
        // A newer kiln's keys (rollback safety) survive a load and a settings save; integer map keys still parse.
        let app = App::for_tests();
        let path = app.data.join("config.json");
        // Filtered egress is refused on macOS, so the round trip uses a value that loads there too.
        let egress = if platform::MACOS { "open" } else { "filtered" };
        let src = r#"{"egress":"EGRESS","vm_cpus":1,"size_mem_mb":{"2":4096},"forges":[{"id":"gl","kind":"gitlab","url":"https://gitlab.example.com","credential":"file","network":"public","repos":["g/s/p"]}],"future":true}"#
                .replace("EGRESS", egress);
        std::fs::write(&path, &src).unwrap();
        let c = load_config(&app.data).unwrap();
        assert_eq!((c.egress.as_str(), c.size_mem_mb.get(&2)), (egress, Some(&4096)));
        app.save_cfg(c).unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved["forges"],
            serde_json::json!([{"id": "gl", "kind": "gitlab", "url": "https://gitlab.example.com", "credential": "file", "network": "public", "repos": ["g/s/p"]}])
        );
        assert_eq!(saved["future"], true);
        assert_eq!(saved["size_mem_mb"], serde_json::json!({"2": 4096}));
        assert_eq!(Config::default().extra.len(), 0);
    }

    #[test]
    fn config_load_fails_closed() {
        let d = std::env::temp_dir().join(format!("kiln-test-config_load_fails_closed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(load_config(&d).unwrap().egress, "open", "no file: defaults");
        std::fs::write(d.join("config.json"), r#"{"egress":"filtered"}"#).unwrap();
        // Filtered egress is Linux-only (rootlesskit, nftables); elsewhere it is refused, not ignored.
        if cfg!(target_os = "linux") {
            assert_eq!(load_config(&d).unwrap().egress, "filtered");
        } else {
            assert!(load_config(&d).is_err(), "filtered egress must not silently become open");
        }
        std::fs::write(d.join("config.json"), r#"{"egress":"Filtered"}"#).unwrap();
        assert!(load_config(&d).is_err(), "a typo never means open");
        std::fs::write(d.join("config.json"), "{").unwrap();
        assert!(load_config(&d).is_err());
        std::fs::remove_file(d.join("config.json")).unwrap();
        std::fs::create_dir(d.join("config.json")).unwrap();
        assert!(load_config(&d).is_err(), "unreadable is not missing");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn health_list_composition() {
        let h = |k: &str| (k.to_string(), "m".to_string());
        let base = [h("disk"), h("draining")];
        let kinds = |l: Vec<(String, String)>| l.into_iter().map(|x| x.0).collect::<Vec<_>>();
        assert_eq!(kinds(health_list(&base, Some("x"), true, None, &[])), ["disk", "poll"]);
        assert_eq!(kinds(health_list(&[], None, false, None, &[])), ["landlock"]);
        assert_eq!(kinds(health_list(&[], None, true, Some("bad"), &[h("d1")])), ["notify_failing", "notify_failing"]);
        let starting = ("egress".to_string(), boot::waiting_for("filtered egress", "step: internet unreachable"));
        assert_eq!(
            kinds(health_list(&[starting, h("disk")], Some(&boot::waiting_msg("dns error")), true, None, &[])),
            ["disk"],
            "starting alerts nobody"
        );
    }

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
        for a in ["bake", "doctor", "status", "wait", "--version", "-V", "version", "help", ""] {
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
        assert!(!ok(|c| c.repos = vec!["Acme/Kiln".into(), "acme/kiln".into()]));
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
        assert_eq!(ok(|c| c.egress = "filtered".into()), !platform::MACOS, "filtered egress is Linux-only");
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
        assert_eq!(c.labels_for(4, false), ["self-hosted", "linux", "x64", "kiln-4cpu", "kiln"]);
        assert_eq!(c.labels_for(8, false), ["self-hosted", "linux", "x64", "kiln-8cpu"]);
        assert_eq!(c.runner_labels(8), c.labels_for(8, platform::ARM64));
        // arm64 hosts never advertise the plain label: x64 jobs must not land there.
        assert_eq!(c.labels_for(4, true), ["self-hosted", "linux", "ARM64", "kiln-arm64-4cpu", "kiln-arm64"]);
        assert_eq!(c.labels_for(8, true), ["self-hosted", "linux", "ARM64", "kiln-arm64-8cpu"]);
        assert_eq!(c.job_label(), if platform::ARM64 { "kiln-arm64" } else { "kiln" });
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
    fn repo_cap_rules() {
        let mut c = Config { max_vms_per_repo: 2, ..Config::default() };
        c.repo_max_vms.insert("Acme/Demo".into(), 1);
        c.repo_max_vms.insert("acme/free".into(), 0);
        assert_eq!(c.repo_cap("acme/demo"), Some(1), "override, case-insensitive");
        assert_eq!(c.repo_cap("acme/free"), None, "an override of 0 lifts the cap");
        assert_eq!(c.repo_cap("acme/other"), Some(2));
        assert_eq!(Config::default().repo_cap("acme/demo"), None, "0 = unlimited");
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
    fn a_failed_rebake_is_retried_soon() {
        let cfg = Config::default();
        let t = 1_000_000;
        let last = rebake_last_after_failure(t, 1);
        assert!(!should_rebake(&cfg, true, false, t + 299, last));
        assert!(should_rebake(&cfg, true, false, t + 300, last), "first retry after 5 minutes");
        assert!(should_rebake(&cfg, true, false, t + 600, rebake_last_after_failure(t, 2)));
        assert!(!should_rebake(&cfg, true, false, t + 599, rebake_last_after_failure(t, 2)), "then doubling");
        assert!(
            !should_rebake(&cfg, true, false, t + REBAKE_EVERY - 1, rebake_last_after_failure(t, 40)),
            "never sooner than 6 h at the cap"
        );
        assert!(should_rebake(&cfg, true, false, t + REBAKE_EVERY, rebake_last_after_failure(t, 40)));
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
        assert_eq!(app_refresh_secs(0, false, 0), 30, "never discovered");
        assert_eq!(app_refresh_secs(3, false, 0), 30, "only an old map, never a successful discovery");
        assert_eq!(app_refresh_secs(0, true, 0), 30, "installed nowhere yet: pick up a new install quickly");
        assert_eq!(app_refresh_secs(3, true, 0), 300);
        assert_eq!(
            [1, 2, 3, 6, 50].map(|f| app_refresh_secs(0, false, f)),
            [5, 10, 20, 60, 60],
            "a failure is retried quickly, not after 5 minutes"
        );
    }

    #[test]
    fn github_wide_backoff() {
        // The banner now takes the forge's name; GitHub's text is word for word what it was.
        assert_eq!([1, 2, 3, 4, 9].map(api_backoff_secs), [60, 120, 300, 600, 600]);
        let mut b = ApiBackoff::default();
        assert!(!b.held(0) && b.banner(0, "GitHub").is_none());
        // First failure: pause 1 min, and say so once.
        assert!(b.fail(Some(500), 1000));
        assert!(b.held(1059) && !b.held(1060));
        // A sibling launch of the same batch failing inside the pause neither escalates nor logs again.
        assert!(!b.fail(Some(500), 1001));
        assert_eq!((b.fails, b.retry_at), (1, 1060));
        assert_eq!(
            b.banner(1000, "GitHub").as_deref(),
            Some("GitHub is rejecting runner registration (HTTP 500) — launches paused, retrying in 1 min")
        );
        // Each retry that fails again escalates: 2, 5, then 10 min, capped.
        assert!(b.fail(Some(502), 1060));
        assert_eq!(b.retry_at, 1180);
        assert!(b.fail(Some(500), 1180) && b.fail(None, 1480) && b.fail(None, 2080));
        assert_eq!((b.fails, b.retry_at), (5, 2680));
        assert_eq!(
            b.banner(2081, "GitHub").as_deref(),
            Some("GitHub is unreachable for runner registration — launches paused, retrying in 10 min")
        );
        // Pause over, no new launch yet: still not healthy, but not paused either.
        assert_eq!(
            b.banner(2680, "GitHub").as_deref(),
            Some("GitHub is unreachable for runner registration — retrying with the next launch")
        );
        // The first successful mint clears it.
        b = ApiBackoff::default();
        assert!(!b.held(2680) && b.banner(2680, "GitHub").is_none());
    }

    #[test]
    fn settings_save_keeps_unchanged_forges() {
        let app = App::for_tests();
        let before = app.forges.get(&forge::ForgeId::github()).unwrap();
        let mut c = app.cfg();
        c.repos = vec!["acme/demo".into()];
        c.forges = Some(vec![
            serde_json::from_str(r#"{"id":"github","kind":"github"}"#).unwrap(),
            serde_json::from_str(r#"{"id":"gt","kind":"gitea","url":"https://gitea.example.com"}"#).unwrap(),
            serde_json::from_str(r#"{"id":"gl","kind":"gitlab","url":"https://gitlab.example.com"}"#).unwrap(),
        ]);
        app.save_cfg(c).unwrap();
        // Same client (ETags, rate limits, App tokens) after a save that changed repos and added a forge.
        assert!(Arc::ptr_eq(&before, &app.forges.get(&forge::ForgeId::github()).unwrap()));
        assert!(app.forges.get(&forge::ForgeId::new("gt").unwrap()).is_some());
        let gl = app.forges.get(&forge::ForgeId::new("gl").unwrap()).unwrap();
        assert_eq!(app.forges.all().len(), 3);
        // A save that leaves it alone keeps the same client (its project-id and fork caches).
        let c = app.cfg();
        app.save_cfg(c).unwrap();
        assert!(Arc::ptr_eq(&gl, &app.forges.get(&forge::ForgeId::new("gl").unwrap()).unwrap()));
        let mut c = app.cfg();
        c.forges = None;
        app.save_cfg(c).unwrap();
        assert!(Arc::ptr_eq(&before, &app.forges.get(&forge::ForgeId::github()).unwrap()));
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
    fn stop_waits_for_running_jobs_only() {
        use vm::State::*;
        for s in [Booting, Idle, Busy] {
            assert!(stop_waits_for(s), "{s:?}");
        }
        for s in [Held, Done, Failed, Killed, Lost, Unneeded] {
            assert!(!stop_waits_for(s), "{s:?}");
        }
        assert_eq!(Config::default().stop_grace_secs, 25);
        assert!(Config { stop_grace_secs: 0, ..Config::default() }.validate_for(8).is_ok());
        // 600 s unit timeout minus ~30 s of cleanup
        assert!(Config { stop_grace_secs: 570, ..Config::default() }.validate_for(8).is_ok());
        assert!(Config { stop_grace_secs: 571, ..Config::default() }.validate_for(8).is_err());
    }

    #[test]
    fn unit_stop_timeout_clamps_the_grace() {
        assert_eq!(parse_timespan("30s"), Some(30));
        assert_eq!(parse_timespan("10min"), Some(600));
        assert_eq!(parse_timespan("1min 30s"), Some(90));
        assert_eq!(parse_timespan("1h 2min"), Some(3720));
        assert_eq!(parse_timespan("1min 500ms"), Some(60));
        assert_eq!(parse_timespan("infinity"), Some(u64::MAX));
        for bad in ["", "abc", "30", "5parsecs", "s"] {
            assert_eq!(parse_timespan(bad), None, "{bad}");
        }
        assert_eq!(unit_timeout("LoadState=loaded\nTimeoutStopUSec=30s\n"), Some(30));
        assert_eq!(unit_timeout("TimeoutStopUSec=10min\nLoadState=loaded\n"), Some(600));
        assert_eq!(unit_timeout("LoadState=not-found\nTimeoutStopUSec=1min 30s\n"), None, "no kiln unit");
        assert_eq!(unit_timeout(""), None);
        assert_eq!(clamp_grace(25, None), 25, "not under systemd");
        assert_eq!(clamp_grace(25, Some(600)), 25);
        assert_eq!(clamp_grace(570, Some(600)), 570);
        assert_eq!(clamp_grace(570, Some(30)), 5, "an old 30 s unit");
        assert_eq!(clamp_grace(25, Some(10)), 0);
        assert_eq!(clamp_grace(570, Some(u64::MAX)), 570);
    }

    #[test]
    fn poll_pacing() {
        assert_eq!(poll_sleep(5, None), 5);
        assert_eq!(poll_sleep(5, Some((1000, 5000, 0))), 5);
        assert_eq!(poll_sleep(5, Some((999, 5000, 0))), 30);
        assert_eq!(poll_sleep(1, Some((5000, 5000, 0))), 3);
    }
}
