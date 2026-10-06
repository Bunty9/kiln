mod github;
mod vm;
mod web;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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
    /// Tailnet login names allowed to use the dashboard. Empty = anyone on the tailnet.
    pub allowed_users: Vec<String>,
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
            poll_secs: 10,
            job_timeout_mins: 60,
            idle_timeout_mins: 10,
            allowed_users: vec![],
        }
    }
}

impl Config {
    pub fn runner_labels(&self) -> Vec<String> {
        vec!["self-hosted".into(), "linux".into(), "x64".into(), self.label.clone()]
    }

    pub fn validate(&self) -> Result<()> {
        for r in &self.repos {
            let ok = r.split('/').count() == 2
                && r.split('/').all(|p| {
                    !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                });
            if !ok {
                bail!("repo must look like owner/name: {r:?}");
            }
        }
        if self.label.is_empty() || self.max_vms == 0 || self.vm_cpus == 0 || self.vm_mem_mb < 1024 {
            bail!("label must be set, max_vms/vm_cpus >= 1, vm_mem_mb >= 1024");
        }
        Ok(())
    }
}

#[derive(Serialize, Default, Clone)]
pub struct PollStatus {
    pub last_ok: Option<u64>,
    pub error: Option<String>,
    pub queued: HashMap<String, usize>,
}

pub struct App {
    pub data: PathBuf,
    pub cfg: RwLock<Config>,
    pub gh: github::Gh,
    pub vms: Mutex<Vec<vm::Vm>>,
    pub kills: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    pub poll: Mutex<PollStatus>,
    pub baking: std::sync::atomic::AtomicBool,
}

impl App {
    pub fn cfg(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    pub fn save_cfg(&self, c: Config) -> Result<()> {
        c.validate()?;
        std::fs::write(self.data.join("config.json"), serde_json::to_vec_pretty(&c)?)?;
        *self.cfg.write().unwrap() = c;
        Ok(())
    }

    pub fn save_token(&self, t: String) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.data.join("token"))?;
        std::io::Write::write_all(&mut f, t.trim().as_bytes())?;
        self.gh.set_token(t.trim().to_string());
        Ok(())
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Env var, then the token file the dashboard writes, then the gh CLI login.
fn load_token(data: &std::path::Path) -> String {
    for k in ["KILN_GITHUB_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(t) = std::env::var(k)
            && !t.is_empty() {
                return t;
            }
    }
    if let Ok(t) = std::fs::read_to_string(data.join("token")) {
        return t.trim().to_string();
    }
    std::process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let data = std::env::var_os("KILN_DATA").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/kiln")
    });
    std::fs::create_dir_all(data.join("vms"))?;
    std::fs::create_dir_all(data.join("images"))?;
    let cfg: Config = match std::fs::read(data.join("config.json")) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => Config::default(),
    };
    let app = Arc::new(App {
        gh: github::Gh::new(load_token(&data)),
        cfg: RwLock::new(cfg),
        vms: Mutex::new(vm::load_history(&data)),
        data,
        kills: Mutex::default(),
        poll: Mutex::default(),
        baking: Default::default(),
    });

    match std::env::args().nth(1).as_deref() {
        Some("bake") => vm::bake(app).await,
        Some("serve") | None => {
            tokio::spawn(scheduler(app.clone()));
            web::serve(app).await
        }
        _ => {
            eprintln!("usage: kiln [serve|bake]\n  serve  run scheduler + dashboard (default)\n  bake   build the base VM image");
            std::process::exit(2)
        }
    }
}

async fn scheduler(app: Arc<App>) {
    loop {
        let cfg = app.cfg();
        let res = tick(&app, &cfg).await;
        {
            let mut p = app.poll.lock().unwrap();
            match res {
                Ok(q) => {
                    p.last_ok = Some(now());
                    p.error = None;
                    p.queued = q;
                }
                Err(e) => p.error = Some(format!("{e:#}")),
            }
        }
        tokio::time::sleep(Duration::from_secs(cfg.poll_secs.max(3))).await;
    }
}

/// One poll: per repo, boot as many VMs as there are queued jobs not already
/// covered by a VM that is booting or idle. A JIT runner may take any queued
/// job with matching labels, not necessarily the one that triggered it, so we
/// match on counts, never on job ids.
async fn tick(app: &Arc<App>, cfg: &Config) -> Result<HashMap<String, usize>> {
    if !app.gh.has_token() {
        bail!("no GitHub token: set one in the dashboard, export KILN_GITHUB_TOKEN, or `gh auth login`");
    }
    if !vm::image_ready(&app.data) {
        bail!("base image not baked yet: run `kiln bake` or use the dashboard");
    }
    let mut queued_by_repo = HashMap::new();
    let mut errors = vec![];
    for repo in &cfg.repos {
        let queued = match app.gh.queued_jobs(repo, &cfg.runner_labels()).await {
            Ok(q) => q.len(),
            Err(e) => {
                errors.push(format!("{repo}: {e:#}"));
                continue;
            }
        };
        queued_by_repo.insert(repo.clone(), queued);
        let (waiting, active) = {
            let vms = app.vms.lock().unwrap();
            let waiting = vms.iter().filter(|v| &v.repo == repo && v.state.is_waiting()).count();
            (waiting, vms.iter().filter(|v| v.state.is_active()).count())
        };
        let want = queued.saturating_sub(waiting).min(cfg.max_vms.saturating_sub(active));
        for _ in 0..want {
            vm::launch(app.clone(), repo.clone());
        }
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(queued_by_repo)
}
