//! Job VMs: one throwaway QEMU/KVM guest per GitHub Actions job.
//!
//! Rootless by design: KVM access + QEMU user-mode networking, no tap devices,
//! no bridges, no sudo. Each job boots a qcow2 overlay of the baked base image,
//! so the base never changes and a job's writes vanish with its overlay.

use crate::{App, host, now};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Booting,
    Idle,
    Busy,
    Done,
    Failed,
    Killed,
    /// Job failed; the guest is kept alive for SSH until `hold_until`.
    Held,
    /// Was active when kiln stopped; its QEMU died with us.
    Lost,
}

impl State {
    /// Will take the next queued job without us launching another VM.
    pub fn is_waiting(self) -> bool {
        matches!(self, State::Booting | State::Idle)
    }
    pub fn is_active(self) -> bool {
        matches!(self, State::Booting | State::Idle | State::Busy | State::Held)
    }
}

/// What this VM's cache disk did.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheUse {
    #[default]
    None,
    /// Attached as a throwaway overlay.
    Read,
    Committed,
    Discarded,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Vm {
    pub id: String,
    pub repo: String,
    pub runner_id: Option<u64>,
    pub state: State,
    pub job: Option<String>,
    pub result: Option<String>,
    #[serde(default)]
    pub job_url: Option<String>,
    /// When GitHub queued the job this VM's runner picked up.
    #[serde(default)]
    pub queued_at: Option<u64>,
    pub started: u64,
    /// The runner said "Listening for Jobs".
    #[serde(default)]
    pub online_at: Option<u64>,
    pub busy_since: Option<u64>,
    pub ended: Option<u64>,
    pub note: Option<String>,
    /// Size this VM was booted with (0 in records from before size labels).
    #[serde(default)]
    pub cpus: u32,
    #[serde(default)]
    pub mem_mb: u32,
    #[serde(default)]
    pub cache: CacheUse,
    /// Why the cache was not saved.
    #[serde(default)]
    pub cache_note: Option<String>,
    /// Held VMs: `ssh -p N runner@host`, and when the hold ends.
    #[serde(default)]
    pub ssh: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub hold_until: Option<u64>,
    /// Host key fingerprints the held guest printed (first 4), to verify before trusting the login.
    #[serde(default)]
    pub ssh_hostkeys: Vec<String>,
    /// Job network this VM booted with: "open" | "filtered" ("" in older records).
    #[serde(default)]
    pub egress: String,
    /// Fingerprint of the security settings baked in at boot (see `policy_id`).
    #[serde(default)]
    pub policy: String,
    /// Launched to fill the warm pool; cleared once it takes a job.
    #[serde(default)]
    pub warm: bool,
}

impl Vm {
    /// Holds off `auto_update`: a job (or a demand VM about to take one) or a debug hold.
    /// Idle warm VMs do not: the drain reaps them.
    pub fn blocks_auto_update(&self) -> bool {
        match self.state {
            State::Busy | State::Held => true,
            State::Booting | State::Idle => !self.warm || self.job_url.is_some(),
            _ => false,
        }
    }
}

const KEEP_HISTORY: usize = 200;
/// console.log and steps.log stop growing here (parsing continues).
const LOG_CAP: usize = 64 << 20;
/// Longest console line kept in memory; a guest can print forever without a newline.
const LINE_CAP: u64 = 64 << 10;

pub fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("bad vm id");
    }
    Ok(())
}

fn images(data: &Path) -> PathBuf {
    data.join("images")
}

pub fn image_ready(data: &Path) -> bool {
    images(data).join("base.qcow2").exists() && images(data).join("base.vmlinuz").exists()
}

pub fn load_history(data: &Path) -> Vec<Vm> {
    let mut vms: Vec<Vm> = std::fs::read_dir(data.join("vms"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path().join("meta.json")).ok()?).ok())
        .collect();
    for v in &mut vms {
        if v.state.is_active() {
            v.state = State::Lost;
            v.ended.get_or_insert(v.started);
            // The crash skipped the normal cleanup: don't leave a disk or a credential behind.
            let dir = data.join("vms").join(&v.id);
            let _ = std::fs::remove_file(dir.join("disk.qcow2"));
            let _ = std::fs::remove_file(dir.join("cache.qcow2"));
            let _ = std::fs::remove_file(dir.join("jit"));
            write_meta(data, v);
        }
    }
    vms.sort_by_key(|v| v.started);
    vms
}

fn update(app: &App, id: &str, f: impl FnOnce(&mut Vm)) -> Option<Vm> {
    let mut vms = app.vms.lock().unwrap();
    let v = vms.iter_mut().find(|v| v.id == id)?;
    f(v);
    Some(v.clone())
}

fn write_meta(data: &Path, v: &Vm) {
    let path = data.join("vms").join(&v.id).join("meta.json");
    if let Err(e) = std::fs::write(&path, serde_json::to_vec_pretty(v).unwrap_or_default()) {
        tracing::warn!("write {}: {e}", path.display());
    }
}

pub fn persist(app: &App, v: &Vm) {
    write_meta(&app.data, v);
}

/// Seconds to keep a repo's launches paused after `fails` consecutive failures.
fn backoff_secs(fails: u32) -> u64 {
    (30u64 << fails.min(5)).min(900)
}

/// Register the VM synchronously (so the next scheduler tick counts it), then
/// boot it in the background.
pub fn launch(app: Arc<App>, repo: String, cpus: u32, warm: bool) {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = format!("kiln-{}-{seq}", now());
    let vm = Vm {
        id: id.clone(),
        repo: repo.clone(),
        runner_id: None,
        state: State::Booting,
        job: None,
        result: None,
        job_url: None,
        queued_at: None,
        started: now(),
        online_at: None,
        busy_since: None,
        ended: None,
        note: None,
        cpus,
        mem_mb: app.cfg().mem_mb(cpus),
        cache: CacheUse::None,
        cache_note: None,
        ssh: None,
        ssh_port: None,
        hold_until: None,
        ssh_hostkeys: vec![],
        egress: app.cfg().egress,
        policy: policy_id(&app.cfg()),
        warm,
    };
    // Registered before the task starts so Kill and shutdown also work during JIT/qemu-img.
    let kill = Arc::new(tokio::sync::Notify::new());
    app.kills.lock().unwrap().insert(id.clone(), kill.clone());
    let release = Arc::new(tokio::sync::Notify::new());
    app.releases.lock().unwrap().insert(id.clone(), release.clone());
    app.vms.lock().unwrap().push(vm);
    tokio::spawn(async move {
        let dir = app.data.join("vms").join(&id);
        let outcome = run(&app, &id, &repo, &dir, &kill, &release).await;
        finish_cache(&app, &id, &repo, &dir, matches!(outcome, Ok(State::Done))).await;
        // Never leave a big overlay or a credential behind, whatever happened.
        let _ = tokio::fs::remove_file(dir.join("disk.qcow2")).await;
        let _ = tokio::fs::remove_file(dir.join("jit")).await;
        let _ = tokio::fs::remove_file(dir.join("egress.nft")).await;
        let _ = tokio::fs::remove_file(dir.join("steps.sock")).await;
        let _ = tokio::fs::remove_file(dir.join("mon.sock")).await;
        let _ = tokio::fs::remove_dir_all(dir.join("rk")).await;
        let v = update(&app, &id, |v| {
            v.ended = Some(now());
            v.state = match outcome {
                Ok(s) => s,
                Err(e) => {
                    v.note = Some(format!("{e:#}"));
                    State::Failed
                }
            };
            // Failed means kiln or the host broke; a job's own verdict is Done.
            if v.result.is_some() {
                v.state = State::Done;
            }
        });
        if let Some(v) = v {
            tracing::info!("{} {:?} job={:?} result={:?}", v.id, v.state, v.job, v.result);
            {
                let mut b = app.backoff.lock().unwrap();
                if v.job.is_some() {
                    b.remove(&v.repo);
                } else if v.state == State::Failed {
                    let e = b.entry(v.repo.clone()).or_default();
                    e.0 += 1;
                    e.1 = now() + backoff_secs(e.0);
                }
            }
            // A JIT runner that never ran a job stays registered (offline) on GitHub.
            if let (Some(rid), None) = (v.runner_id, &v.job)
                && let Err(e) = app.gh.delete_runner(&v.repo, rid).await
            {
                tracing::warn!("{}: {e:#}", v.id);
            }
            persist(&app, &v);
        }
        // Last: shutdown waits on `kills` to know cleanup is complete.
        app.releases.lock().unwrap().remove(&id);
        app.kills.lock().unwrap().remove(&id);
        prune(&app);
    });
}

/// Idle VMs of `repo` and size `cpus` (online for 30s+, oldest first) that
/// could be dropped: returns up to `n` of (vm id, runner id).
fn reap_candidates(vms: &[Vm], repo: &str, cpus: u32, n: usize, t: u64) -> Vec<(String, u64)> {
    let mut c: Vec<_> = vms
        .iter()
        .filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.cpus == cpus && v.state == State::Idle && v.job_url.is_none())
        .filter_map(|v| Some((v.online_at.filter(|&o| o + 30 < t)?, v.id.clone(), v.runner_id?)))
        .collect();
    c.sort();
    c.into_iter().take(n).map(|(_, id, rid)| (id, rid)).collect()
}

/// Kill up to `n` surplus idle VMs. Deregistering the runner is the arbiter:
/// if GitHub refuses (422), the runner just got a job and must live.
pub async fn reap(app: &App, repo: &str, cpus: u32, n: usize) {
    let c = reap_candidates(&app.vms.lock().unwrap(), repo, cpus, n, now());
    drop_idle(app, repo, c, "no job left for this runner").await;
}

async fn drop_idle(app: &App, repo: &str, c: Vec<(String, u64)>, why: &str) {
    for (id, rid) in c {
        if app.gh.delete_runner(repo, rid).await.is_err() {
            continue;
        }
        note(app, &id, why);
        if let Some(k) = app.kills.lock().unwrap().get(&id) {
            k.notify_one();
        }
    }
}

/// (demand launches, warm launches) for one repo at the default size: demand is
/// queued jobs no waiting VM covers; warm tops the waiting VMs up to queued + target.
pub fn launch_split(queued: usize, waiting: usize, target: usize) -> (usize, usize) {
    (queued.saturating_sub(waiting), if waiting >= queued { target.saturating_sub(waiting - queued) } else { target })
}

/// Waiting VMs beyond demand and the warm target.
pub fn surplus(waiting: usize, queued: usize, target: usize) -> usize {
    waiting.saturating_sub(queued + target)
}

/// Idle VMs to recycle: warm ones online longer than `recycle_secs` (so they never go
/// stale), and, with a cache commit parked while only idle job-less VMs still read the
/// cache, all of those (warm or a leftover from a burst; they would block the commit).
fn recycle_candidates(vms: &[Vm], repo: &str, recycle_secs: u64, t: u64, pending: bool) -> Vec<(String, u64)> {
    let mine = |v: &&Vm| v.repo.eq_ignore_ascii_case(repo);
    let idle_free = |v: &Vm| v.state == State::Idle && v.job_url.is_none();
    let mut readers = vms.iter().filter(mine).filter(|v| v.state.is_active() && v.cache == CacheUse::Read).peekable();
    let flush = pending && readers.peek().is_some() && readers.all(&idle_free);
    vms.iter()
        .filter(mine)
        .filter(|v| idle_free(v) && ((v.warm && v.online_at.is_some_and(|o| o + recycle_secs < t)) || (flush && v.cache == CacheUse::Read)))
        .filter_map(|v| Some((v.id.clone(), v.runner_id?)))
        .collect()
}

/// The settings a VM fixes at boot and that must never be stale when it takes a job:
/// egress mode, the SSH keys it would accept, and whether failures are held.
pub fn policy_id(cfg: &crate::Config) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (&cfg.egress, &cfg.debug_ssh_keys, cfg.debug_hold_mins > 0).hash(&mut h);
    format!("{}-{:x}", cfg.egress, h.finish())
}

/// Idle job-less VMs booted under older security settings than the current ones:
/// e.g. an open-egress VM must never pick up a job after egress was switched to
/// filtered, nor a VM holding an SSH key that was since removed.
fn stale_policy(vms: &[Vm], repo: &str, policy: &str) -> Vec<(String, u64)> {
    vms.iter()
        .filter(|v| v.repo.eq_ignore_ascii_case(repo) && v.state == State::Idle && v.job_url.is_none() && v.policy != policy)
        .filter_map(|v| Some((v.id.clone(), v.runner_id?)))
        .collect()
}

pub async fn recycle_stale_policy(app: &App, repo: &str, policy: &str) {
    let c = stale_policy(&app.vms.lock().unwrap(), repo, policy);
    drop_idle(app, repo, c, "recycled: security settings changed").await;
}

pub async fn recycle_warm(app: &App, repo: &str, recycle_mins: u64) {
    let pending = pending_file(&app.data, repo).exists();
    let c = recycle_candidates(&app.vms.lock().unwrap(), repo, recycle_mins * 60, now(), pending);
    drop_idle(app, repo, c, "recycled warm VM").await;
}

/// A cache commit for `repo` is running or parked: warm VMs wait for it so they boot on the new cache.
pub fn cache_busy(app: &App, repo: &str) -> bool {
    pending_file(&app.data, repo).exists() || app.committing.lock().unwrap().contains(&repo.to_ascii_lowercase())
}

/// The state the VM ends in (Killed, Failed or Done); Err = infrastructure failure.
async fn run(app: &Arc<App>, id: &str, repo: &str, dir: &Path, kill: &tokio::sync::Notify, release: &tokio::sync::Notify) -> Result<State> {
    let cfg = app.cfg();
    tokio::fs::create_dir_all(dir).await?;
    if let Some(v) = update(app, id, |_| {}) {
        persist(app, &v);
    }

    let v = update(app, id, |_| {}).context("vm vanished")?;
    let (cpus, mem_mb) = (v.cpus, v.mem_mb);
    let (runner_id, jit) = app.gh.jit_config(repo, id, &cfg.runner_labels(cpus)).await?;
    if let Some(v) = update(app, id, |v| v.runner_id = Some(runner_id)) {
        persist(app, &v);
    }
    // Handed over as a file QEMU reads at start (fw_cfg, plus SMBIOS on x86: see job_args).
    write_secret(&dir.join("jit"), &format!("kiln.jit={jit}")).await?;

    let base = images(&app.data).join("base.qcow2");
    let disk = dir.join("disk.qcow2");
    let out = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(&base)
        .arg(&disk)
        .output()
        .await
        .context("qemu-img")?;
    if !out.status.success() {
        bail!("qemu-img create: {}", String::from_utf8_lossy(&out.stderr));
    }
    if tokio::time::timeout(Duration::ZERO, kill.notified()).await.is_ok() {
        kill_note(app, id);
        return Ok(State::Killed);
    }

    // Cache overlay (second disk, so root stays /dev/vda1) and the debug SSH forward.
    let cache_ov = if cfg.cache { setup_cache(app, id, repo, dir, cfg.cache_gb_for(repo)).await } else { None };
    let filtered = v.egress == "filtered";
    let mut ssh_host = None;
    let mut fwd = String::new();
    let publish = if !filtered {
        Publish::Monitor
    } else if host::which("rootlessctl") {
        Publish::Rootless
    } else {
        Publish::Static
    };
    if cfg.debug_hold_mins > 0 && !cfg.debug_ssh_keys.is_empty() {
        let ip = bind_ip().await;
        if let Some(port) = pick_port(app, id, &ip) {
            // The port is only reserved here; it is published when the VM is held (publish_ssh),
            // so a running job cannot even connect to it.
            // Filtered: QEMU runs in a private netns, so its hostfwd binds there, not on the
            // host; rootlesskit's port driver publishes host <ip>:<port> into the netns, at hold
            // time via rootlessctl (QEMU listens on all netns addresses: the driver dials the
            // netns loopback). Without rootlessctl, `-p` publishes it from the start.
            // Open: hostfwd_add through the QEMU monitor at hold time.
            if filtered {
                fwd = format!(",hostfwd=tcp::{port}-:22");
            }
            write_secret(&dir.join("ssh"), &format!("kiln.ssh={}", b64(cfg.debug_ssh_keys.join("\n").as_bytes()))).await?;
            ssh_host = Some((ip, port));
        } else {
            note(app, id, "no free ssh port (2200-2299): this VM will not be held");
        }
    }
    if filtered {
        fwd.push_str(",ipv6=off");
    }
    let mut cmd = qemu(&GUEST, cpus, mem_mb, &disk, &fwd);
    if let Some(ov) = &cache_ov {
        cmd.arg("-drive").arg(format!("file={},if=virtio,format=qcow2,cache=unsafe,discard=unmap", ov.display()));
    }
    // Direct kernel boot without initrd: virtio + ext4 are built into the
    // Ubuntu kernel, which brings boot-to-runner down to ~4s.
    cmd.arg("-kernel").arg(images(&app.data).join("base.vmlinuz"));
    cmd.args(job_args(&GUEST, dir, ssh_host.is_some()));
    if ssh_host.is_some() && publish == Publish::Monitor {
        cmd.arg("-monitor").arg(format!("unix:{},server=on,wait=off", dir.join("mon.sock").display()));
    }
    if filtered {
        tokio::fs::write(dir.join("egress.nft"), egress_nft(cfg.docker_mirror)).await?;
        let std = cmd.as_std();
        let q: Vec<String> = std::iter::once(std.get_program()).chain(std.get_args()).map(|a| a.to_string_lossy().into_owned()).collect();
        let mut rk = Command::new("rootlesskit");
        let stat = ssh_host.as_ref().filter(|_| publish == Publish::Static);
        rk.args(rk_args(dir, stat.map(|(ip, p)| (ip.as_str(), *p)), &q)).kill_on_drop(true);
        cmd = rk;
    }
    let console = tokio::fs::File::create(dir.join("console.log")).await?;
    if filtered {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(console.into_std().await);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let steps = tokio::fs::File::create(dir.join("steps.log")).await?;
    let mut child =
        cmd.spawn().with_context(|| if filtered { "spawning rootlesskit".into() } else { format!("spawning {}", GUEST.qemu) })?;
    if let Some(err) = child.stderr.take() {
        // rootlesskit warns on every start that we keep host loopback; we do on purpose
        // (the mirror), and nft blocks every other loopback port. Keep the rest.
        let path = dir.join("console.log");
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if !l.contains("--disable-host-loopback is highly recommended") {
                    let _ = append(&path, &format!("{l}\n")).await;
                }
            }
        });
    }

    tokio::spawn(copy_steps(dir.join("steps.sock"), steps));
    let mut log = tokio::fs::OpenOptions::new().append(true).open(dir.join("console.log")).await?;
    let mut stdin = child.stdin.take();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut buf = Vec::new();
    let (mut first, mut logged, mut decided, mut cont) = (true, 0, false, false);
    // A job is root in its VM and can write anything to the console, so console lines
    // may shape the timeline but never extend the VM's life past this hard cap.
    let hard_cap = start_cap(&cfg, v.warm);
    loop {
        // Idle VMs are reaped quickly; busy ones get the full job timeout.
        let v = update(app, id, |_| {}).context("vm vanished")?;
        let deadline = match (v.state, v.busy_since) {
            // The guest powers itself off at hold end; this is only the safety net.
            (State::Held, _) => v.hold_until.unwrap_or_else(now) + 60,
            (_, Some(t)) => t + cfg.job_timeout_mins * 60,
            // ponytail: an online warm VM waits warm_recycle_mins + 5 for the reaper's recycle first.
            _ if v.warm && v.online_at.is_some() => v.started + (cfg.warm_recycle_mins + 5) * 60,
            _ => v.started + cfg.idle_timeout_mins * 60,
        }
        .min(v.started + hard_cap);
        let left = Duration::from_secs(deadline.saturating_sub(now()));
        buf.clear();
        tokio::select! {
            r = read_capped(&mut lines, &mut buf) => {
                if r? == 0 {
                    break; // guest powered off, QEMU closed stdout
                }
                if first {
                    // QEMU read the secret files at start, before the guest printed anything.
                    first = false;
                    let _ = tokio::fs::remove_file(dir.join("jit")).await;
                    let _ = tokio::fs::remove_file(dir.join("ssh")).await;
                }
                if logged < LOG_CAP {
                    log.write_all(&buf).await?;
                    logged += buf.len();
                }
                // A line cut at LINE_CAP and its remainder are never parsed: no marker hides in them.
                let was_cont = std::mem::replace(&mut cont, buf.len() as u64 >= LINE_CAP && !buf.ends_with(b"\n"));
                if was_cont || cont {
                    continue;
                }
                let text = String::from_utf8_lossy(&buf);
                observe(app, id, &text);
                if text.contains("kiln: decide") && !std::mem::replace(&mut decided, true) {
                    let v = update(app, id, |_| {}).context("vm vanished")?;
                    let mut hold = decide(cfg.debug_hold_mins, ssh_host.is_some(), v.job.is_some(), v.result.as_deref());
                    if let (Some(_), Some((ip, port))) = (hold, &ssh_host)
                        && let Err(e) = publish_ssh(dir, publish, ip, *port).await
                    {
                        // No way in after all: a hold nobody can reach is just a leak.
                        note(app, id, &format!("ssh forward failed, VM released instead of held: {e:#}"));
                        hold = None;
                    }
                    if let (Some(secs), Some((ip, port))) = (hold, &ssh_host) {
                        let v = update(app, id, |v| {
                            v.state = State::Held;
                            v.hold_until = Some(now() + secs);
                            v.ssh = Some(format!("ssh -p {port} runner@{ip}"));
                            v.ssh_port = Some(*port);
                        });
                        if let Some(v) = v {
                            persist(app, &v);
                        }
                    }
                    send(&mut stdin, &decide_msg(hold)).await;
                }
            }
            _ = release.notified() => send(&mut stdin, "release\n").await,
            _ = kill.notified() => {
                if update(app, id, |_| {}).is_some_and(|v| v.state == State::Held) {
                    // Ask nicely so the guest powers off cleanly; QEMU dies anyway after 5s.
                    send(&mut stdin, "release\n").await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                }
                child.kill().await.ok();
                kill_note(app, id);
                return Ok(State::Killed);
            }
            _ = tokio::time::sleep(left) => {
                child.kill().await.ok();
                if v.state == State::Held {
                    note(app, id, "debug hold expired");
                    return Ok(State::Killed);
                } else if v.busy_since.is_some() {
                    note(app, id, &format!("job timeout after {} min", cfg.job_timeout_mins));
                    return Ok(State::Killed);
                } else if v.online_at.is_some() {
                    note(app, id, "idle timeout: no job arrived");
                    return Ok(State::Killed);
                }
                note(app, id, "boot timeout: runner never came online");
                return Ok(State::Failed);
            }
        }
    }
    let status = child.wait().await?;
    if !status.success() {
        bail!("qemu exited with {status}; see console log");
    }
    if update(app, id, |_| {}).context("vm vanished")?.result.is_none() {
        note(app, id, "runner exited without a result");
        return Ok(State::Failed);
    }
    Ok(State::Done)
}

async fn send(stdin: &mut Option<tokio::process::ChildStdin>, msg: &str) {
    if let Some(s) = stdin {
        let _ = s.write_all(msg.as_bytes()).await;
        let _ = s.flush().await;
    }
}

/// Seconds to hold the VM, if at all. Only a job that started and ended with a
/// verdict other than success is worth keeping, and only when there is a way in.
/// The guest asking early (no verdict yet) is answered "release", so a job
/// cannot force a hold by printing `kiln: decide` itself.
fn decide(hold_mins: u64, can_ssh: bool, job_started: bool, result: Option<&str>) -> Option<u64> {
    (hold_mins > 0 && can_ssh && job_started && result.is_some_and(|r| r != "Succeeded")).then_some(hold_mins * 60)
}

/// How a held VM's SSH port reaches the host.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Publish {
    /// Open egress: `hostfwd_add` through the QEMU monitor.
    Monitor,
    /// Filtered: `rootlessctl add-ports` on the rootlesskit API.
    Rootless,
    /// Filtered without rootlessctl: `-p` at launch, so the port is open for the whole VM life.
    Static,
}

/// Open the SSH port on the host; Err = hold is pointless.
async fn publish_ssh(dir: &Path, how: Publish, ip: &str, port: u16) -> Result<()> {
    match how {
        Publish::Static => Ok(()),
        Publish::Rootless => {
            let o = Command::new("rootlessctl")
                .arg("--socket")
                .arg(dir.join("rk/api.sock"))
                .arg("add-ports")
                .arg(format!("{ip}:{port}:127.0.0.1:{port}/tcp"))
                .output()
                .await
                .context("rootlessctl")?;
            if !o.status.success() {
                bail!("rootlessctl: {}", String::from_utf8_lossy(&o.stderr).trim());
            }
            Ok(())
        }
        Publish::Monitor => {
            let mut s = tokio::net::UnixStream::connect(dir.join("mon.sock")).await.context("qemu monitor")?;
            s.write_all(format!("hostfwd_add n0 tcp:{ip}:{port}-:22\n").as_bytes()).await?;
            // HMP is silent on success and prints the error otherwise; wait briefly for either.
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                let mut b = [0u8; 512];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || out.len() > 4096 {
                        break;
                    }
                    out.extend_from_slice(&b[..n]);
                }
            })
            .await;
            let out = String::from_utf8_lossy(&out);
            if hmp_failed(&out) {
                bail!(
                    "hostfwd_add: {}",
                    out.lines().rev().find(|l| l.contains("Could not") || l.contains("rror")).unwrap_or("failed").trim()
                );
            }
            Ok(())
        }
    }
}

/// One line, at most LINE_CAP bytes (0 = EOF; hitting the cap returns >0 without a newline).
async fn read_capped(r: &mut (impl AsyncBufReadExt + Unpin), buf: &mut Vec<u8>) -> std::io::Result<usize> {
    r.take(LINE_CAP).read_until(b'\n', buf).await
}

fn hmp_failed(out: &str) -> bool {
    out.contains("Could not") || out.contains("rror")
}

/// Copy the guest's steps channel (ttyS1, or a virtio-serial port on arm64; QEMU serves it
/// on a unix socket) into steps.log, capped like console.log. Reads in 64 KiB chunks, so a flood costs disk up to LOG_CAP and no memory.
async fn copy_steps(sock: PathBuf, mut out: tokio::fs::File) {
    let mut s = None;
    // QEMU creates the socket at start; in filtered mode that is after rootlesskit's setup.
    for _ in 0..100 {
        if let Ok(c) = tokio::net::UnixStream::connect(&sock).await {
            s = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let Some(mut s) = s else { return };
    let (mut buf, mut logged) = (vec![0u8; 64 << 10], 0);
    while let Ok(n @ 1..) = s.read(&mut buf).await {
        let k = room(logged, n);
        if k > 0 && out.write_all(&buf[..k]).await.is_err() {
            return;
        }
        logged += k;
    }
}

/// How many of `n` new bytes still fit under LOG_CAP.
fn room(logged: usize, n: usize) -> usize {
    n.min(LOG_CAP.saturating_sub(logged))
}

fn decide_msg(hold: Option<u64>) -> String {
    hold.map_or("release\n".into(), |s| format!("hold {s}\n"))
}

/// First free port of 2200..2300 that no active VM owns and the host can bind.
fn alloc_port(used: &[u16], bindable: impl Fn(u16) -> bool) -> Option<u16> {
    (2200..2300).find(|p| !used.contains(p) && bindable(*p))
}

/// Reserve a port for `id` under the `vms` lock, so concurrent launches get different ones.
fn pick_port(app: &App, id: &str, ip: &str) -> Option<u16> {
    let mut vms = app.vms.lock().unwrap();
    let used: Vec<u16> = vms.iter().filter(|v| v.state.is_active()).filter_map(|v| v.ssh_port).collect();
    let port = alloc_port(&used, |p| std::net::TcpListener::bind((ip, p)).is_ok())?;
    // Not Held yet, but taken: a later launch must not pick it.
    vms.iter_mut().find(|v| v.id == id)?.ssh_port = Some(port);
    Some(port)
}

/// The tailnet IP, so held VMs are not reachable from the LAN; loopback if unknown.
async fn bind_ip() -> String {
    tailnet_ip().await.unwrap_or("127.0.0.1".into())
}

async fn tailnet_ip() -> Option<String> {
    let out = output(host::tailscale(), &["ip", "-4"]).await.unwrap_or_default();
    out.lines().next().map(str::trim).filter(|l| l.parse::<std::net::Ipv4Addr>().is_ok()).map(String::from)
}

/// Public keys only, but a guest-side authorized_keys line: one line, known type.
pub fn valid_ssh_key(k: &str) -> bool {
    let k = k.trim();
    ["ssh-", "ecdsa-", "sk-"].iter().any(|p| k.starts_with(p)) && k.contains(' ') && !k.chars().any(|c| c.is_control())
}

/// Standard base64; the guest decodes with `base64 -d`. (No crate for 10 lines.)
pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    data.chunks(3)
        .flat_map(|c| {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            (0..4).map(move |i| if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' })
        })
        .collect()
}

// ---------------------------------------------------------------- repo cache
//
// Trusted writer, throwaway readers: every job VM gets a private qcow2 overlay
// of its repo's cache disk, so any job starts warm. Only a successful `push`
// to the default branch (or a configured cache branch) may merge its overlay back, so PRs and other branches
// read the cache but can never poison it (GitHub's branch-scope rule for
// actions/cache, kept on a disk).

pub fn cache_file(data: &Path, repo: &str) -> PathBuf {
    data.join("cache").join(format!("{}.qcow2", repo.to_ascii_lowercase().replace('/', "__")))
}

/// Bytes actually allocated (like `du`), not the virtual size.
fn disk_bytes(p: &Path) -> u64 {
    std::fs::metadata(p).map_or(0, |m| m.blocks() * 512)
}

/// Over 1.2x the configured size: reset instead of growing forever.
fn cache_too_big(bytes: u64, gb: u32) -> bool {
    bytes > gb as u64 * (6u64 << 30) / 5
}

pub fn cache_dir_mb(data: &Path) -> u64 {
    let d = std::fs::read_dir(data.join("cache")).into_iter().flatten().flatten();
    d.map(|e| disk_bytes(&e.path())).sum::<u64>() >> 20
}

/// `caches` of /api/state: {"o/n": {"size_mb", "updated"}} for repos that have one.
/// A stat per repo, so no throttling needed.
pub fn cache_stats(data: &Path, repos: &[String]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for r in repos {
        let Ok(md) = std::fs::metadata(cache_file(data, r)) else { continue };
        m.insert(r.clone(), serde_json::json!({ "size_mb": (md.blocks() * 512) >> 20, "updated": u64::try_from(md.mtime()).ok() }));
    }
    m.into()
}

/// Job id from `https://github.com/o/n/actions/runs/1/job/2`.
fn job_id(url: &str) -> Option<u64> {
    url.rsplit_once("/job/")?.1.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// May this job's cache overlay be committed? Err = the reason it is not.
/// `trust` is (event, head branch, default branch, GitHub's job conclusion), or why it is
/// unknown. The console's result alone (the job controls it) never earns a commit.
/// `writers` are extra branches allowed to save besides the default.
fn cache_verdict(cache_on: bool, succeeded: bool, writers: &[String], trust: Result<(&str, &str, &str, &str), &str>) -> Result<(), String> {
    if !cache_on {
        return Err("cache disabled".into());
    }
    if !succeeded {
        return Err("job did not succeed".into());
    }
    let (event, branch, default, conclusion) = trust.map_err(|e| format!("could not verify the trigger ({e})"))?;
    if conclusion != "success" {
        return Err(format!("GitHub reports the job as {conclusion}"));
    }
    if event != "push" {
        return Err(format!("{event} event"));
    }
    if branch != default && !writers.iter().any(|w| w == branch) {
        let also = if writers.is_empty() { String::new() } else { format!(" or a cache branch ({})", writers.join(", ")) };
        return Err(format!("branch {branch} is not the default ({default}){also}"));
    }
    Ok(())
}

/// A trusted overlay parked until the repo's other jobs stop reading the cache.
fn pending_file(data: &Path, repo: &str) -> PathBuf {
    cache_file(data, repo).with_extension("pending.qcow2")
}

async fn qemu_img(args: &[&str]) -> Result<()> {
    let out = Command::new("qemu-img").args(args).output().await.context("qemu-img")?;
    if !out.status.success() {
        bail!("qemu-img {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Attach point for a job: flag the VM as a reader (under the `vms` lock, so a
/// commit or clear can't slip in), create the repo cache if missing, then the overlay.
async fn setup_cache(app: &App, id: &str, repo: &str, dir: &Path, gb: u32) -> Option<PathBuf> {
    static INIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let key = repo.to_ascii_lowercase();
    {
        let mut vms = app.vms.lock().unwrap();
        let busy = app.committing.lock().unwrap().contains(&key);
        let v = vms.iter_mut().find(|v| v.id == id)?;
        if busy {
            v.cache_note = Some("cache busy (another job is saving it): this job runs cold".into());
            return None;
        }
        v.cache = CacheUse::Read;
    }
    let (backing, ov) = (cache_file(&app.data, repo), dir.join("cache.qcow2"));
    let made = async {
        let _g = INIT.lock().await;
        if !backing.exists() {
            tokio::fs::create_dir_all(backing.parent().unwrap()).await?;
            // Unformatted: the guest runs mkfs on first use.
            qemu_img(&["create", "-q", "-f", "qcow2", &backing.display().to_string(), &format!("{gb}G")]).await?;
        }
        qemu_img(&["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", &backing.display().to_string(), &ov.display().to_string()]).await
    }
    .await;
    match made {
        Ok(()) => Some(ov),
        Err(e) => {
            tracing::warn!("{id}: cache: {e:#}");
            update(app, id, |v| {
                v.cache = CacheUse::None;
                v.cache_note = Some(format!("cache unavailable: {e:#}"));
            });
            None
        }
    }
}

/// After QEMU exited: commit the overlay into the repo cache if the job earned
/// it, else just drop it.
async fn finish_cache(app: &App, id: &str, repo: &str, dir: &Path, done: bool) {
    let ov = dir.join("cache.qcow2");
    let Some(v) = update(app, id, |_| {}) else { return };
    if v.cache != CacheUse::Read {
        let _ = tokio::fs::remove_file(&ov).await;
        return;
    }
    let cfg = app.cfg();
    let writers = cfg.cache_branches(repo);
    let succeeded = done && v.result.as_deref() == Some("Succeeded");
    let trust = if succeeded && cfg.cache {
        match v.job_url.as_deref().and_then(job_id) {
            Some(j) => app.gh.cache_trust(repo, j, &writers).await.map_err(|e| format!("{e:#}")),
            None => Err("no job page".into()),
        }
    } else {
        Err(String::new())
    };
    let t = trust.as_ref().map(|(a, b, c, d)| (a.as_str(), b.as_str(), c.as_str(), d.as_str())).map_err(String::as_str);
    let verdict = if v.job.is_none() { Err("no job ran".to_string()) } else { cache_verdict(cfg.cache, succeeded, &writers, t) };
    let (state, note) = match verdict {
        Err(why) => {
            let _ = tokio::fs::remove_file(&ov).await;
            (CacheUse::Discarded, Some(format!("cache not saved: {why}")))
        }
        Ok(()) => {
            // Every overlay alive right now shares the same backing state (commits only happen
            // with no readers), so a newer trusted overlay simply supersedes a parked one.
            let pending = pending_file(&app.data, repo);
            let _ = tokio::fs::rename(&ov, &pending).await;
            match commit_pending(app, repo, id).await {
                Some(r) => r,
                None => (CacheUse::Committed, Some("cache queued: saved when this repo's other jobs finish".into())),
            }
        }
    };
    update(app, id, |v| {
        v.cache = state;
        v.cache_note = note;
    });
    // This VM may have been the last reader holding up an earlier job's parked commit.
    if let Some((_, Some(why))) = commit_pending(app, repo, id).await {
        tracing::info!("{repo}: parked cache commit: {why}");
    }
}

/// Commit the repo's parked trusted overlay if nothing else reads the cache.
/// None = nothing parked, or still readers (stays parked).
pub async fn commit_pending(app: &App, repo: &str, except: &str) -> Option<(CacheUse, Option<String>)> {
    let pending = pending_file(&app.data, repo);
    let key = repo.to_ascii_lowercase();
    {
        let vms = app.vms.lock().unwrap();
        let mut committing = app.committing.lock().unwrap();
        if !pending.exists() || cache_readers(&vms, repo, except) > 0 || committing.contains(&key) {
            return None;
        }
        committing.insert(key.clone());
    }
    let cfg = app.cfg();
    let backing = cache_file(&app.data, repo);
    let r = qemu_img(&["commit", "-q", &pending.display().to_string()]).await;
    // qemu-img takes the write lock before touching anything: a refusal means some QEMU
    // still has the cache open and nothing was written. Keep it parked; the tick retries.
    if let Err(e) = &r
        && is_lock_refusal(&format!("{e:#}"))
    {
        app.committing.lock().unwrap().remove(&key);
        return Some((CacheUse::Committed, Some("cache queued: still in use, saving shortly".into())));
    }
    let _ = tokio::fs::remove_file(&pending).await;
    let big = disk_bytes(&backing);
    let out = match r {
        Err(e) => {
            // A failed commit may leave the backing half-written: start over.
            let _ = tokio::fs::remove_file(&backing).await;
            (CacheUse::Discarded, Some(format!("cache commit failed, cache reset: {e:#}")))
        }
        Ok(()) if cache_too_big(big, cfg.cache_gb_for(repo)) => {
            let gb = cfg.cache_gb_for(repo);
            let _ = tokio::fs::remove_file(&backing).await;
            tracing::info!("cache for {repo} grew to {} MB, over {gb} GB x 1.2: reset", big >> 20);
            (CacheUse::Committed, Some(format!("cache saved, then reset: it grew past {} GB", gb as f64 * 1.2)))
        }
        Ok(()) => (CacheUse::Committed, None),
    };
    app.committing.lock().unwrap().remove(&key);
    Some(out)
}

fn is_lock_refusal(err: &str) -> bool {
    err.contains("Failed to get \"write\" lock") || err.contains("Failed to get shared \"write\" lock")
}

/// Active VMs of `repo` (other than `except`) with the cache attached.
fn cache_readers(vms: &[Vm], repo: &str, except: &str) -> usize {
    vms.iter().filter(|v| v.id != except && v.state.is_active() && v.cache == CacheUse::Read && v.repo.eq_ignore_ascii_case(repo)).count()
}

/// Dashboard "Clear": delete a repo's cache (recreated empty by the next job).
pub fn clear_cache(app: &App, repo: &str) -> Result<()> {
    if !app.repos().iter().any(|r| r.eq_ignore_ascii_case(repo)) {
        bail!("not a configured repo");
    }
    let vms = app.vms.lock().unwrap();
    if vms.iter().any(|v| v.state.is_active() && v.repo.eq_ignore_ascii_case(repo))
        || app.committing.lock().unwrap().contains(&repo.to_ascii_lowercase())
    {
        bail!("jobs of {repo} are running: clear the cache when they finish");
    }
    let _ = std::fs::remove_file(pending_file(&app.data, repo));
    match std::fs::remove_file(cache_file(&app.data, repo)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn note(app: &App, id: &str, msg: &str) {
    update(app, id, |v| v.note = Some(msg.into()));
}

/// Keeps a more specific reason set by the reaper or by shutdown.
fn kill_note(app: &App, id: &str) {
    update(app, id, |v| {
        v.note.get_or_insert("killed from dashboard".into());
    });
}

/// Track runner lifecycle from its stdout, e.g.
/// `2026-10-06 10:00:01Z: Listening for Jobs`
/// `2026-10-06 10:00:05Z: Running job: build`
/// `2026-10-06 10:01:40Z: Job build completed with result: Succeeded`
fn observe(app: &App, id: &str, line: &str) {
    let mut save = false;
    if let Some(v) = update(app, id, |v| save = apply_line(v, line, now()))
        && save
    {
        persist(app, &v);
    }
}

/// Longest a VM may live, whatever its console says: idle + job + hold, plus slack.
fn start_cap(cfg: &crate::Config, warm: bool) -> u64 {
    let idle = if warm { cfg.idle_timeout_mins.max(cfg.warm_recycle_mins + 5) } else { cfg.idle_timeout_mins };
    (idle + cfg.job_timeout_mins + cfg.debug_hold_mins) * 60 + 300
}

/// Returns true when the change is worth persisting right away. Each lifecycle
/// step is accepted once and only forward: the job (root in the guest) can echo
/// these lines itself, and must not rewind the state or restart its timeout.
fn apply_line(v: &mut Vm, line: &str, t: u64) -> bool {
    let line = line.trim_end();
    // The guest's journal prefixes console lines ("[ 32.2] kiln-job[1395]: kiln: hostkey ...").
    if let Some((_, k)) = line.split_once("kiln: hostkey ") {
        if v.state != State::Held || v.ssh_hostkeys.len() >= 4 {
            return false;
        }
        v.ssh_hostkeys.push(k.chars().filter(|c| !c.is_control()).take(200).collect());
        true
    } else if line.contains("Listening for Jobs") {
        if v.state != State::Booting {
            return false;
        }
        v.state = State::Idle;
        v.online_at.get_or_insert(t);
        true
    } else if let Some((_, job)) = line.split_once("Running job: ") {
        if v.busy_since.is_some() || !matches!(v.state, State::Booting | State::Idle) {
            return false;
        }
        v.state = State::Busy;
        v.warm = false;
        v.job = Some(job.trim().to_string());
        v.busy_since = Some(t);
        true
    } else if let Some((_, result)) = line.split_once("completed with result: ") {
        if v.result.is_none() && v.state == State::Busy {
            v.result = Some(result.trim().to_string());
        }
        false
    } else if line.contains("Runner update") {
        v.note = Some("runner self-updating (rebake to avoid)".into());
        false
    } else {
        false
    }
}

async fn write_secret(path: &Path, s: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    std::io::Write::write_all(&mut f, s.as_bytes())?;
    Ok(())
}

/// What differs between x86_64 and arm64 guests. A guest always has the host's architecture.
struct Guest {
    /// Ubuntu's name for the architecture (cloud image files).
    ubuntu: &'static str,
    /// GitHub's and Node's name (runner label, runner and Node tarballs, tool cache).
    gh: &'static str,
    qemu: &'static str,
    machine: &'static str,
    /// The kernel console. It is QEMU's stdio, so its input is also the host->guest control channel.
    console: &'static str,
    /// Device the guest mirrors step logs to, and the QEMU flags that attach it to chardev `s1`.
    steps: &'static str,
    steps_args: &'static [&'static str],
    /// SMBIOS OEM strings reach the guest (x86 only: arm64 `virt` has no SMBIOS without UEFI).
    smbios: bool,
}

const X64: Guest = Guest {
    ubuntu: "amd64",
    gh: "x64",
    qemu: "qemu-system-x86_64",
    machine: "q35",
    console: "ttyS0",
    steps: "/dev/ttyS1",
    steps_args: &["-serial", "chardev:s1"],
    smbios: true,
};

/// Apple Silicon (HVF) or aarch64 Linux (KVM). `virt` has a single UART (PL011, ttyAMA0), so
/// steps go over a virtio-serial port. GICv3: GICv2 stops at 8 vCPUs.
const ARM64: Guest = Guest {
    ubuntu: "arm64",
    gh: "arm64",
    qemu: "qemu-system-aarch64",
    machine: "virt,gic-version=3",
    console: "ttyAMA0",
    steps: "/dev/virtio-ports/kiln.steps",
    steps_args: &["-device", "virtio-serial-pci", "-device", "virtserialport,chardev=s1,name=kiln.steps"],
    smbios: false,
};

const GUEST: Guest = if host::ARM64 { ARM64 } else { X64 };

/// Job VM flags after the kernel: its command line, the secrets (JIT config, debug SSH
/// keys) and the serial channels. Secrets go in as fw_cfg files, which every guest reads,
/// and on x86 also as SMBIOS OEM strings (the older path); `path=`/`file=` keep them out of `ps`.
/// panic=1 + -no-reboot make a kernel panic end the VM instead of hanging until the timeout.
fn job_args(g: &Guest, dir: &Path, ssh: bool) -> Vec<String> {
    let mut a = vec!["-append".into(), format!("root=/dev/vda1 rootfstype=ext4 ro console={} quiet panic=1", g.console)];
    for s in if ssh { &["jit", "ssh"][..] } else { &["jit"] } {
        let f = dir.join(s).display().to_string();
        if g.smbios {
            a.extend(["-smbios".into(), format!("type=11,path={f}")]);
        }
        a.extend(["-fw_cfg".into(), format!("name=opt/kiln/{s},file={f}")]);
    }
    // stdio is the guest's console: its input is the host->guest control channel (hold/release).
    a.extend(["-serial".into(), "stdio".into()]);
    // Steps: a unix socket kiln copies into a capped steps.log.
    a.extend(["-chardev".into(), format!("socket,id=s1,path={},server=on,wait=off", dir.join("steps.sock").display())]);
    a.extend(g.steps_args.iter().map(|s| s.to_string()));
    a
}

/// Common QEMU flags for both bake and job VMs.
/// `netdev_extra`: more `-netdev user` options, e.g. `,hostfwd=...`.
fn qemu(g: &Guest, cpus: u32, mem_mb: u32, disk: &Path, netdev_extra: &str) -> Command {
    let mut c = Command::new(g.qemu);
    c.args(["-machine", &format!("{},accel={}", g.machine, host::ACCEL), "-cpu", "host", "-nodefaults", "-display", "none", "-no-reboot"])
        .args(["-smp", &cpus.to_string(), "-m", &mem_mb.to_string()])
        // cache=unsafe: the overlay is discarded after the job anyway, so skip fsyncs.
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2,cache=unsafe,discard=unmap", disk.display()))
        .args(["-netdev", &format!("user,id=n0{netdev_extra}"), "-device", "virtio-net-pci,netdev=n0"])
        .args(["-device", "virtio-rng-pci"])
        .kill_on_drop(true);
    c
}

/// nftables ruleset (the mirror's DNAT and accept only when `mirror`) loaded inside a filtered job VM's network namespace.
/// Guest traffic leaves QEMU's slirp as ordinary sockets of the qemu process, so it
/// hits this OUTPUT chain. The guest's 10.0.2.2 is the namespace loopback; the DNAT
/// rewrites the mirror's port to slirp4netns's host-loopback alias 10.0.2.2, which
/// reaches the host's 127.0.0.1:5000. Every other host loopback port, the LAN, the
/// tailnet, metadata and the host's own IPs are dropped; IPv6 is off entirely and
/// outbound SMTP is dropped. Replies to the debug-SSH port driver are `ct established`.
fn egress_nft(mirror: bool) -> String {
    let (dnat, accept) = if mirror {
        (
            "\n    chain out  { type nat hook output priority -100; ip daddr 127.0.0.1 tcp dport 5000 dnat to 10.0.2.2:5000; }",
            "\n    ip daddr 10.0.2.2 tcp dport 5000 accept",
        )
    } else {
        ("", "")
    };
    format!(
        r#"table ip kilnnat {{{dnat}
  chain post {{ type nat hook postrouting priority 100; oifname "tap0" masquerade; }}
}}
table inet kiln {{
  chain out {{
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
    ip daddr 10.0.2.3 meta l4proto {{ tcp, udp }} th dport 53 accept{accept}
    ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
               172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 }} drop
    tcp dport 25 drop
    oifname "tap0" meta nfproto ipv4 accept
  }}
}}
"#
    )
}

/// Drops every capability QEMU could use in the namespace once nft is loaded (fails closed if setpriv is missing).
const DROP_CAPS: &str = "setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs";

/// Namespace setup shared by jobs and the doctor: `$1` is the nft file.
const RK_SETUP: &str = "sysctl -qw net.ipv4.conf.all.route_localnet=1; nft -f \"$1\"";

fn rk_base(state: &Path) -> Vec<String> {
    ["--state-dir", &state.display().to_string(), "--net=slirp4netns", "--copy-up=/etc"].map(String::from).into()
}

/// rootlesskit argv that runs `qemu` (program + args) in a filtered namespace.
/// `sh -e` fails closed: if sysctl or nft fail, QEMU never starts. QEMU's args are
/// positional parameters, never spliced into the script. `publish`: host (ip, port)
/// forwarded to the same port in the namespace, for the debug-SSH hostfwd.
fn rk_args(dir: &Path, publish: Option<(&str, u16)>, qemu: &[String]) -> Vec<String> {
    let mut a = rk_base(&dir.join("rk"));
    a.extend(["--mtu=65520", "--slirp4netns-sandbox=auto", "--slirp4netns-seccomp=auto"].map(String::from));
    if let Some((ip, port)) = publish {
        // Child IP 127.0.0.1: by default the port driver dials the namespace's tap
        // address, which the egress filter drops (10.0.0.0/8); loopback is allowed.
        a.extend(["--port-driver=builtin".into(), "-p".into(), format!("{ip}:{port}:127.0.0.1:{port}/tcp")]);
    }
    a.extend([
        "/bin/sh".into(),
        "-ec".into(),
        format!("{RK_SETUP}; shift; exec {DROP_CAPS} \"$@\""),
        "sh".into(),
        dir.join("egress.nft").display().to_string(),
    ]);
    a.extend_from_slice(qemu);
    a
}

/// Script for the doctor's probe namespace. `$1` nft file, `$2` dashboard port, `$3` tailnet IP.
fn egress_script(mirror: bool, tailnet: bool) -> String {
    let step = |cond: &str, msg: &str| format!("{cond} && {{ echo 'step: {msg}'; exit 1; }}\n");
    let mut s = String::from("sysctl -qw net.ipv4.conf.all.route_localnet=1 || { echo 'step: sysctl'; exit 1; }\n");
    s += "nft -f \"$1\" || { echo 'step: loading nft rules'; exit 1; }\n";
    if mirror {
        s += &step("! curl -sf -m5 -o /dev/null http://127.0.0.1:5000/v2/", "docker mirror unreachable");
    }
    s += &step("curl -s -m3 -o /dev/null \"http://10.0.2.2:$2/\"", "dashboard port reachable from jobs");
    if tailnet {
        s += &step("curl -s -m3 -o /dev/null \"http://$3:$2/\"", "tailnet address reachable from jobs");
    }
    // Each check is `cond && fail`, so a passing last check leaves status 1: end explicitly.
    s + &step("! curl -sf -m8 -o /dev/null https://api.github.com/", "internet unreachable") + "exit 0\n"
}

pub const FILTERED_LINUX_ONLY: &str = "filtered egress needs Linux (rootlesskit, slirp4netns and nftables): \
     not available on macOS, where jobs run with open egress (set egress to \"open\")";

/// Last probe: (unix time, result). Held across the probe so callers share one run.
static EGRESS: tokio::sync::Mutex<Option<(u64, Result<(), String>)>> = tokio::sync::Mutex::const_new(None);
const EGRESS_TTL: u64 = 600;

fn fresh(at: u64, t: u64) -> bool {
    t < at + EGRESS_TTL
}

/// Result of the filtered-egress probe, cached 10 minutes unless `force`.
pub async fn egress_ready(app: &App, force: bool) -> Result<(), String> {
    let mut g = EGRESS.lock().await;
    if let Some((at, r)) = &*g
        && !force
        && fresh(*at, now())
    {
        return r.clone();
    }
    let r = egress_probe(app).await.map_err(|e| format!("{e:#}"));
    *g = Some((now(), r.clone()));
    r
}

async fn egress_probe(app: &App) -> Result<()> {
    if host::MACOS {
        bail!("{FILTERED_LINUX_ONLY}");
    }
    for bin in ["rootlesskit", "slirp4netns", "nft", "setpriv"] {
        if !host::which(bin) {
            bail!("{bin} not found; install: sudo apt install rootlesskit slirp4netns nftables uidmap util-linux");
        }
    }
    let cfg = app.cfg();
    let port = cfg.listen.parse::<std::net::SocketAddr>()?.port();
    let mirror = cfg.docker_mirror && app.mirror.lock().unwrap().running;
    let ts = tailnet_ip().await;
    let dir = app.data.join("egress-check");
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await?;
    let nft = dir.join("egress.nft");
    tokio::fs::write(&nft, egress_nft(cfg.docker_mirror)).await?;
    let mut cmd = Command::new("rootlesskit");
    cmd.args(rk_base(&dir.join("rk")))
        .args(["/bin/sh", "-c", &egress_script(mirror, ts.is_some()), "sh"])
        .arg(&nft)
        .arg(port.to_string())
        .arg(ts.unwrap_or_default())
        .kill_on_drop(true);
    let o = tokio::time::timeout(Duration::from_secs(60), cmd.output()).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    let o = o.context("probe timed out")?.context("running rootlesskit")?;
    if o.status.success() {
        return Ok(());
    }
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let why = out
        .lines()
        .find(|l| l.starts_with("step:"))
        .map(String::from)
        .or_else(|| err.lines().rev().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()));
    bail!("{}", why.unwrap_or_else(|| format!("rootlesskit exited with {}", o.status)))
}

fn prune(app: &App) {
    let mut vms = app.vms.lock().unwrap();
    while vms.len() > KEEP_HISTORY {
        let Some(pos) = vms.iter().position(|v| !v.state.is_active()) else { break };
        let old = vms.remove(pos);
        let _ = std::fs::remove_dir_all(app.data.join("vms").join(&old.id));
    }
}

// ---------------------------------------------------------------- bake

const CLOUD: &str = "https://cloud-images.ubuntu.com/noble/current";
/// Disk image plus its matching kernel/initrd. They must come from the same
/// build (the kernel has to match /lib/modules inside the image), so they are
/// always downloaded together.
fn cloud_files(g: &Guest) -> [String; 3] {
    let u = g.ubuntu;
    [
        format!("noble-server-cloudimg-{u}.img"),
        format!("unpacked/noble-server-cloudimg-{u}-vmlinuz-generic"),
        format!("unpacked/noble-server-cloudimg-{u}-initrd-generic"),
    ]
}

/// Build images/base.qcow2: Ubuntu cloud image + cloud-init recipe
/// (guest/user-data.yaml) booted once, then frozen.
pub async fn bake(app: Arc<App>) -> Result<()> {
    use std::sync::atomic::Ordering;
    if app.baking.swap(true, Ordering::SeqCst) {
        bail!("a bake is already running");
    }
    // Checked after claiming `baking` (SeqCst): a drain that saw `baking` false has set
    // `draining` before, so no bake slips in between a finished drain and the re-exec.
    if let Some(why) = bake_refused(app.draining.load(Ordering::SeqCst), app.stopping.load(Ordering::SeqCst)) {
        app.baking.store(false, Ordering::SeqCst);
        bail!("{why}");
    }
    // Held until the bake ends; also keeps a second kiln process out.
    let lock = std::fs::OpenOptions::new().create(true).append(true).open(images(&app.data).join("bake.lock"));
    let lock = lock.map_err(anyhow::Error::from).and_then(|f| match f.try_lock() {
        Ok(()) => Ok(f),
        Err(_) => Err(anyhow::anyhow!("a bake is already running (another kiln process)")),
    });
    let lock = match lock {
        Ok(f) => f,
        Err(e) => {
            app.baking.store(false, Ordering::SeqCst);
            return Err(e);
        }
    };
    let r = bake_inner(&app).await;
    drop(lock);
    if let Err(e) = &r {
        let _ = append(&images(&app.data).join("bake.log"), &format!("\nkiln: bake failed: {e:#}\n")).await;
    }
    app.baking.store(false, Ordering::SeqCst);
    r
}

/// Why a bake may not start now: an update drains (and re-execs) or kiln stops.
pub fn bake_refused(draining: bool, stopping: bool) -> Option<&'static str> {
    if stopping {
        Some("kiln is stopping")
    } else if draining {
        Some("kiln is updating")
    } else {
        None
    }
}

async fn append(path: &Path, s: &str) -> Result<()> {
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(path).await?;
    f.write_all(s.as_bytes()).await?;
    Ok(())
}

async fn sh(log: &Path, cmd: &mut Command) -> Result<()> {
    let f = std::fs::OpenOptions::new().append(true).open(log)?;
    let status = cmd.stdout(f.try_clone()?).stderr(f).status().await?;
    if !status.success() {
        bail!("{cmd:?} failed: {status}");
    }
    Ok(())
}

async fn bake_inner(app: &App) -> Result<()> {
    let cfg = app.cfg();
    // config.json may be hand-edited and is only validated on dashboard saves; apt
    // names and Node versions reach the bake's root shell, so check them here too.
    cfg.validate().context("config.json is invalid, not baking")?;
    let img = images(&app.data);
    let log = img.join("bake.log");
    tokio::fs::write(&log, "").await?;
    let say = |m: String| {
        let log = log.clone();
        async move {
            tracing::info!("bake: {}", m.trim());
            append(&log, &format!("kiln: {m}\n")).await
        }
    };

    let local = |f: &str| img.join(f.rsplit('/').next().unwrap());
    let part = |f: &str| img.join(format!("{}.part", f.rsplit('/').next().unwrap()));
    // -z: skip files that haven't changed, but pick up a moved "current".
    // Parts are renamed only once all three arrived, so image and kernel stay a matched set.
    let files = cloud_files(&GUEST);
    for f in &files {
        say(format!("fetching {CLOUD}/{f}")).await?;
        let _ = tokio::fs::remove_file(part(f)).await;
        let mut curl = Command::new("curl");
        curl.args(["-fLR", "--no-progress-meter", "--speed-limit", "1024", "--speed-time", "60", "-z"])
            .arg(local(f))
            .arg("-o")
            .arg(part(f))
            .arg(format!("{CLOUD}/{f}"));
        sh(&log, &mut curl).await?;
    }
    for f in &files {
        if part(f).exists() {
            tokio::fs::rename(part(f), local(f)).await?;
        }
    }
    let [cloud, kernel, initrd] = files.map(|f| local(&f));

    let rel = app.gh.raw(reqwest::Method::GET, "repos/actions/runner/releases/latest", None).await?;
    let tag: serde_json::Value = serde_json::from_slice(&rel.body)?;
    let version = runner_version(tag["tag_name"].as_str().context("runner release tag")?)?;
    say(format!("actions runner {version}")).await?;

    let work = img.join("bake");
    let _ = tokio::fs::remove_dir_all(&work).await;
    tokio::fs::create_dir_all(work.join("seed")).await?;
    let index: serde_json::Value = reqwest::Client::builder()
        .user_agent("kiln-ci")
        .timeout(Duration::from_secs(60))
        .build()?
        .get("https://nodejs.org/dist/index.json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("nodejs.org release index")?;
    let node = resolve_node(&index, &cfg.bake_node_versions)?;
    say(format!("node {}", node.join(" "))).await?;
    let user_data = recipe(&GUEST, &version, &node.join(" "), &cfg.bake_apt_packages.join(" "));
    tokio::fs::write(work.join("seed/user-data"), user_data).await?;
    tokio::fs::write(work.join("seed/meta-data"), "instance-id: kiln-bake\nlocal-hostname: kiln\n").await?;
    let seed = work.join("seed.iso");
    sh(
        &log,
        Command::new("xorriso")
            .args(["-as", "mkisofs", "-quiet", "-volid", "cidata", "-joliet", "-rock", "-o"])
            .arg(&seed)
            .arg(work.join("seed")),
    )
    .await?;

    let disk = work.join("base.qcow2");
    sh(&log, Command::new("qemu-img").args(["convert", "-O", "qcow2"]).arg(&cloud).arg(&disk)).await?;
    sh(&log, Command::new("qemu-img").arg("resize").arg(&disk).arg(format!("{}G", cfg.vm_disk_gb))).await?;

    say("booting bake VM (installs packages + runner, takes a few minutes)".into()).await?;
    let mut cmd = qemu(&GUEST, cfg.vm_cpus, cfg.vm_mem_mb.max(4096), &disk, "");
    cmd.arg("-kernel").arg(&kernel).arg("-initrd").arg(&initrd);
    cmd.arg("-append").arg(format!("root=LABEL=cloudimg-rootfs ro console={}", GUEST.console));
    cmd.arg("-drive").arg(format!("file={},if=virtio,format=raw,readonly=on", seed.display()));
    cmd.arg("-serial").arg(format!("file:{}", work.join("console.log").display()));
    let qemu_err = std::fs::OpenOptions::new().append(true).open(&log)?;
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(qemu_err).spawn()?;
    // Mirror the guest console into bake.log as it grows, so the dashboard can follow along.
    let console = work.join("console.log");
    let mut off = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30 * 60);
    let status = loop {
        let done = tokio::select! {
            s = child.wait() => Some(s?),
            _ = tokio::time::sleep(Duration::from_secs(1)) => None,
        };
        if done.is_none() && tokio::time::Instant::now() > deadline {
            child.kill().await.ok();
            bail!("bake VM timed out after 30 minutes");
        }
        copy_new(&console, &log, &mut off).await;
        if let Some(s) = done {
            break s;
        }
    };
    let console_text = tokio::fs::read_to_string(&console).await.unwrap_or_default();
    if !status.success() || !console_text.contains("KILN_BAKE_OK") {
        bail!("bake VM did not finish cleanly ({status}); see log above");
    }

    // Running job VMs keep their open handle on the old base; new ones get this.
    // Kernel and image are swapped by rename, so a job never sees a half-copied kernel.
    let new_kernel = img.join("base.vmlinuz.new");
    tokio::fs::copy(&kernel, &new_kernel).await?;
    tokio::fs::rename(&disk, img.join("base.qcow2")).await?;
    tokio::fs::rename(&new_kernel, img.join("base.vmlinuz")).await?;
    let meta = serde_json::json!({
        "recipe": RECIPE,
        "baked_at": now(),
        "runner_version": version,
        "node_versions": node,
        "node_wanted": cfg.bake_node_versions,
        "apt_wanted": cfg.bake_apt_packages,
    });
    tokio::fs::write(img.join("base.json.tmp"), meta.to_string()).await?;
    tokio::fs::rename(img.join("base.json.tmp"), img.join("base.json")).await?;
    let _ = tokio::fs::remove_dir_all(&work).await;
    say("base image ready".into()).await?;
    Ok(())
}

/// The actions/runner version in a release tag ("v2.338.0"). It is templated into the
/// bake's root shell, so anything but N.N.N is refused.
fn runner_version(tag: &str) -> Result<String> {
    let v = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        bail!("unexpected actions/runner release tag {tag:?}");
    }
    Ok(v.to_string())
}

/// Version of the guest recipe (guest/user-data.yaml) that the host relies on.
/// Bump it when an image baked from an older recipe lacks something kiln
/// depends on; such images are stale (and rebaked by auto_rebake).
/// 2: fork-refusal job hook, apt archives on the cache disk, bake_node_versions.
/// 3: the hook also refuses workflow_run from forks; Node tarballs checked against SHASUMS256.txt.
/// 4: secrets also read from fw_cfg; console and steps devices per architecture (arm64 guests).
const RECIPE: u64 = 4;

/// guest/user-data.yaml with kiln's values filled in.
fn recipe(g: &Guest, runner: &str, node: &str, apt: &str) -> String {
    include_str!("../guest/user-data.yaml")
        .replace("{{RUNNER_VERSION}}", runner)
        .replace("{{NODE_VERSIONS}}", node)
        .replace("{{APT_PACKAGES}}", apt)
        .replace("{{ARCH}}", g.gh)
        .replace("{{CONSOLE}}", g.console)
        .replace("{{STEPS}}", g.steps)
}

/// Was the image at `base` (base.json) baked from the current recipe? kiln launches
/// nothing on an older one: it may lack the fork-refusal hook. No marker = recipe 1.
pub fn image_recipe_ok(base: &serde_json::Value) -> bool {
    base["recipe"].as_u64().unwrap_or(1) >= RECIPE
}

/// Why the image at `base` (base.json) must be rebaked for the current config, if so.
/// Images from before `node_wanted` was recorded carried Node 24 only, and no extra apt packages.
fn rebake_reason(base: &serde_json::Value, node: &[String], apt: &[String]) -> Option<String> {
    if !image_recipe_ok(base) {
        return Some("baked by an older kiln: rebake for the fork-refusal hook".into());
    }
    let set = |v: &[String]| v.iter().cloned().collect::<std::collections::BTreeSet<_>>();
    let baked = |k: &str, old: &[&str]| -> Vec<String> {
        serde_json::from_value(base[k].clone()).unwrap_or_else(|_| old.iter().map(|s| s.to_string()).collect())
    };
    if set(&baked("node_wanted", &["24"])) != set(node) {
        return Some("bake_node_versions changed since this bake".into());
    }
    (set(&baked("apt_wanted", &[])) != set(apt)).then(|| "bake_apt_packages changed since this bake".into())
}

/// Exact Node versions to bake for `wanted` (majors like "20" or exact "20.19.5"),
/// looked up in nodejs.org's dist/index.json (newest first, "version": "v24.21.0").
/// Returned oldest to newest, without duplicates: the bake loop symlinks the last
/// one as the bare `node`. Unknown versions are an error, so a typo fails the bake.
fn resolve_node(index: &serde_json::Value, wanted: &[String]) -> Result<Vec<String>> {
    // Only plain x.y.z strings: they end up in the bake's shell script.
    let releases: Vec<&str> = index
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["version"].as_str()?.strip_prefix('v'))
        .filter(|v| v.split('.').count() == 3 && v.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
        .collect();
    let key = |v: &str| v.split('.').map(|p| p.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    let mut out = wanted
        .iter()
        .map(|w| {
            // "20" means the 20.x line ("20." prefix, so "2" never matches 20.x); exact otherwise.
            let hit = if w.contains('.') {
                releases.iter().find(|r| *r == w)
            } else {
                releases.iter().filter(|r| r.strip_prefix(w.as_str()).is_some_and(|t| t.starts_with('.'))).max_by_key(|r| key(r))
            };
            hit.map(|r| r.to_string()).with_context(|| format!("node {w}: no such release on nodejs.org"))
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_by_key(|v| key(v));
    out.dedup();
    Ok(out)
}

/// Append whatever `src` gained since offset `off`.
async fn copy_new(src: &Path, dst: &Path, off: &mut usize) {
    // ponytail: rereads the whole console each second; fine for a few-MB bake log.
    let Ok(data) = tokio::fs::read(src).await else { return };
    if data.len() > *off && append(dst, &String::from_utf8_lossy(&data[*off..])).await.is_ok() {
        *off = data.len();
    }
}

// ---------------------------------------------------------------- host checks

/// Available KB column of `df -Pk` (header line, then one data line).
fn parse_df_kb(out: &str) -> Option<u64> {
    out.lines().nth(1)?.split_whitespace().nth(3)?.parse().ok()
}

pub async fn disk_free_gb(dir: &Path) -> Option<u64> {
    let out = Command::new("df").arg("-Pk").arg(dir).output().await.ok()?;
    Some(parse_df_kb(&String::from_utf8_lossy(&out.stdout))? / (1024 * 1024))
}

const MIN_DISK_GB: u64 = 15;

/// Why no VM may start right now, if so. The mirror cache is the usual
/// reclaimable disk hog, so a low-disk message names its size.
pub fn launch_gate(
    mem_avail_mb: u64,
    vm_mem_mb: u32,
    disk_free_gb: Option<u64>,
    mirror_mb: Option<u64>,
    cache_mb: Option<u64>,
) -> Option<String> {
    if mem_avail_mb < vm_mem_mb as u64 + 1024 {
        return Some(format!("not enough memory: {mem_avail_mb} MB free"));
    }
    disk_free_gb.filter(|&g| g < MIN_DISK_GB).map(|g| {
        let gb = |m: u64| m as f64 / 1024.0;
        let parts: Vec<String> =
            [mirror_mb.map(|m| format!("docker mirror cache {:.1} GB", gb(m))), cache_mb.map(|m| format!("repo caches {:.1} GB", gb(m)))]
                .into_iter()
                .flatten()
                .collect();
        let m = if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) };
        format!("low disk: {g} GB free{m}")
    })
}

/// Memory and vCPUs still available for new VMs in one tick. QEMU allocates
/// guest RAM lazily, so MemAvailable alone says nothing about what running VMs
/// will still claim: budget against what is committed instead.
pub struct Budget {
    mem_mb: u64,
    cpus: u64,
    total_mb: u64,
    committed_mb: u64,
    committed_cpus: u64,
    max_cpus: u64,
}

impl Budget {
    pub fn new(total_mb: u64, committed_mb: u64, committed_cpus: u64, host_threads: u32) -> Self {
        // CI is bursty (builds spike, then idle), so vCPUs may oversubscribe threads by 1.5x.
        let max_cpus = host_threads as u64 * 3 / 2;
        Self {
            mem_mb: total_mb.saturating_sub(committed_mb).saturating_sub(2048),
            cpus: max_cpus.saturating_sub(committed_cpus),
            total_mb,
            committed_mb,
            committed_cpus,
            max_cpus,
        }
    }

    /// Grants up to `want` VMs of this size and reserves them; the reason when it grants fewer.
    pub fn take(&mut self, want: usize, mem_mb: u32, cpus: u32) -> (usize, Option<String>) {
        let (by_mem, by_cpu) = (self.mem_mb / mem_mb.max(1) as u64, self.cpus / cpus.max(1) as u64);
        let n = want.min(by_mem.min(by_cpu) as usize);
        self.mem_mb -= n as u64 * mem_mb as u64;
        self.cpus -= n as u64 * cpus as u64;
        let why = (n < want).then(|| {
            if by_mem <= by_cpu {
                format!("memory budget: {} GB committed of {} GB", self.committed_mb / 1024, self.total_mb / 1024)
            } else {
                format!("cpu budget: {} vCPUs committed of {}", self.committed_cpus, self.max_cpus)
            }
        });
        (n, why)
    }
}

/// Age and staleness against a runner release (GitHub stops serving runners ~30 days old).
fn image_age(baked_at: u64, version: &str, latest: Option<&str>, t: u64) -> (u64, bool) {
    let age = t.saturating_sub(baked_at) / 86400;
    (age, age > 25 || latest.is_some_and(|l| l != version))
}

/// images/base.json plus runner_latest, age_days, rebake (reason or null) and stale; null when
/// never baked. `cfg` supplies the bake settings (see `rebake_reason`).
pub fn image_info(data: &Path, latest: Option<String>, cfg: &crate::Config) -> serde_json::Value {
    let Some(mut v) = std::fs::read(images(data).join("base.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|v| v.is_object())
    else {
        return serde_json::Value::Null;
    };
    let (age, stale) = image_age(v["baked_at"].as_u64().unwrap_or(0), v["runner_version"].as_str().unwrap_or(""), latest.as_deref(), now());
    let rebake = rebake_reason(&v, &cfg.bake_node_versions, &cfg.bake_apt_packages);
    v["runner_latest"] = latest.into();
    v["age_days"] = age.into();
    v["stale"] = (stale || rebake.is_some()).into();
    v["rebake"] = rebake.into();
    v
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &str, ok: bool, detail: impl Into<String>) -> Check {
    Check { name: name.into(), ok, detail: detail.into() }
}

async fn output(bin: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(bin).args(args).output().await.with_context(|| format!("running {bin}"))?;
    if !o.status.success() {
        bail!("{bin} exited with {}", o.status);
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

/// Host prerequisites, for `kiln doctor` and GET /api/doctor.
/// `cli`: run from `kiln doctor`, where a `kiln serve` may be running next to us.
pub async fn doctor(app: &App, cli: bool) -> Vec<Check> {
    let cfg = app.cfg();
    let mut out = vec![];

    let (ok, detail) = host::hypervisor();
    out.push(check(if host::MACOS { "hvf" } else { "kvm" }, ok, detail));

    for bin in [GUEST.qemu, "qemu-img", "xorriso", "curl", host::tailscale()] {
        // The macOS app's CLI is .../Tailscale.app/Contents/MacOS/Tailscale.
        let name = bin.rsplit('/').next().unwrap_or(bin).to_ascii_lowercase();
        out.push(match output(bin, &["--version"]).await {
            Ok(v) => check(&name, true, v.lines().next().unwrap_or("").to_string()),
            Err(e) => check(&name, false, format!("{e:#}")),
        });
    }

    let disk = disk_free_gb(&app.data).await;
    out.push(match disk {
        Some(g) => check("disk", g >= MIN_DISK_GB, format!("{g} GB free (need {MIN_DISK_GB})")),
        None => check("disk", false, "df failed"),
    });

    let avail = host::mem_avail_mb();
    let want = cfg.max_vms as u64 * cfg.vm_mem_mb as u64;
    let note = if avail < want { "; not enough for all slots at once" } else { "" };
    out.push(check(
        "memory",
        avail >= cfg.vm_mem_mb as u64,
        format!("{avail} MB available, {} x {} MB wanted{note}", cfg.max_vms, cfg.vm_mem_mb),
    ));

    app.gh.refresh_latest().await;
    let info = image_info(&app.data, app.gh.latest_cached(), &cfg);
    out.push(if !image_ready(&app.data) {
        check("image", false, "not baked: run `kiln bake`")
    } else {
        let node = info["node_versions"]
            .as_array()
            .map_or("24 (older image)".into(), |a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "));
        let facts = format!("runner {}, node {node}, {} days old", info["runner_version"], info["age_days"]);
        if let Some(why) = info["rebake"].as_str() {
            check("image", false, format!("rebake needed: {why} ({facts})"))
        } else if info["stale"] == true {
            check("image", true, format!("warning: stale: {facts} (runner latest {})", info["runner_latest"]))
        } else {
            check("image", true, facts)
        }
    });

    let src = app.gh.source();
    if let Some(a) = app.gh.app() {
        if let Err(e) = app.gh.discover().await {
            out.push(check("app discovery", false, format!("{e:#}")));
        }
        out.push(match app.gh.app_info(&a).await {
            Ok(v) => check("github app", true, format!("{} (id {})", v["slug"].as_str().unwrap_or("?"), a.id)),
            Err(e) => check("github app", false, format!("{e:#}")),
        });
        let n = a.names.read().unwrap().len();
        out.push(if n > 0 {
            check("app installations", true, format!("{n} repo(s)"))
        } else {
            check("app installations", false, format!("installed on no repo: {}/installations/new", a.html_url))
        });
    } else {
        out.push(match (app.gh.has_token(), src) {
            (false, _) => check("token", false, "no token: set one in the dashboard, KILN_GITHUB_TOKEN, or `gh auth login`"),
            (true, "gh") => check(
                "token",
                true,
                "from `gh auth token`; a keyring may be locked after a headless reboot, save it from the dashboard instead",
            ),
            (true, s) => check("token", true, format!("source: {s}")),
        });
    }
    // A read per permission kiln needs; 403/404 on one names the missing permission
    // (fine-grained tokens) instead of a generic API failure.
    const NEEDS: [(&str, &str); 3] = [
        ("actions/runners?per_page=1", "Administration: write (register runners)"),
        ("actions/runs?per_page=1", "Actions: read and write (find queued jobs)"),
        ("commits?per_page=1", "Contents: read (verify cache-writer pushes)"),
    ];
    for repo in &app.repos() {
        let (mut missing, mut errs) = (vec![], vec![]);
        for (path, perm) in NEEDS {
            match app.gh.raw(reqwest::Method::GET, &format!("repos/{repo}/{path}"), None).await {
                // 409: commits of an empty repo; the permission is there.
                Ok(r) if r.status == 200 || r.status == 409 => {}
                Ok(r) if matches!(r.status, 403 | 404) => missing.push(perm),
                Ok(r) => errs.push(format!("{path} returned {}", r.status)),
                Err(e) => errs.push(format!("{path}: {e:#}")),
            }
        }
        let mut why = vec![];
        if !missing.is_empty() {
            why.push(format!("token lacks {} (or the repo is not visible to it)", missing.join(", ")));
        }
        why.extend(errs);
        out.push(if why.is_empty() {
            check(&format!("repo {repo}"), true, "runners, actions and contents reachable")
        } else {
            check(&format!("repo {repo}"), false, why.join("; "))
        });
    }
    if let Some(t) = *app.gh.expires.lock().unwrap() {
        let days = t.saturating_sub(now()) / 86400;
        let detail =
            if t <= now() { "expired".to_string() } else { format!("{}expires in {days} days", if days < 14 { "warning: " } else { "" }) };
        out.push(check("token expiry", days >= 7, detail));
    }

    let (ok, detail) = crate::mirror::check(app).await;
    out.push(check("docker mirror", ok, detail));

    // Cached unless run from the CLI; a failure only matters when jobs are filtered.
    out.push(match egress_ready(app, cli).await {
        Ok(()) => check("filtered egress", true, "jobs reach the internet and the mirror only"),
        Err(e) => check(
            "filtered egress",
            cfg.egress != "filtered",
            if cfg.egress == "filtered" { e } else { format!("unavailable (jobs run with open egress): {e}") },
        ),
    });

    out.push(match output(host::tailscale(), &["status", "--json"]).await {
        Ok(j) => {
            let v: serde_json::Value = serde_json::from_str(&j).unwrap_or_default();
            let st = v["BackendState"].as_str().unwrap_or("unknown");
            check("tailscale up", st == "Running", format!("BackendState {st}"))
        }
        Err(e) => check("tailscale up", false, format!("{e:#}")),
    });
    if let Some((ok, detail)) = crate::web::serve_doctor(&app.data).await {
        out.push(check("tailscale serve", ok, detail));
    }

    // QEMU processes of ours that no VM record accounts for (e.g. after a crash).
    let vms_dir = format!("{}/", app.data.join("vms").display());
    let stray = host::process_cmdlines().iter().filter(|c| c.contains("qemu-system") && c.contains(&vms_dir)).count();
    let active = app.vms.lock().unwrap().iter().any(|v| v.state.is_active());
    let serving =
        cli && tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(&cfg.listen)).await.is_ok_and(|r| r.is_ok());
    out.push(if stray > 0 && serving {
        check("stray qemu", true, format!("{stray} qemu process(es) owned by running kiln serve"))
    } else if stray > 0 && !active {
        check(
            "stray qemu",
            false,
            format!(
                "{stray} qemu process(es) running from {vms_dir} with no active VM (expected only if another kiln serve is running jobs)"
            ),
        )
    } else {
        check("stray qemu", true, "none")
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str, state: State, online_at: Option<u64>) -> Vm {
        Vm {
            id: id.into(),
            repo: "o/n".into(),
            runner_id: Some(7),
            state,
            job: None,
            result: None,
            job_url: None,
            queued_at: None,
            started: 0,
            online_at,
            busy_since: None,
            ended: None,
            note: None,
            cpus: 4,
            mem_mb: 8192,
            cache: CacheUse::None,
            cache_note: None,
            ssh: None,
            ssh_port: None,
            hold_until: None,
            ssh_hostkeys: vec![],
            egress: String::new(),
            policy: String::new(),
            warm: false,
        }
    }

    #[test]
    fn egress_wrapping() {
        let q: Vec<String> = ["qemu-system-x86_64", "-drive", "file=/a b/disk.qcow2"].map(String::from).into();
        let a = rk_args(Path::new("/d/vm 1"), Some(("100.1.2.3", 2201)), &q);
        let at = |x: &str| a.iter().position(|v| v == x).unwrap();
        assert!(a.contains(&"--state-dir".into()) && a.contains(&"/d/vm 1/rk".into()));
        assert!(!a.iter().any(|v| v == "--disable-host-loopback"));
        assert_eq!(a[at("-p") + 1], "100.1.2.3:2201:127.0.0.1:2201/tcp");
        assert!(a.contains(&"--port-driver=builtin".into()));
        // qemu args follow the script and nft path as separate argv entries
        assert_eq!(&a[a.len() - 3..], &q[..]);
        assert_eq!(a[a.len() - 4], "/d/vm 1/egress.nft");
        assert!(
            a[at("-ec") + 1].ends_with("--no-new-privs \"$@\"") && a[at("-ec") + 1].contains("; shift; exec setpriv --bounding-set=-all")
        );
        assert!(!rk_args(Path::new("/d"), None, &q).contains(&"-p".into()));
        let on = egress_nft(true);
        assert!(on.contains("ct state established,related accept") && on.contains("tcp dport 25 drop"));
        assert!(on.contains("dnat to 10.0.2.2:5000") && on.contains("ip daddr 10.0.2.2 tcp dport 5000 accept"));
        let off = egress_nft(false);
        assert!(!off.contains("5000") && off.contains("tcp dport 25 drop") && off.contains("masquerade"));
    }

    #[test]
    fn egress_probe_script() {
        let s = egress_script(true, true);
        assert!(s.contains("mirror") && s.contains("tailnet") && s.contains("internet unreachable"));
        let s = egress_script(false, false);
        assert!(!s.contains("mirror") && !s.contains("$3") && s.contains("dashboard port"));
        assert!(fresh(100, 699) && !fresh(100, 700));
    }

    /// Runs the real probe script with stubbed tools: a correctly filtered
    /// namespace must exit 0, a leaky one must name the failing step.
    #[test]
    fn egress_probe_script_runs() {
        let run = |leaky: bool| {
            let curl = if leaky { "return 0" } else { r#"case "$*" in *5000*|*github*) return 0;; *) return 7;; esac"# };
            let script = format!("sysctl(){{ :; }}; nft(){{ :; }}; curl(){{ {curl}; }}\n{}", egress_script(true, true));
            std::process::Command::new("sh").args(["-c", &script, "sh", "x.nft", "7878", "100.1.2.3"]).output().unwrap()
        };
        assert!(run(false).status.success());
        let leaky = run(true);
        assert!(!leaky.status.success() && String::from_utf8_lossy(&leaky.stdout).contains("step: dashboard port reachable"));
    }

    /// Runs the guest's job-started hook (kiln-prejob.sh, cut out of the recipe)
    /// against event payloads. Skipped where bash or jq is missing.
    #[test]
    fn prejob_hook_refuses_forks() {
        let have = |b: &str| std::process::Command::new(b).arg("--version").output().is_ok_and(|o| o.status.success());
        // The guest's bash is 5.x; macOS ships 3.2, which lacks ${x,,}.
        let bash4 = || std::process::Command::new("bash").args(["-c", "((BASH_VERSINFO[0] >= 4))"]).status().is_ok_and(|s| s.success());
        if !have("bash") || !have("jq") || !bash4() {
            eprintln!("skipping: bash 4+ and jq needed");
            return;
        }
        let yaml = include_str!("../guest/user-data.yaml");
        let body = yaml.split("path: /usr/local/sbin/kiln-prejob.sh").nth(1).unwrap().split_once("content: |\n").unwrap().1;
        let script: String = body
            .lines()
            .take_while(|l| l.is_empty() || l.starts_with("      "))
            .map(|l| format!("{}\n", l.get(6..).unwrap_or("")))
            .collect();
        assert!(script.starts_with("#!/bin/bash"));
        let dir = std::env::temp_dir().join(format!("kiln-prejob-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let run = |payload: Option<serde_json::Value>| {
            let p = dir.join("event.json");
            let _ = std::fs::remove_file(&p);
            if let Some(v) = payload {
                std::fs::write(&p, v.to_string()).unwrap();
            }
            std::process::Command::new("bash")
                .args(["-c", &script])
                .env("GITHUB_EVENT_PATH", &p)
                .env("GITHUB_REPOSITORY", "Bunty9/kiln")
                .output()
                .unwrap()
                .status
                .success()
        };
        let pr = |head: serde_json::Value| serde_json::json!({ "pull_request": { "head": { "repo": head } } });
        assert!(run(Some(pr(serde_json::json!({ "full_name": "bunty9/KILN" })))), "same-repo PR");
        assert!(!run(Some(pr(serde_json::json!({ "full_name": "evil/kiln" })))), "fork PR");
        assert!(!run(Some(pr(serde_json::Value::Null))), "deleted fork");
        assert!(run(Some(serde_json::json!({ "ref": "refs/heads/main", "head_commit": {} }))), "push");
        let wr = |head: serde_json::Value| serde_json::json!({ "workflow_run": { "head_repository": head } });
        assert!(!run(Some(wr(serde_json::json!({ "full_name": "evil/kiln" })))), "workflow_run from a fork");
        assert!(run(Some(wr(serde_json::json!({ "full_name": "Bunty9/kiln" })))), "workflow_run same repo");
        assert!(!run(Some(serde_json::json!({ "workflow_run": {} }))), "workflow_run, head repo missing");
        assert!(!run(None), "missing payload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backoff_growth() {
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(4), 480);
        assert_eq!(backoff_secs(5), 900);
        assert_eq!(backoff_secs(50), 900);
    }

    #[test]
    fn console_lines() {
        let mut v = vm("a", State::Booting, None);
        assert!(apply_line(&mut v, "2026-10-06 10:00:01Z: Listening for Jobs\n", 100));
        assert_eq!((v.state, v.online_at), (State::Idle, Some(100)));
        assert!(apply_line(&mut v, "x: Running job: build\n", 120));
        assert_eq!((v.state, v.job.as_deref(), v.busy_since), (State::Busy, Some("build"), Some(120)));
        assert!(!apply_line(&mut v, "x: Job build completed with result: Failed", 130));
        assert_eq!(v.result.as_deref(), Some("Failed"));
        assert!(!apply_line(&mut v, "Runner update in progress, do not shutdown runner.", 140));
        assert!(v.note.as_deref().unwrap().contains("self-updating"));
        // A job echoing lifecycle lines itself can't rewind state, restart its
        // timeout or rewrite its result.
        assert!(!apply_line(&mut v, "Listening for Jobs", 500));
        assert!(!apply_line(&mut v, "x: Running job: again", 600));
        apply_line(&mut v, "Job x completed with result: Succeeded", 700);
        assert_eq!((v.state, v.busy_since, v.job.as_deref(), v.result.as_deref()), (State::Busy, Some(120), Some("build"), Some("Failed")));
        let cfg = crate::Config { idle_timeout_mins: 10, job_timeout_mins: 60, debug_hold_mins: 30, ..Default::default() };
        assert_eq!(start_cap(&cfg, false), 100 * 60 + 300);
        let cfg = crate::Config { warm_recycle_mins: 30, ..cfg };
        assert_eq!(start_cap(&cfg, true), 125 * 60 + 300);
    }

    #[test]
    fn warm_math() {
        assert_eq!(launch_split(0, 0, 2), (0, 2));
        assert_eq!(launch_split(3, 1, 2), (2, 2));
        assert_eq!(launch_split(0, 3, 2), (0, 0));
        assert_eq!(launch_split(1, 2, 2), (0, 1));
        assert_eq!(launch_split(2, 2, 1), (0, 1));
        assert_eq!(launch_split(5, 0, 0), (5, 0));
        assert_eq!((surplus(3, 1, 1), surplus(2, 1, 1), surplus(1, 2, 1), surplus(2, 0, 0)), (1, 0, 0, 2));
    }

    #[test]
    fn no_bake_while_updating_or_stopping() {
        assert_eq!(bake_refused(false, false), None);
        assert_eq!(bake_refused(true, false), Some("kiln is updating"));
        assert_eq!(bake_refused(false, true), Some("kiln is stopping"));
        assert!(bake_refused(true, true).is_some());
    }

    #[test]
    fn auto_update_blockers() {
        let w = |s| Vm { warm: true, ..vm("w", s, None) };
        // real work blocks: a job, a demand VM about to take one, a debug hold
        for v in [vm("a", State::Busy, None), vm("b", State::Booting, None), vm("c", State::Idle, Some(1)), vm("d", State::Held, None)] {
            assert!(v.blocks_auto_update(), "{:?}", v.state);
        }
        // the warm pool does not (the drain reaps it), unless GitHub already gave it a job
        assert!(!w(State::Booting).blocks_auto_update());
        assert!(!w(State::Idle).blocks_auto_update());
        assert!(Vm { job_url: Some("u".into()), ..w(State::Idle) }.blocks_auto_update());
        for s in [State::Done, State::Failed, State::Killed, State::Lost] {
            assert!(!vm("x", s, None).blocks_auto_update());
        }
    }

    #[test]
    fn warm_recycle_selection() {
        let w = |id: &str, online: u64, cache: CacheUse| Vm { warm: true, cache, ..vm(id, State::Idle, Some(online)) };
        // age: only the one online longer than 1800s at t=2000
        let vms = [w("old", 100, CacheUse::Read), w("young", 1500, CacheUse::Read)];
        let ids = |c: Vec<(String, u64)>| c.into_iter().map(|(i, _)| i).collect::<Vec<_>>();
        assert_eq!(ids(recycle_candidates(&vms, "O/N", 1800, 2000, false)), ["old"]);
        assert!(recycle_candidates(&vms, "o/n", 1800, 1900, false).is_empty());
        // parked commit, only idle warm readers: all recycled
        assert_eq!(ids(recycle_candidates(&vms, "o/n", 1800, 2000, true)), ["old", "young"]);
        // an idle job-less leftover (not warm) is flushed too; it is never aged out as warm
        let leftover = [w("a", 1500, CacheUse::Read), Vm { cache: CacheUse::Read, ..vm("b", State::Idle, Some(1)) }];
        assert_eq!(ids(recycle_candidates(&leftover, "o/n", 1800, 2000, true)), ["a", "b"]);
        assert!(recycle_candidates(&leftover[1..], "o/n", 1800, 9999, false).is_empty());
        // a busy reader or one GitHub already gave a job blocks the flush
        let mut blocked = leftover.to_vec();
        blocked[1] = Vm { cache: CacheUse::Read, ..vm("b", State::Busy, Some(1)) };
        assert!(recycle_candidates(&blocked, "o/n", 1800, 2000, true).is_empty());
        blocked[1] = Vm { job_url: Some("u".into()), ..w("b", 1500, CacheUse::Read) };
        assert!(recycle_candidates(&blocked, "o/n", 1800, 2000, true).is_empty());
        // nothing parked, nothing stale: nothing to do; other repos untouched
        assert!(recycle_candidates(&vms[1..], "o/n", 1800, 2000, false).is_empty());
        assert!(recycle_candidates(&vms, "x/y", 1800, 9999, true).is_empty());
        // taking a job clears warm
        let mut v = w("j", 1, CacheUse::Read);
        apply_line(&mut v, "x: Running job: build", 5);
        assert!(!v.warm);
    }

    #[test]
    fn reaping_picks_oldest_settled_idle() {
        let vms = [
            vm("new", State::Idle, Some(990)),
            vm("old", State::Idle, Some(100)),
            vm("mid", State::Idle, Some(500)),
            vm("busy", State::Busy, Some(1)),
            vm("booting", State::Booting, None),
        ];
        let ids = |n| reap_candidates(&vms, "o/n", 4, n, 1000).into_iter().map(|c| c.0).collect::<Vec<_>>();
        assert_eq!(ids(5), ["old", "mid"]);
        assert_eq!(ids(1), ["old"]);
        assert_eq!(reap_candidates(&vms, "O/N", 4, 1, 1000).len(), 1);
        assert!(reap_candidates(&vms, "other/repo", 4, 5, 1000).is_empty());
        let mut assigned = vm("assigned", State::Idle, Some(1));
        assigned.job_url = Some("https://github.com/o/n/actions/runs/1/job/2".into());
        assert!(reap_candidates(&[assigned], "o/n", 4, 5, 1000).is_empty());
        assert!(reap_candidates(&vms, "o/n", 8, 5, 1000).is_empty());
    }

    #[test]
    fn gates_and_parsers() {
        assert!(launch_gate(9300, 8192, Some(100), None, None).is_none());
        assert!(launch_gate(9300, 8192, None, None, None).is_none());
        assert_eq!(launch_gate(9300, 8192, Some(3), None, None).unwrap(), "low disk: 3 GB free");
        assert_eq!(launch_gate(9300, 8192, Some(12), Some(9523), None).unwrap(), "low disk: 12 GB free (docker mirror cache 9.3 GB)");
        assert_eq!(
            launch_gate(9300, 8192, Some(12), Some(9523), Some(2048)).unwrap(),
            "low disk: 12 GB free (docker mirror cache 9.3 GB, repo caches 2.0 GB)"
        );
        assert_eq!(launch_gate(9300, 8192, Some(12), None, Some(2048)).unwrap(), "low disk: 12 GB free (repo caches 2.0 GB)");
        assert!(launch_gate(5000, 8192, Some(100), None, None).unwrap().starts_with("not enough memory"));
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 40 62914560 40% /\n";
        assert_eq!(parse_df_kb(df), Some(62914560));
    }

    #[test]
    fn budget_limits() {
        // 32 GB host, one 8 GB / 4 vCPU VM running, 16 threads (24 vCPU budget)
        let mut b = Budget::new(32768, 8192, 4, 16);
        let (n, why) = b.take(5, 8192, 4);
        assert_eq!(n, 2); // (32768 - 8192 - 2048) / 8192
        assert_eq!(why.unwrap(), "memory budget: 8 GB committed of 32 GB");
        // 6 GB of memory left: one 4 GB VM fits, the second does not
        assert_eq!(b.take(2, 4096, 2).0, 1);
        assert!(b.take(0, 8192, 4).1.is_none());
        // plenty of memory, few threads: the vCPU budget (6 threads -> 9 vCPUs) limits
        let (n, why) = Budget::new(65536, 0, 4, 6).take(3, 2048, 4);
        assert_eq!(n, 1);
        assert_eq!(why.unwrap(), "cpu budget: 4 vCPUs committed of 9");
        assert_eq!(Budget::new(65536, 0, 0, 16).take(3, 8192, 4), (3, None));
        assert_eq!(Budget::new(3000, 0, 0, 16).take(1, 2048, 2).0, 0); // the 2 GB host reserve
    }

    #[test]
    fn hold_decisions() {
        let f = Some("Failed");
        assert_eq!(decide_msg(decide(30, true, true, f)), "hold 1800\n");
        assert_eq!(decide_msg(decide(30, true, true, None)), "release\n"); // no verdict yet: forced early ask
        assert_eq!(decide_msg(decide(30, true, true, Some("Succeeded"))), "release\n");
        assert_eq!(decide_msg(decide(0, true, true, f)), "release\n");
        assert_eq!(decide_msg(decide(30, false, true, f)), "release\n"); // no way in
        assert_eq!(decide_msg(decide(30, true, false, None)), "release\n"); // never ran a job
        assert_eq!(decide_msg(decide(30, true, true, Some("Cancelled"))), "hold 1800\n");
    }

    #[test]
    fn hostkeys_and_caps() {
        let mut v = vm("a", State::Busy, None);
        assert!(!apply_line(&mut v, "kiln: hostkey 256 SHA256:x", 1)); // only while held
        v.state = State::Held;
        for i in 0..6 {
            apply_line(&mut v, &format!("[   32.24] kiln-job[1395]: kiln: hostkey 256 SHA256:{i} (ED25519)\n"), 1);
        }
        assert_eq!(v.ssh_hostkeys.len(), 4);
        assert_eq!(v.ssh_hostkeys[0], "256 SHA256:0 (ED25519)");
        assert_eq!(room(10, 5), 5);
        assert_eq!(room(LOG_CAP - 2, 5), 2);
        assert_eq!(room(LOG_CAP, 5), 0);
        assert!(hmp_failed("Could not set up host forwarding rule 'tcp::1-:22'") && !hmp_failed("(qemu) "));
    }

    #[test]
    fn ssh_ports() {
        assert_eq!(alloc_port(&[], |_| true), Some(2200));
        assert_eq!(alloc_port(&[2200, 2201], |_| true), Some(2202));
        assert_eq!(alloc_port(&[2200], |p| p != 2201), Some(2202));
        assert_eq!(alloc_port(&[], |_| false), None);
        let all: Vec<u16> = (2200..2300).collect();
        assert_eq!(alloc_port(&all, |_| true), None);
    }

    #[test]
    fn key_validation() {
        assert!(valid_ssh_key("ssh-ed25519 AAAAC3 me@x"));
        assert!(valid_ssh_key("ecdsa-sha2-nistp256 AAAA"));
        assert!(valid_ssh_key("sk-ssh-ed25519@openssh.com AAAA"));
        assert!(!valid_ssh_key("ssh-ed25519"));
        assert!(!valid_ssh_key("rsa AAAA"));
        assert!(!valid_ssh_key("ssh-rsa AAAA\nssh-rsa BBBB"));
        assert!(!valid_ssh_key(""));
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(b64(b"ssh-a b\nssh-c d"), "c3NoLWEgYgpzc2gtYyBk");
    }

    #[test]
    fn stale_policy_selection() {
        let idle = |id: &str, p: &str| Vm { policy: p.into(), ..vm(id, State::Idle, Some(1)) };
        let vms = [
            idle("open", "open"),
            idle("filtered", "filtered"),
            Vm { policy: "open".into(), ..vm("busy", State::Busy, Some(1)) },
            Vm { job_url: Some("u".into()), ..idle("assigned", "open") },
        ];
        let ids: Vec<_> = stale_policy(&vms, "O/N", "filtered").into_iter().map(|(i, _)| i).collect();
        assert_eq!(ids, ["open"]);
        assert!(stale_policy(&vms, "o/n", "open").iter().all(|(i, _)| i == "filtered"));
        let mut cfg = crate::Config::default();
        let a = policy_id(&cfg);
        cfg.debug_ssh_keys = vec!["ssh-ed25519 AAAA x".into()];
        assert_ne!(a, policy_id(&cfg));
        cfg.max_vms = 7; // unrelated settings don't recycle VMs
        let same = crate::Config { debug_ssh_keys: vec!["ssh-ed25519 AAAA x".into()], ..Default::default() };
        assert_eq!(policy_id(&cfg), policy_id(&same));
    }

    #[test]
    fn lock_refusal_is_not_corruption() {
        assert!(is_lock_refusal("qemu-img commit: qemu-img: Failed to get \"write\" lock\nIs another process using the image [/x.qcow2]?"));
        assert!(!is_lock_refusal("qemu-img commit: Could not write to the backing file: No space left on device"));
    }

    #[test]
    fn rebake_reasons() {
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let cur = |w: &[&str]| serde_json::json!({ "recipe": RECIPE, "node_wanted": w });
        assert_eq!(rebake_reason(&cur(&["24"]), &n(&["24"]), &[]), None);
        // order does not matter: the bake sorts anyway
        assert_eq!(rebake_reason(&cur(&["20", "24"]), &n(&["24", "20"]), &[]), None);
        assert!(rebake_reason(&cur(&["24"]), &n(&["20", "24"]), &[]).unwrap().contains("bake_node_versions"));
        // an image from before the recipe marker lacks the fork hook, whatever its Node list
        assert!(rebake_reason(&serde_json::json!({ "runner_version": "2.338.0" }), &n(&["24"]), &[]).unwrap().contains("older kiln"));
        assert!(rebake_reason(&serde_json::json!({ "recipe": 1, "node_wanted": ["24"] }), &n(&["24"]), &[]).is_some());
        // recipe 2 had the PR hook but not the workflow_run check or Node checksums
        assert!(
            rebake_reason(&serde_json::json!({ "recipe": 2, "node_wanted": ["24"] }), &n(&["24"]), &[]).unwrap().contains("older kiln")
        );
        // and kiln launches nothing on it (nor on an image without a marker) until rebaked
        assert!(!image_recipe_ok(&serde_json::json!({ "recipe": 2 })) && !image_recipe_ok(&serde_json::json!({})));
        assert!(image_recipe_ok(&serde_json::json!({ "recipe": RECIPE })) && image_recipe_ok(&serde_json::json!({ "recipe": RECIPE + 1 })));
        // current recipe, no node_wanted recorded: Node 24
        assert_eq!(rebake_reason(&serde_json::json!({ "recipe": RECIPE }), &n(&["24"]), &[]), None);
        // apt packages: compared as sets; an image without apt_wanted had none
        let apt = |w: &[&str]| serde_json::json!({ "recipe": RECIPE, "node_wanted": ["24"], "apt_wanted": w });
        assert_eq!(rebake_reason(&apt(&["a", "b"]), &n(&["24"]), &n(&["b", "a"])), None);
        assert!(rebake_reason(&apt(&["a"]), &n(&["24"]), &n(&["a", "b"])).unwrap().contains("bake_apt_packages"));
        assert!(rebake_reason(&cur(&["24"]), &n(&["24"]), &n(&["chromium"])).unwrap().contains("bake_apt_packages"));
    }

    #[test]
    fn runner_versions() {
        assert_eq!(runner_version("v2.338.0").unwrap(), "2.338.0");
        assert_eq!(runner_version("2.10.11").unwrap(), "2.10.11");
        for bad in ["v2.338", "v2.338.0-rc1", "v2.338.0; reboot", "v2.338.0\n", "v2..0", "", "v", "v2.3a8.0", "vv2.338.0"] {
            assert!(runner_version(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn node_resolution() {
        let index = serde_json::json!([
            { "version": "v24.21.0" }, { "version": "v24.20.1" },
            { "version": "v22.20.0" }, { "version": "v20.19.5" }, { "version": "v20.19.4" },
        ]);
        let r = |w: &[&str]| resolve_node(&index, &w.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(r(&["24"]).unwrap(), ["24.21.0"]);
        // newest last whatever the configured order, no duplicates
        assert_eq!(r(&["24", "20"]).unwrap(), ["20.19.5", "24.21.0"]);
        assert_eq!(r(&["20", "20.19.5"]).unwrap(), ["20.19.5"]);
        assert_eq!(r(&["20.19.4"]).unwrap(), ["20.19.4"]);
        // "2" must not match 20.x or 24.x
        assert!(r(&["2"]).is_err());
        assert!(r(&["18"]).is_err());
        assert!(r(&["20.19.9"]).is_err());
        // numeric, not textual: 20.10.0 is newer than 20.9.0, and 8 is older than 10
        let index = serde_json::json!([
            { "version": "v20.9.0" }, { "version": "v10.0.0" }, { "version": "v20.10.0" }, { "version": "v8.17.0" },
            { "version": "v20.11.0;reboot" },
        ]);
        let r = |w: &[&str]| resolve_node(&index, &w.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(r(&["20"]).unwrap(), ["20.10.0"]);
        assert_eq!(r(&["10", "8"]).unwrap(), ["8.17.0", "10.0.0"]);
    }

    #[test]
    fn cache_trust_rules() {
        let t = |e, b, d| Ok::<_, &str>((e, b, d, "success"));
        assert!(cache_verdict(true, true, &[], t("push", "main", "main")).is_ok());
        // the console said Succeeded but GitHub disagrees (or has no conclusion yet)
        assert!(cache_verdict(true, true, &[], Ok(("push", "main", "main", "failure"))).unwrap_err().contains("failure"));
        assert!(cache_verdict(true, true, &[], Ok(("push", "main", "main", "none"))).is_err());
        assert_eq!(cache_verdict(true, true, &[], t("pull_request", "feat", "main")).unwrap_err(), "pull_request event");
        assert!(cache_verdict(true, true, &[], t("push", "feat", "main")).unwrap_err().contains("not the default"));
        assert!(cache_verdict(true, false, &[], t("push", "main", "main")).is_err());
        assert!(cache_verdict(false, true, &[], t("push", "main", "main")).is_err());
        assert!(cache_verdict(true, true, &[], Err("rate limited")).unwrap_err().contains("rate limited"));
        // extra writer branches: pushes only, and they never make a PR a writer
        let dev = ["dev".to_string()];
        assert!(cache_verdict(true, true, &dev, t("push", "dev", "main")).is_ok());
        assert!(cache_verdict(true, true, &dev, t("push", "main", "main")).is_ok());
        assert_eq!(cache_verdict(true, true, &dev, t("pull_request", "dev", "main")).unwrap_err(), "pull_request event");
        let e = cache_verdict(true, true, &dev, t("push", "feat", "main")).unwrap_err();
        assert!(e.contains("not the default") && e.contains("(dev)"), "{e}");
        assert!(cache_verdict(true, true, &dev, Ok(("push", "dev", "main", "failure"))).is_err());
        // a tag named like a writer arrives with a marked-up branch from cache_trust
        assert!(cache_verdict(true, true, &dev, t("push", "dev (commit abc1234 not on dev)", "main")).is_err());
    }

    #[test]
    fn cache_paths_and_limits() {
        assert_eq!(cache_file(Path::new("/d"), "Bunty9/Kiln"), Path::new("/d/cache/bunty9__kiln.qcow2"));
        assert!(!cache_too_big(36 << 30, 30));
        assert!(cache_too_big((36 << 30) + 1, 30));
        assert_eq!(job_id("https://github.com/o/n/actions/runs/1/job/22?pr=3"), Some(22));
        assert_eq!(job_id("https://github.com/o/n/actions/runs/1"), None);
        let mut a = vm("a", State::Busy, None);
        a.cache = CacheUse::Read;
        let mut b = vm("b", State::Busy, None);
        b.cache = CacheUse::Read;
        let mut c = vm("c", State::Done, None);
        c.cache = CacheUse::Read;
        let vms = [a, b, c];
        assert_eq!(cache_readers(&vms, "O/N", "a"), 1);
        assert_eq!(cache_readers(&vms, "o/n", "zz"), 2);
        assert_eq!(cache_readers(&vms, "x/y", "a"), 0);
    }

    #[test]
    fn guest_wiring_per_arch() {
        let has = |a: &[String], k: &str, v: &str| a.windows(2).any(|w| w[0] == k && w[1] == v);
        let d = Path::new("/d/vm");
        // x86: unchanged SMBIOS path plus fw_cfg, ttyS0 console, ttyS1 steps.
        let x = job_args(&X64, d, true);
        assert!(has(&x, "-append", "root=/dev/vda1 rootfstype=ext4 ro console=ttyS0 quiet panic=1"));
        assert!(has(&x, "-smbios", "type=11,path=/d/vm/jit") && has(&x, "-smbios", "type=11,path=/d/vm/ssh"));
        assert!(has(&x, "-fw_cfg", "name=opt/kiln/jit,file=/d/vm/jit") && has(&x, "-fw_cfg", "name=opt/kiln/ssh,file=/d/vm/ssh"));
        assert!(has(&x, "-serial", "stdio") && has(&x, "-chardev", "socket,id=s1,path=/d/vm/steps.sock,server=on,wait=off"));
        assert!(has(&x, "-serial", "chardev:s1"));
        // arm64: no SMBIOS without UEFI; PL011 console; steps on a virtio-serial port.
        let a = job_args(&ARM64, d, false);
        assert!(has(&a, "-append", "root=/dev/vda1 rootfstype=ext4 ro console=ttyAMA0 quiet panic=1"));
        assert!(!a.iter().any(|s| s == "-smbios" || s.contains("opt/kiln/ssh")));
        assert!(has(&a, "-fw_cfg", "name=opt/kiln/jit,file=/d/vm/jit") && has(&a, "-serial", "stdio"));
        assert!(has(&a, "-device", "virtserialport,chardev=s1,name=kiln.steps") && !has(&a, "-serial", "chardev:s1"));
        let argv = |g: &Guest| -> Vec<String> {
            let c = qemu(g, 4, 8192, Path::new("/d/disk.qcow2"), "");
            std::iter::once(c.as_std().get_program()).chain(c.as_std().get_args()).map(|s| s.to_string_lossy().into_owned()).collect()
        };
        let accel = if host::MACOS { "hvf" } else { "kvm" };
        assert_eq!(argv(&X64)[..3], ["qemu-system-x86_64", "-machine", &format!("q35,accel={accel}")]);
        assert_eq!(argv(&ARM64)[..3], ["qemu-system-aarch64", "-machine", &format!("virt,gic-version=3,accel={accel}")]);
        assert_eq!(cloud_files(&X64)[0], "noble-server-cloudimg-amd64.img");
        assert_eq!(cloud_files(&ARM64)[1], "unpacked/noble-server-cloudimg-arm64-vmlinuz-generic");
        assert_eq!(GUEST.gh, if host::ARM64 { "arm64" } else { "x64" });
    }

    #[test]
    fn recipe_per_arch() {
        let x = recipe(&X64, "2.338.0", "22.1.0 24.2.0", "chromium");
        assert!(!x.contains("{{"));
        assert!(x.contains("actions-runner-linux-x64-$V.tar.gz") && x.contains("T=node-v$N-linux-x64.tar.xz"));
        assert!(x.contains("/opt/hostedtoolcache/node/$N/x64.complete") && x.contains("serial-getty@ttyS0.service"));
        assert!(x.contains("exec 3</dev/ttyS0") && x.contains("exec >/dev/ttyS1") && x.contains("KILN_BAKE_OK > /dev/ttyS0"));
        assert!(x.contains("V=2.338.0") && x.contains("for N in 22.1.0 24.2.0;") && x.contains("APT_EXTRA=\"chromium\""));
        let a = recipe(&ARM64, "2.338.0", "24.2.0", "");
        assert!(!a.contains("{{") && !a.contains("x64") && !a.contains("ttyS"));
        assert!(a.contains("actions-runner-linux-arm64-$V.tar.gz") && a.contains("T=node-v$N-linux-arm64.tar.xz"));
        assert!(a.contains("serial-getty@ttyAMA0.service") && a.contains("exec 3</dev/ttyAMA0"));
        assert!(a.contains("exec >/dev/virtio-ports/kiln.steps") && a.contains("KILN_BAKE_OK > /dev/ttyAMA0"));
    }

    #[test]
    fn held_counts_as_active() {
        assert!(State::Held.is_active() && !State::Held.is_waiting());
    }

    #[test]
    fn image_staleness() {
        let day = 86400;
        assert_eq!(image_age(0, "2.1", Some("2.1"), 3 * day), (3, false));
        assert!(image_age(0, "2.1", Some("2.2"), day).1);
        assert!(image_age(0, "2.1", None, 26 * day).1);
        assert!(!image_age(0, "2.1", None, 25 * day).1);
    }
}
