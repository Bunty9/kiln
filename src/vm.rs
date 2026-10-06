//! Job VMs: one throwaway QEMU/KVM guest per GitHub Actions job.
//!
//! Rootless by design: KVM access + QEMU user-mode networking, no tap devices,
//! no bridges, no sudo. Each job boots a qcow2 overlay of the baked base image,
//! so the base never changes and a job's writes vanish with its overlay.

use crate::{App, now};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    /// Was active when kiln stopped; its QEMU died with us.
    Lost,
}

impl State {
    /// Will take the next queued job without us launching another VM.
    pub fn is_waiting(self) -> bool {
        matches!(self, State::Booting | State::Idle)
    }
    pub fn is_active(self) -> bool {
        matches!(self, State::Booting | State::Idle | State::Busy)
    }
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
}

const KEEP_HISTORY: usize = 200;
/// console.log stops growing here (parsing continues).
const LOG_CAP: usize = 64 << 20;

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
pub fn launch(app: Arc<App>, repo: String, cpus: u32) {
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
    };
    // Registered before the task starts so Kill and shutdown also work during JIT/qemu-img.
    let kill = Arc::new(tokio::sync::Notify::new());
    app.kills.lock().unwrap().insert(id.clone(), kill.clone());
    app.vms.lock().unwrap().push(vm);
    tokio::spawn(async move {
        let dir = app.data.join("vms").join(&id);
        let outcome = run(&app, &id, &repo, &dir, &kill).await;
        // Never leave a big overlay or a credential behind, whatever happened.
        let _ = tokio::fs::remove_file(dir.join("disk.qcow2")).await;
        let _ = tokio::fs::remove_file(dir.join("jit")).await;
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
                && let Err(e) = app.gh.delete_runner(&v.repo, rid).await {
                    tracing::warn!("{}: {e:#}", v.id);
                }
            persist(&app, &v);
        }
        // Last: shutdown waits on `kills` to know cleanup is complete.
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
    for (id, rid) in c {
        if app.gh.delete_runner(repo, rid).await.is_err() {
            continue;
        }
        note(app, &id, "no job left for this runner");
        if let Some(k) = app.kills.lock().unwrap().get(&id) {
            k.notify_one();
        }
    }
}

/// The state the VM ends in (Killed, Failed or Done); Err = infrastructure failure.
async fn run(app: &Arc<App>, id: &str, repo: &str, dir: &Path, kill: &tokio::sync::Notify) -> Result<State> {
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
    // Delivered as an SMBIOS OEM string: works with the stock cloud kernel
    // (fw_cfg needs a module it lacks), and `path=` keeps it out of `ps`.
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

    let mut cmd = qemu(cpus, mem_mb, &disk);
    // Direct kernel boot without initrd: virtio + ext4 are built into the
    // Ubuntu kernel, which brings boot-to-runner down to ~4s. panic=1 + -no-reboot
    // make a kernel panic end the VM instead of hanging until the timeout.
    cmd.arg("-kernel").arg(images(&app.data).join("base.vmlinuz"));
    cmd.args(["-append", "root=/dev/vda1 rootfstype=ext4 ro console=ttyS0 quiet panic=1"]);
    cmd.arg("-smbios").arg(format!("type=11,path={}", dir.join("jit").display()));
    cmd.arg("-serial").arg("stdio");
    cmd.arg("-serial").arg(format!("file:{}", dir.join("steps.log").display()));
    let console = tokio::fs::File::create(dir.join("console.log")).await?;
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(console.into_std().await);
    let mut child = cmd.spawn().context("spawning qemu-system-x86_64")?;

    let mut log = tokio::fs::OpenOptions::new().append(true).open(dir.join("console.log")).await?;
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut buf = Vec::new();
    let (mut first, mut logged) = (true, 0);
    loop {
        // Idle VMs are reaped quickly; busy ones get the full job timeout.
        let v = update(app, id, |_| {}).context("vm vanished")?;
        let deadline = match v.busy_since {
            Some(t) => t + cfg.job_timeout_mins * 60,
            None => v.started + cfg.idle_timeout_mins * 60,
        };
        let left = Duration::from_secs(deadline.saturating_sub(now()));
        buf.clear();
        tokio::select! {
            r = lines.read_until(b'\n', &mut buf) => {
                if r? == 0 {
                    break; // guest powered off, QEMU closed stdout
                }
                if first {
                    // QEMU read the SMBIOS file before the guest printed anything.
                    first = false;
                    let _ = tokio::fs::remove_file(dir.join("jit")).await;
                }
                if logged < LOG_CAP {
                    log.write_all(&buf).await?;
                    logged += buf.len();
                }
                observe(app, id, &String::from_utf8_lossy(&buf));
            }
            _ = kill.notified() => {
                child.kill().await.ok();
                kill_note(app, id);
                return Ok(State::Killed);
            }
            _ = tokio::time::sleep(left) => {
                child.kill().await.ok();
                if v.busy_since.is_some() {
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
    if let Some(v) = update(app, id, |v| save = apply_line(v, line, now())) && save {
        persist(app, &v);
    }
}

/// Returns true when the change is worth persisting right away.
fn apply_line(v: &mut Vm, line: &str, t: u64) -> bool {
    let line = line.trim_end();
    if line.contains("Listening for Jobs") {
        v.state = State::Idle;
        v.online_at.get_or_insert(t);
        true
    } else if let Some((_, job)) = line.split_once("Running job: ") {
        v.state = State::Busy;
        v.job = Some(job.trim().to_string());
        v.busy_since = Some(t);
        true
    } else if let Some((_, result)) = line.split_once("completed with result: ") {
        v.result = Some(result.trim().to_string());
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

/// Common QEMU flags for both bake and job VMs.
fn qemu(cpus: u32, mem_mb: u32, disk: &Path) -> Command {
    let mut c = Command::new("qemu-system-x86_64");
    c.args(["-machine", "q35,accel=kvm", "-cpu", "host", "-nodefaults", "-display", "none", "-no-reboot"])
        .args(["-smp", &cpus.to_string(), "-m", &mem_mb.to_string()])
        // cache=unsafe: the overlay is discarded after the job anyway, so skip fsyncs.
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2,cache=unsafe,discard=unmap", disk.display()))
        .args(["-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"])
        .args(["-device", "virtio-rng-pci"])
        .kill_on_drop(true);
    c
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
const CLOUD_FILES: [&str; 3] = [
    "noble-server-cloudimg-amd64.img",
    "unpacked/noble-server-cloudimg-amd64-vmlinuz-generic",
    "unpacked/noble-server-cloudimg-amd64-initrd-generic",
];

/// Build images/base.qcow2: Ubuntu cloud image + cloud-init recipe
/// (guest/user-data.yaml) booted once, then frozen.
pub async fn bake(app: Arc<App>) -> Result<()> {
    use std::sync::atomic::Ordering;
    if app.baking.swap(true, Ordering::SeqCst) {
        bail!("a bake is already running");
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
    for f in CLOUD_FILES {
        say(format!("fetching {CLOUD}/{f}")).await?;
        let _ = tokio::fs::remove_file(part(f)).await;
        let mut curl = Command::new("curl");
        curl.args(["-fLR", "--no-progress-meter", "--speed-limit", "1024", "--speed-time", "60", "-z"]).arg(local(f)).arg("-o").arg(part(f)).arg(format!("{CLOUD}/{f}"));
        sh(&log, &mut curl).await?;
    }
    for f in CLOUD_FILES {
        if part(f).exists() {
            tokio::fs::rename(part(f), local(f)).await?;
        }
    }
    let [cloud, kernel, initrd] = CLOUD_FILES.map(local);

    let rel = app.gh.raw(reqwest::Method::GET, "repos/actions/runner/releases/latest", None).await?;
    let tag: serde_json::Value = serde_json::from_slice(&rel.body)?;
    let version = tag["tag_name"].as_str().context("runner release tag")?.trim_start_matches('v').to_string();
    say(format!("actions runner {version}")).await?;

    let work = img.join("bake");
    let _ = tokio::fs::remove_dir_all(&work).await;
    tokio::fs::create_dir_all(work.join("seed")).await?;
    let user_data = include_str!("../guest/user-data.yaml").replace("{{RUNNER_VERSION}}", &version);
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
    let mut cmd = qemu(cfg.vm_cpus, cfg.vm_mem_mb.max(4096), &disk);
    cmd.arg("-kernel").arg(&kernel).arg("-initrd").arg(&initrd);
    cmd.args(["-append", "root=LABEL=cloudimg-rootfs ro console=ttyS0"]);
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
    let meta = serde_json::json!({ "baked_at": now(), "runner_version": version });
    tokio::fs::write(img.join("base.json.tmp"), meta.to_string()).await?;
    tokio::fs::rename(img.join("base.json.tmp"), img.join("base.json")).await?;
    let _ = tokio::fs::remove_dir_all(&work).await;
    say("base image ready".into()).await?;
    Ok(())
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

fn kb_of(meminfo: &str, key: &str) -> u64 {
    meminfo
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

pub fn meminfo_kb(key: &str) -> u64 {
    kb_of(&std::fs::read_to_string("/proc/meminfo").unwrap_or_default(), key)
}

pub fn mem_avail_mb() -> u64 {
    meminfo_kb("MemAvailable:") / 1024
}

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
pub fn launch_gate(mem_avail_mb: u64, vm_mem_mb: u32, disk_free_gb: Option<u64>, mirror_mb: Option<u64>) -> Option<String> {
    if mem_avail_mb < vm_mem_mb as u64 + 1024 {
        return Some(format!("not enough memory: {mem_avail_mb} MB free"));
    }
    disk_free_gb.filter(|&g| g < MIN_DISK_GB).map(|g| {
        let m = mirror_mb.map_or(String::new(), |m| format!(" (docker mirror cache {:.1} GB)", m as f64 / 1024.0));
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

/// images/base.json plus runner_latest, age_days and stale; null when never baked.
pub fn image_info(data: &Path, latest: Option<String>) -> serde_json::Value {
    let Some(mut v) = std::fs::read(images(data).join("base.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|v| v.is_object())
    else {
        return serde_json::Value::Null;
    };
    let (age, stale) = image_age(
        v["baked_at"].as_u64().unwrap_or(0),
        v["runner_version"].as_str().unwrap_or(""),
        latest.as_deref(),
        now(),
    );
    v["runner_latest"] = latest.into();
    v["age_days"] = age.into();
    v["stale"] = stale.into();
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

    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm");
    let groups = output("id", &["-nG"]).await.unwrap_or_default();
    let warn = if groups.split_whitespace().any(|g| g == "kvm") { "" } else { " (warning: current user is not in the kvm group)" };
    out.push(match kvm {
        Ok(_) => check("kvm", true, format!("/dev/kvm opens read/write{warn}")),
        Err(e) => check("kvm", false, format!("/dev/kvm: {e}{warn}")),
    });

    for bin in ["qemu-system-x86_64", "qemu-img", "xorriso", "curl", "tailscale"] {
        out.push(match output(bin, &["--version"]).await {
            Ok(v) => check(bin, true, v.lines().next().unwrap_or("").to_string()),
            Err(e) => check(bin, false, format!("{e:#}")),
        });
    }

    let disk = disk_free_gb(&app.data).await;
    out.push(match disk {
        Some(g) => check("disk", g >= MIN_DISK_GB, format!("{g} GB free (need {MIN_DISK_GB})")),
        None => check("disk", false, "df failed"),
    });

    let avail = mem_avail_mb();
    let want = cfg.max_vms as u64 * cfg.vm_mem_mb as u64;
    let note = if avail < want { "; not enough for all slots at once" } else { "" };
    out.push(check("memory", avail >= cfg.vm_mem_mb as u64, format!("{avail} MB available, {} x {} MB wanted{note}", cfg.max_vms, cfg.vm_mem_mb)));

    app.gh.refresh_latest().await;
    let info = image_info(&app.data, app.gh.latest_cached());
    out.push(if !image_ready(&app.data) {
        check("image", false, "not baked: run `kiln bake`")
    } else if info["stale"] == true {
        check("image", true, format!("warning: stale: {} days old, runner {} (latest {})", info["age_days"], info["runner_version"], info["runner_latest"]))
    } else {
        check("image", true, format!("runner {}, {} days old", info["runner_version"], info["age_days"]))
    });

    let src = app.gh.source();
    out.push(match (app.gh.has_token(), src) {
        (false, _) => check("token", false, "no token: set one in the dashboard, KILN_GITHUB_TOKEN, or `gh auth login`"),
        (true, "gh") => check("token", true, "from `gh auth token`; a keyring may be locked after a headless reboot, save it from the dashboard instead"),
        (true, s) => check("token", true, format!("source: {s}")),
    });
    for repo in &cfg.repos {
        let r = app.gh.raw(reqwest::Method::GET, &format!("repos/{repo}/actions/runners?per_page=1"), None).await;
        out.push(match r {
            Ok(r) if r.status == 200 => check(&format!("repo {repo}"), true, "runners API reachable"),
            Ok(r) => check(&format!("repo {repo}"), false, format!("runners API returned {}", r.status)),
            Err(e) => check(&format!("repo {repo}"), false, format!("{e:#}")),
        });
    }

    let (ok, detail) = crate::mirror::check(app).await;
    out.push(check("docker mirror", ok, detail));

    out.push(match output("tailscale", &["status", "--json"]).await {
        Ok(j) => {
            let v: serde_json::Value = serde_json::from_str(&j).unwrap_or_default();
            let st = v["BackendState"].as_str().unwrap_or("unknown");
            check("tailscale up", st == "Running", format!("BackendState {st}"))
        }
        Err(e) => check("tailscale up", false, format!("{e:#}")),
    });

    // QEMU processes of ours that no VM record accounts for (e.g. after a crash).
    let vms_dir = format!("{}/", app.data.join("vms").display());
    let stray = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .filter(|c| {
            let c = String::from_utf8_lossy(c);
            c.contains("qemu-system") && c.contains(&vms_dir)
        })
        .count();
    let active = app.vms.lock().unwrap().iter().any(|v| v.state.is_active());
    let serving = cli && tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(&cfg.listen)).await.is_ok_and(|r| r.is_ok());
    out.push(if stray > 0 && serving {
        check("stray qemu", true, format!("{stray} qemu process(es) owned by running kiln serve"))
    } else if stray > 0 && !active {
        check("stray qemu", false, format!("{stray} qemu process(es) running from {vms_dir} with no active VM (expected only if another kiln serve is running jobs)"))
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
        }
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
        assert!(launch_gate(9300, 8192, Some(100), None).is_none());
        assert!(launch_gate(9300, 8192, None, None).is_none());
        assert_eq!(launch_gate(9300, 8192, Some(3), None).unwrap(), "low disk: 3 GB free");
        assert_eq!(launch_gate(9300, 8192, Some(12), Some(9523)).unwrap(), "low disk: 12 GB free (docker mirror cache 9.3 GB)");
        assert!(launch_gate(5000, 8192, Some(100), None).unwrap().starts_with("not enough memory"));
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 40 62914560 40% /\n";
        assert_eq!(parse_df_kb(df), Some(62914560));
        assert_eq!(kb_of("MemTotal: 10 kB\nMemAvailable:    2048 kB\n", "MemAvailable:"), 2048);
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
    fn image_staleness() {
        let day = 86400;
        assert_eq!(image_age(0, "2.1", Some("2.1"), 3 * day), (3, false));
        assert!(image_age(0, "2.1", Some("2.2"), day).1);
        assert!(image_age(0, "2.1", None, 26 * day).1);
        assert!(!image_age(0, "2.1", None, 25 * day).1);
    }
}
