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
    pub started: u64,
    pub busy_since: Option<u64>,
    pub ended: Option<u64>,
    pub note: Option<String>,
}

const KEEP_HISTORY: usize = 200;

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

fn persist(app: &App, v: &Vm) {
    let path = app.data.join("vms").join(&v.id).join("meta.json");
    if let Err(e) = std::fs::write(&path, serde_json::to_vec_pretty(v).unwrap_or_default()) {
        tracing::warn!("write {}: {e}", path.display());
    }
}

/// Register the VM synchronously (so the next scheduler tick counts it), then
/// boot it in the background.
pub fn launch(app: Arc<App>, repo: String) {
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
        started: now(),
        busy_since: None,
        ended: None,
        note: None,
    };
    app.vms.lock().unwrap().push(vm);
    tokio::spawn(async move {
        let dir = app.data.join("vms").join(&id);
        let outcome = run(&app, &id, &repo, &dir).await;
        // Never leave a big overlay or a credential behind, whatever happened.
        let _ = tokio::fs::remove_file(dir.join("disk.qcow2")).await;
        let _ = tokio::fs::remove_file(dir.join("jit")).await;
        app.kills.lock().unwrap().remove(&id);
        let v = update(&app, &id, |v| {
            v.ended = Some(now());
            match outcome {
                Ok(killed) if killed => v.state = State::Killed,
                Ok(_) if v.result.as_deref() == Some("Succeeded") => v.state = State::Done,
                Ok(_) if v.job.is_none() => {
                    v.state = State::Failed;
                    v.note.get_or_insert("VM exited without running a job".into());
                }
                Ok(_) => v.state = State::Failed,
                Err(e) => {
                    v.state = State::Failed;
                    v.note = Some(format!("{e:#}"));
                }
            }
        });
        if let Some(v) = v {
            tracing::info!("{} {:?} job={:?} result={:?}", v.id, v.state, v.job, v.result);
            // A JIT runner that never ran a job stays registered (offline) on GitHub.
            if let (Some(rid), None) = (v.runner_id, &v.job)
                && let Err(e) = app.gh.delete_runner(&v.repo, rid).await {
                    tracing::warn!("{}: {e:#}", v.id);
                }
            persist(&app, &v);
        }
        prune(&app);
    });
}

/// Ok(true) = killed (by user or a timeout), Ok(false) = guest powered off on its own.
async fn run(app: &Arc<App>, id: &str, repo: &str, dir: &Path) -> Result<bool> {
    let cfg = app.cfg();
    tokio::fs::create_dir_all(dir).await?;
    if let Some(v) = update(app, id, |_| {}) {
        persist(app, &v);
    }

    let (runner_id, jit) = app.gh.jit_config(repo, id, &cfg.runner_labels()).await?;
    update(app, id, |v| v.runner_id = Some(runner_id));
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

    let mut cmd = qemu(cfg.vm_cpus, cfg.vm_mem_mb, &disk);
    // Direct kernel boot without initrd: virtio + ext4 are built into the
    // Ubuntu kernel, which brings boot-to-runner down to ~4s.
    cmd.arg("-kernel").arg(images(&app.data).join("base.vmlinuz"));
    cmd.args(["-append", "root=/dev/vda1 rootfstype=ext4 ro console=ttyS0 quiet"]);
    cmd.arg("-smbios").arg(format!("type=11,path={}", dir.join("jit").display()));
    cmd.arg("-serial").arg("stdio");
    cmd.arg("-serial").arg(format!("file:{}", dir.join("steps.log").display()));
    let console = tokio::fs::File::create(dir.join("console.log")).await?;
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(console.into_std().await);
    let mut child = cmd.spawn().context("spawning qemu-system-x86_64")?;

    let kill = Arc::new(tokio::sync::Notify::new());
    app.kills.lock().unwrap().insert(id.to_string(), kill.clone());

    let mut log = tokio::fs::OpenOptions::new().append(true).open(dir.join("console.log")).await?;
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut buf = Vec::new();
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
                log.write_all(&buf).await?;
                observe(app, id, &String::from_utf8_lossy(&buf));
            }
            _ = kill.notified() => {
                child.kill().await.ok();
                note(app, id, "killed from dashboard");
                return Ok(true);
            }
            _ = tokio::time::sleep(left) => {
                child.kill().await.ok();
                note(app, id, "timed out");
                return Ok(true);
            }
        }
    }
    let status = child.wait().await?;
    if !status.success() {
        bail!("qemu exited with {status}; see console log");
    }
    Ok(false)
}

fn note(app: &App, id: &str, msg: &str) {
    update(app, id, |v| v.note = Some(msg.into()));
}

/// Track runner lifecycle from its stdout, e.g.
/// `2026-10-06 10:00:01Z: Listening for Jobs`
/// `2026-10-06 10:00:05Z: Running job: build`
/// `2026-10-06 10:01:40Z: Job build completed with result: Succeeded`
fn observe(app: &App, id: &str, line: &str) {
    let line = line.trim_end();
    if line.contains("Listening for Jobs") {
        update(app, id, |v| v.state = State::Idle);
    } else if let Some((_, job)) = line.split_once("Running job: ") {
        update(app, id, |v| {
            v.state = State::Busy;
            v.job = Some(job.trim().to_string());
            v.busy_since = Some(now());
        });
    } else if let Some((_, result)) = line.split_once("completed with result: ") {
        update(app, id, |v| v.result = Some(result.trim().to_string()));
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
    let r = bake_inner(&app).await;
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
    if !CLOUD_FILES.iter().all(|f| local(f).exists()) {
        for f in CLOUD_FILES {
            say(format!("downloading {CLOUD}/{f}")).await?;
            let part = img.join("download.part");
            let url = format!("{CLOUD}/{f}");
            sh(&log, Command::new("curl").args(["-fL", "--no-progress-meter", "-o"]).arg(&part).arg(url)).await?;
            tokio::fs::rename(&part, local(f)).await?;
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
    let status = loop {
        let done = tokio::select! {
            s = child.wait() => Some(s?),
            _ = tokio::time::sleep(Duration::from_secs(1)) => None,
        };
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
    tokio::fs::copy(&kernel, img.join("base.vmlinuz")).await?;
    tokio::fs::rename(&disk, img.join("base.qcow2")).await?;
    let meta = serde_json::json!({ "baked_at": now(), "runner_version": version });
    tokio::fs::write(img.join("base.json"), meta.to_string()).await?;
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
