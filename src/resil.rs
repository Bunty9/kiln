//! Host resilience: what keeps kiln alive and useful when the machine it shares is short of memory.
//!
//! - Each job VM runs in its own transient systemd scope (`kiln-vm-<id>.scope`), so systemd-oomd or the
//!   kernel OOM killer picks one VM, not the kiln service with every job in it. Falls back to a plain
//!   child (today's behaviour) where there is no systemd, as on macOS and in most containers.
//! - Launches hold while the host is stalling on memory (PSI), see [`pressure_gate`].
//! - io_uring rings count against the user's locked-memory limit, which other processes of the same
//!   user can exhaust: `qemu-img` then fails with [`IO_URING_FAIL`]. [`io_uring_exhausted`] spots it.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

// ---------------------------------------------------------------- per-VM cgroups

/// Unit name of a VM's scope.
fn unit(id: &str) -> String {
    format!("kiln-vm-{id}")
}

/// Memory cap of a VM's scope: guest RAM plus what QEMU, rootlesskit and slirp4netns need around it.
pub fn scope_mem_max_mb(mem_mb: u32) -> u64 {
    mem_mb as u64 + 1536
}

/// `systemd-run` arguments that run a VM's command in its own scope; the command follows.
/// `user`: the user manager (`--user`) rather than the system one (kiln running as root).
fn scope_args(user: bool, id: &str, mem_mb: u32) -> Vec<String> {
    let mut a: Vec<String> = vec![];
    if user {
        a.push("--user".into());
    }
    a.extend(["--scope".into(), "--quiet".into(), "--collect".into(), format!("--unit={}", unit(id))]);
    a.extend(["-p".into(), format!("MemoryMax={}M", scope_mem_max_mb(mem_mb)), "--".into()]);
    a
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// How long a failed scope probe stands before the next launch probes again.
const REPROBE: Duration = Duration::from_secs(300);

type Probe = Option<(std::time::Instant, Option<String>)>;

/// The last scope probe: when, and why not (None = it worked).
static PROBE: std::sync::Mutex<Probe> = std::sync::Mutex::new(None);

/// Whether the last probe still stands: a success for the life of the process, a failure for
/// [`REPROBE`] (the user manager may just have been busy at boot).
fn probe_fresh(p: &Probe) -> bool {
    p.as_ref().is_some_and(|(at, why)| why.is_none() || at.elapsed() < REPROBE)
}

/// Whether the last probe found scopes working (no probe, or a failed one, is false): the Actions cache trusts a
/// VM's cgroup scope to tell its connections from everyone else's.
pub fn scopes_ok() -> bool {
    PROBE.lock().unwrap().as_ref().is_some_and(|(_, why)| why.is_none())
}

/// Whether VMs get scopes: Linux with a working `systemd-run`.
async fn scopes_work() -> bool {
    scope_state().await.is_none()
}

/// None when scopes work, else why not.
async fn scope_state() -> Option<String> {
    {
        let p = PROBE.lock().unwrap();
        if probe_fresh(&p) {
            return p.as_ref().and_then(|(_, why)| why.clone());
        }
    }
    let why = probe_scopes().await;
    if let Some(w) = &why {
        tracing::info!(
            "job VMs share kiln's cgroup (systemd-run --scope unavailable: {w}); probing again in {} min",
            REPROBE.as_secs() / 60
        );
    }
    *PROBE.lock().unwrap() = Some((std::time::Instant::now(), why.clone()));
    why
}

/// One probe: a scope that does nothing.
async fn probe_scopes() -> Option<String> {
    if !cfg!(target_os = "linux") || !crate::platform::which("systemd-run") {
        return Some("no systemd-run".into());
    }
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let probe = format!("probe-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let mut c = Command::new("systemd-run");
    c.args(scope_args(!is_root(), &probe, 0)).arg("true").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    match tokio::time::timeout(Duration::from_secs(10), c.kill_on_drop(true).output()).await {
        Ok(Ok(o)) if o.status.success() => None,
        Ok(Ok(o)) => Some(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("timed out".into()),
    }
}

/// `cmd` (program and args as set) run in the VM's own scope, or `cmd` unchanged without systemd.
/// The environment is not copied: the caller clears and sets it after wrapping.
pub async fn in_scope(cmd: Command, id: &str, mem_mb: u32) -> Command {
    if !scopes_work().await {
        return cmd;
    }
    let std = cmd.as_std();
    let mut c = Command::new("systemd-run");
    c.args(scope_args(!is_root(), id, mem_mb)).arg(std.get_program()).args(std.get_args());
    c
}

/// Kill whatever is left in the VM's scope (QEMU after a killed rootlesskit, say). Cheap and
/// harmless when the scope is gone, which is the normal case: `--collect` removes it with its last process.
pub async fn stop_scope(id: &str) {
    if scopes_work().await {
        systemctl(&["kill", "--signal=SIGKILL", &format!("{}.scope", unit(id))]).await;
    }
}

/// At startup: kiln's VMs died with it (their records become Lost), but scopes outlive the service
/// they were started from, so stop any still around from a crash or a SIGKILLed kiln.
pub async fn reap_scopes() {
    if scopes_work().await {
        systemctl(&["kill", "--signal=SIGKILL", "kiln-vm-*.scope"]).await;
    }
}

async fn systemctl(args: &[&str]) {
    let mut c = Command::new("systemctl");
    if !is_root() {
        c.arg("--user");
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        c.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).status(),
    )
    .await;
}

/// Doctor's line: whether job VMs get their own cgroup. Without scopes it is a warning (ok: kiln
/// runs, just without the OOM protection), with the probe's reason.
pub async fn scope_check() -> (bool, String) {
    match scope_state().await {
        None => (true, "each job VM runs in its own systemd scope (memory pressure kills one VM, not kiln)".into()),
        Some(why) => (
            true,
            format!("warning: job VMs share kiln's cgroup ({why}): memory pressure may kill kiln with its jobs; retried every 5 minutes"),
        ),
    }
}

/// A VM that exited with SIGKILL or 137 although kiln did not kill it: the OOM killer or systemd-oomd.
pub fn looks_oom_killed(code: Option<i32>, signal: Option<i32>) -> bool {
    signal == Some(libc::SIGKILL) || code == Some(137)
}

pub const OOM_NOTE: &str = "killed: likely out of memory (host memory pressure or the VM's memory cap)";

// ---------------------------------------------------------------- memory pressure

/// Launches hold while memory stalls tasks for more than this share of the last 10 s (PSI `some avg10`).
pub const PSI_HOLD_PCT: f64 = 20.0;

/// `some avg10` of `/proc/pressure/memory`.
pub fn parse_psi(s: &str) -> Option<f64> {
    s.lines().find_map(|l| l.strip_prefix("some "))?.split_whitespace().find_map(|f| f.strip_prefix("avg10=")?.parse().ok())
}

/// The host's memory pressure now; None where the kernel has no PSI (or it is off).
pub fn memory_psi() -> Option<f64> {
    parse_psi(&std::fs::read_to_string("/proc/pressure/memory").ok()?)
}

/// Why no VM may start under this pressure, if so.
pub fn pressure_gate(psi: Option<f64>) -> Option<String> {
    psi.filter(|&p| p > PSI_HOLD_PCT)
        .map(|p| format!("host memory pressure: tasks stalled {p:.0}% of the last 10 s (limit {PSI_HOLD_PCT:.0}%); holding launches"))
}

// ---------------------------------------------------------------- io_uring

/// What qemu-img and QEMU print when io_uring cannot get locked memory.
pub const IO_URING_FAIL: &str = "Failed to initialize io_uring: Cannot allocate memory";

pub fn io_uring_exhausted(text: &str) -> bool {
    text.contains(IO_URING_FAIL)
}

/// `RLIMIT_MEMLOCK` soft limit in bytes (`None` = unlimited).
fn memlock_limit() -> Option<u64> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: r is a valid rlimit.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) } == 0;
    (ok && r.rlim_cur != libc::RLIM_INFINITY).then_some(r.rlim_cur)
}

/// The soft `RLIMIT_MEMLOCK` to set given the current soft limit (`None` = leave it). io_uring rings are
/// charged to this limit, shared by all of the user's processes; QEMU exits when it cannot get a ring but
/// falls back to epoll and threads when the limit is 0. Unlimited cannot be exhausted. Lowering the soft
/// limit never needs privilege and never exceeds the hard one.
#[cfg(any(target_os = "linux", test))]
pub fn memlock_target(soft: u64) -> Option<u64> {
    (soft != 0 && soft != libc::RLIM_INFINITY).then_some(0)
}

/// Lower our soft locked-memory limit so QEMU and qemu-img (children inherit it) never fight other
/// processes for io_uring memory. Nothing kiln runs needs locked memory.
#[cfg(target_os = "linux")]
pub fn lower_memlock() {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: r is a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) } != 0 {
        return;
    }
    let Some(t) = memlock_target(r.rlim_cur) else { return };
    let was = r.rlim_cur;
    r.rlim_cur = t;
    // SAFETY: r is a valid rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) } == 0 {
        tracing::info!("lowered the soft locked-memory limit from {} KiB to 0 so QEMU does not use io_uring", was >> 10);
    } else {
        tracing::warn!("could not lower RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lower_memlock() {}

pub fn io_uring_message(limit: Option<u64>) -> String {
    let l = limit.map_or("unlimited".to_string(), |b| format!("{} MiB", b >> 20));
    format!(
        "io_uring: locked-memory limit reached (RLIMIT_MEMLOCK {l}; other processes of this user hold io_uring memory). \
         kiln normally lowers its own limit to avoid this; see Troubleshooting in configuration.md"
    )
}

/// Banner text while launches wait on io_uring.
pub fn io_uring_banner() -> String {
    io_uring_message(memlock_limit())
}

/// Doctor: set up and tear down a ring like QEMU's (128 entries). Linux only.
#[cfg(target_os = "linux")]
pub fn io_uring_check() -> (bool, String) {
    if memlock_limit() == Some(0) {
        return (true, "QEMU does not use io_uring (RLIMIT_MEMLOCK soft limit 0): other processes cannot exhaust it".into());
    }
    // struct io_uring_params is 120 bytes; the kernel fills it.
    let mut params = [0u8; 120];
    // SAFETY: io_uring_setup(entries, params*) with a buffer of the size the kernel expects.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 128u32, params.as_mut_ptr()) };
    if fd >= 0 {
        // SAFETY: fd is a descriptor just returned to us.
        unsafe { libc::close(fd as i32) };
        return (true, "rings can be created".into());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOMEM) => (false, io_uring_message(memlock_limit())),
        Some(libc::ENOSYS | libc::EPERM) => (true, "io_uring is disabled on this kernel; QEMU uses threads instead".into()),
        e => (false, format!("io_uring_setup failed (errno {})", e.unwrap_or(0))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn io_uring_check() -> (bool, String) {
    (true, "not applicable".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_uring_failure_text_is_recognised() {
        assert!(io_uring_exhausted("qemu-img create: qemu-img: Failed to initialize io_uring: Cannot allocate memory\n"));
        assert!(!io_uring_exhausted("qemu-img create: No space left on device"));
        assert!(io_uring_message(Some(8 << 20)).contains("RLIMIT_MEMLOCK 8 MiB"));
        assert!(io_uring_message(None).contains("unlimited"));
    }

    #[test]
    fn a_failed_scope_probe_expires_a_good_one_does_not() {
        use std::time::Instant;
        let old = Instant::now().checked_sub(REPROBE * 2).unwrap();
        assert!(!probe_fresh(&None));
        assert!(probe_fresh(&Some((Instant::now(), None))));
        assert!(probe_fresh(&Some((old, None))));
        assert!(probe_fresh(&Some((Instant::now(), Some("busy".into())))));
        assert!(!probe_fresh(&Some((old, Some("busy".into())))));
    }

    #[test]
    fn memlock_is_lowered_unless_unlimited_or_zero() {
        assert_eq!(memlock_target(8 << 20), Some(0));
        assert_eq!(memlock_target(0), None);
        assert_eq!(memlock_target(libc::RLIM_INFINITY), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lowered_memlock_is_inherited() {
        // Lowered in a forked child only, so other tests keep their limits.
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "ulimit -l"]);
        // SAFETY: the closure only calls getrlimit/setrlimit (and logs, which is a no-op without a subscriber).
        unsafe {
            c.pre_exec(|| {
                lower_memlock();
                Ok(())
            })
        };
        let out = c.output().unwrap();
        let v = String::from_utf8_lossy(&out.stdout);
        assert!(["0", "unlimited"].contains(&v.trim()), "got {v}");
    }

    #[test]
    fn psi_is_parsed_and_gated() {
        let s = "some avg10=34.50 avg60=10.00 avg300=2.00 total=123\nfull avg10=50.00 avg60=0.00 avg300=0.00 total=9\n";
        assert_eq!(parse_psi(s), Some(34.5));
        assert_eq!(parse_psi("full avg10=1.00\n"), None);
        assert_eq!(parse_psi(""), None);
        assert!(pressure_gate(Some(34.5)).unwrap().contains("holding launches"));
        assert!(pressure_gate(Some(20.0)).is_none(), "the limit itself is fine");
        assert!(pressure_gate(Some(3.0)).is_none());
        assert!(pressure_gate(None).is_none(), "no PSI, no gate");
    }

    #[test]
    fn scope_command_is_built() {
        let a = scope_args(true, "kiln-1-0", 4096);
        assert_eq!(a, ["--user", "--scope", "--quiet", "--collect", "--unit=kiln-vm-kiln-1-0", "-p", "MemoryMax=5632M", "--"]);
        assert!(!scope_args(false, "x", 0).contains(&"--user".to_string()));
    }

    #[test]
    fn oom_kill_is_told_from_a_normal_exit() {
        assert!(looks_oom_killed(None, Some(9)));
        assert!(looks_oom_killed(Some(137), None));
        assert!(!looks_oom_killed(Some(1), None));
        assert!(!looks_oom_killed(None, Some(15)));
    }

    #[tokio::test]
    async fn a_process_runs_in_its_own_scope_and_dies_with_it() {
        // Only where a user manager is reachable; elsewhere the wrapper must hand back the command untouched.
        let mut c = Command::new("sleep");
        c.arg("30");
        let id = format!("test-{}", std::process::id());
        let mut w = in_scope(c, &id, 64).await;
        let prog = w.as_std().get_program().to_owned();
        if prog == "sleep" {
            return;
        }
        assert_eq!(prog, "systemd-run");
        let mut child = w.stdin(Stdio::null()).spawn().unwrap();
        let pid = child.id().unwrap();
        let mut cg = String::new();
        for _ in 0..50 {
            cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
            if cg.contains(&unit(&id)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(cg.contains(&format!("{}.scope", unit(&id))), "cgroup was {cg:?}");
        stop_scope(&id).await;
        assert!(!child.wait().await.unwrap().success());
    }
}
