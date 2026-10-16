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

/// Whether VMs get scopes: Linux with a working `systemd-run`, probed once (a scope that does nothing).
async fn scopes_work() -> bool {
    static OK: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
    *OK.get_or_init(|| async {
        if !cfg!(target_os = "linux") || !crate::platform::which("systemd-run") {
            return false;
        }
        let probe = format!("probe-{}", std::process::id());
        let mut c = Command::new("systemd-run");
        c.args(scope_args(!is_root(), &probe, 0)).arg("true").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let r = tokio::time::timeout(Duration::from_secs(10), c.kill_on_drop(true).output()).await;
        match r {
            Ok(Ok(o)) if o.status.success() => true,
            other => {
                let why = match other {
                    Ok(Ok(o)) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "timed out".into(),
                };
                tracing::info!("job VMs share kiln's cgroup (systemd-run --scope unavailable: {why})");
                false
            }
        }
    })
    .await
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

/// Doctor's line: whether job VMs get their own cgroup.
pub async fn scope_check() -> (bool, String) {
    if scopes_work().await {
        (true, "each job VM runs in its own systemd scope (memory pressure kills one VM, not kiln)".into())
    } else {
        (true, "job VMs share kiln's cgroup (no systemd-run --scope): memory pressure may kill kiln with its jobs".into())
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

pub fn io_uring_message(limit: Option<u64>) -> String {
    let l = limit.map_or("unlimited".to_string(), |b| format!("{} MiB", b >> 20));
    format!(
        "io_uring: locked-memory limit reached (RLIMIT_MEMLOCK {l}; other processes of this user hold io_uring memory). \
         Raise LimitMEMLOCK for kiln (see Troubleshooting in configuration.md) or close those processes"
    )
}

/// Banner text while launches wait on io_uring.
pub fn io_uring_banner() -> String {
    io_uring_message(memlock_limit())
}

/// Doctor: set up and tear down a ring like QEMU's (128 entries). Linux only.
#[cfg(target_os = "linux")]
pub fn io_uring_check() -> (bool, String) {
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
