//! Confinement for a job VM's QEMU, in the spirit of libvirt's sVirt profile and seccomp
//! sandbox. A job is hostile and QEMU is what stands between it and the host: if a guest
//! ever escaped into QEMU, it would run as the kiln user, next to the GitHub token, the App
//! key and the dashboard key. So QEMU is started through `kiln __confine`, which applies a
//! Landlock ruleset to itself and then execs QEMU:
//!
//! - files: the system directories read-only, `/dev/kvm` and a few standard character
//!   devices (not the rest of `/dev`), and read-write only the VM's `q/` directory (its
//!   disks, JIT secret, sockets). The images directory and the repo's cache disk are
//!   readable; everything else under kiln's data directory (token, keys, the VM's own
//!   record and logs, other jobs) is not. kiln also strips GitHub tokens from its environment;
//! - no ptrace of processes outside the sandbox (kiln, other VMs); on Linux 6.12+ (ABI 6)
//!   no signals to them or abstract unix sockets either, and with ABI 9 no connecting to
//!   unix sockets elsewhere (tailscaled, docker).
//!
//! QEMU's own seccomp filter (`-sandbox`, see `vm::qemu`) adds no exec, no setuid and
//! no obsolete syscalls. Landlock is best effort: a kernel without it runs QEMU
//! unconfined, and `kiln doctor` says so.

use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope};
use std::ffi::OsString;
use std::path::PathBuf;

/// What the startup probe found: false means job VMs' QEMU runs unconfined.
pub static ENFORCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// The argv[1] that makes `main` run [`main`] instead of the service.
pub const ARG: &str = "__confine";

/// Read and execute: the programs and libraries QEMU loads, its firmware and config.
const SYSTEM: [&str; 6] = ["/usr", "/lib", "/lib64", "/bin", "/etc", "/opt"];
/// Read-only kernel interfaces QEMU inspects (CPU topology, its own fds and limits).
const KERNEL: [&str; 2] = ["/proc", "/sys"];
/// The device nodes QEMU opens, read-write with ioctls: KVM, and the usual character devices.
const DEVICES: [&str; 6] = ["/dev/kvm", "/dev/null", "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random"];

/// The read rule a data directory falls under, if any: then confined QEMU could read the token
/// and keys, so `serve` refuses to start there.
pub fn exposed(data: &std::path::Path) -> Option<&'static str> {
    let data = std::fs::canonicalize(data).unwrap_or_else(|_| data.to_path_buf());
    SYSTEM.into_iter().chain(KERNEL).find(|p| data.starts_with(p))
}

/// What a confined process may touch.
#[derive(Debug, Default, PartialEq)]
pub struct Policy {
    /// Read-write, including creating its sockets: the VM's `q/` directory.
    pub rw: Vec<PathBuf>,
    /// Read-only files or directories: the images directory, the repo's cache disk.
    pub ro: Vec<PathBuf>,
}

impl Policy {
    /// `kiln __confine` arguments that carry this policy, then `--` and the program.
    pub fn args(&self) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec![ARG.into()];
        for p in &self.rw {
            a.extend(["--rw".into(), p.into()]);
        }
        for p in &self.ro {
            a.extend(["--ro".into(), p.into()]);
        }
        a.push("--".into());
        a
    }

    /// Inverse of `args` (after `ARG`): the policy and the command to exec.
    fn parse(mut it: impl Iterator<Item = OsString>) -> Result<(Self, Vec<OsString>), String> {
        let mut p = Policy::default();
        loop {
            match it.next().as_ref().and_then(|a| a.to_str()) {
                Some("--rw") => p.rw.push(it.next().ok_or("--rw needs a path")?.into()),
                Some("--ro") => p.ro.push(it.next().ok_or("--ro needs a path")?.into()),
                Some("--") => break,
                other => return Err(format!("unexpected argument {other:?}")),
            }
        }
        let cmd: Vec<OsString> = it.collect();
        if cmd.is_empty() {
            return Err("no command after --".into());
        }
        Ok((p, cmd))
    }
}

/// Apply `p` to this thread (and so to whatever it execs). Err only for a ruleset kiln got
/// wrong; a kernel without (full) Landlock support is not an error: see the status.
pub fn restrict(p: &Policy) -> Result<RulesetStatus, landlock::RulesetError> {
    restrict_as(p, ABI::V9)
}

/// `restrict` asking for no more than `abi`'s features.
fn restrict_as(p: &Policy, abi: ABI) -> Result<RulesetStatus, landlock::RulesetError> {
    let read = AccessFs::from_read(abi);
    let read_only = read & !AccessFs::Execute;
    let all = AccessFs::from_all(abi);
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all)?
        .scope(Scope::from_all(abi))?
        .create()?
        .no_new_privs(true)
        .add_rules(landlock::path_beneath_rules(SYSTEM, read))?
        .add_rules(landlock::path_beneath_rules(KERNEL, read_only))?
        .add_rules(landlock::path_beneath_rules(DEVICES, read | AccessFs::from_write(abi)))?
        // slirp's DNS reads /etc/resolv.conf, which usually points into /run (systemd-resolved).
        .add_rules(landlock::path_beneath_rules(resolv_dir(), read_only))?
        .add_rules(landlock::path_beneath_rules(&p.ro, read_only))?
        .add_rules(landlock::path_beneath_rules(&p.rw, all & !AccessFs::Execute))?
        .restrict_self()?;
    Ok(status.ruleset)
}

/// Where `/etc/resolv.conf` really lives, when that is outside `/etc`: its directory
/// (systemd-resolved replaces the file, so a rule on the file alone goes stale), unless
/// that is a top-level one like `/run`, then the file only.
fn resolv_dir() -> Option<PathBuf> {
    let f = std::fs::canonicalize("/etc/resolv.conf").ok().filter(|f| !f.starts_with("/etc"))?;
    let dir = f.parent()?;
    Some(if dir.components().count() > 2 { dir.to_path_buf() } else { f })
}

/// `kiln __confine [--rw P]... [--ro P]... -- PROGRAM ARGS...`: confine, then exec.
/// Never returns; exit status 125 when it could not start the program.
pub fn main(args: impl Iterator<Item = OsString>) -> ! {
    use std::os::unix::process::CommandExt;
    let fail = |msg: String| -> ! {
        eprintln!("kiln confine: {msg}");
        std::process::exit(125)
    };
    let (p, cmd) = Policy::parse(args).unwrap_or_else(|e| fail(e));
    // Partly enforced is the norm on kernels older than the newest Landlock ABI: `kiln
    // doctor` reports which protections this kernel has.
    match restrict(&p) {
        Ok(RulesetStatus::NotEnforced) => eprintln!("kiln confine: Landlock unavailable on this kernel; QEMU runs unconfined"),
        Ok(_) => {}
        Err(e) => fail(format!("Landlock: {e}")),
    }
    let e = std::process::Command::new(&cmd[0]).args(&cmd[1..]).exec();
    fail(format!("exec {:?}: {e}", cmd[0]))
}

/// Landlock on this kernel, for `kiln doctor`: (ok, detail). ABI 6 (Linux 6.12) brings the
/// signal and abstract-socket scopes; ABI 9 also limits connecting to unix sockets.
pub fn probe() -> (bool, String) {
    // In a throwaway thread: the restriction sticks to the thread that applied it.
    let full = |abi| std::thread::spawn(move || restrict_as(&Policy::default(), abi).map_err(|e| e.to_string())).join();
    match (full(ABI::V9), full(ABI::V6)) {
        // What job VMs use: an error here means every VM would fail to start.
        (Ok(Err(e)), _) => (false, format!("Landlock: {e}")),
        (Ok(Ok(RulesetStatus::FullyEnforced)), _) => (true, "Landlock: job VMs' QEMU sees only its own files and sockets".into()),
        (_, Ok(Ok(RulesetStatus::FullyEnforced))) => {
            (true, "Landlock: job VMs' QEMU sees only its own files, cannot signal kiln (unix-socket limits need a newer kernel)".into())
        }
        (_, Ok(Ok(RulesetStatus::PartiallyEnforced))) => {
            (true, "warning: Landlock partly enforced (kernel older than 6.12): QEMU is confined to its files, not all scopes".into())
        }
        (_, Ok(Ok(RulesetStatus::NotEnforced))) => {
            (false, "Landlock unavailable (needs Linux 5.13+ with landlock in lsm=): job VMs' QEMU is not confined".into())
        }
        (_, Ok(Err(e))) => (false, format!("Landlock: {e}")),
        (_, Err(_)) => (false, "Landlock probe panicked".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_must_not_be_readable_by_qemu() {
        assert_eq!(exposed(std::path::Path::new("/opt/kiln-does-not-exist")), Some("/opt"));
        assert_eq!(exposed(std::path::Path::new("/etc/kiln")), Some("/etc"));
        assert_eq!(exposed(&std::env::temp_dir().join("kiln-data")), None);
        assert_eq!(exposed(std::path::Path::new("/optional/kiln")), None, "a prefix is not a parent");
    }

    #[test]
    fn args_round_trip() {
        let p = Policy { rw: vec!["/d/vms/x".into()], ro: vec!["/d/images/base.qcow2".into(), "/d/cache/o__n.qcow2".into()] };
        let mut a = p.args();
        assert_eq!(a.remove(0), ARG);
        a.extend(["qemu".into(), "-m".into(), "1024".into()]);
        let (q, cmd) = Policy::parse(a.into_iter()).unwrap();
        assert_eq!(q, p);
        assert_eq!(cmd, ["qemu", "-m", "1024"]);
        assert!(Policy::parse(["--rw".into()].into_iter()).is_err());
        assert!(Policy::parse(["--".into()].into_iter()).is_err(), "no command");
        assert!(Policy::parse(["qemu".into()].into_iter()).is_err(), "no --");
    }

    /// The real thing, in a child thread: files outside the policy are out of reach.
    #[test]
    fn confines_files() {
        let d = std::env::temp_dir().join(format!("kiln-test-confine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("vm")).unwrap();
        std::fs::write(d.join("token"), "secret").unwrap();
        std::fs::write(d.join("base"), "image").unwrap();
        std::fs::create_dir_all(d.join("other")).unwrap();
        std::fs::write(d.join("other/jit"), "x").unwrap();
        let (vm, token, base) = (d.join("vm"), d.join("token"), d.join("base"));
        let p = Policy { rw: vec![vm.clone()], ro: vec![base.clone()] };
        let r = std::thread::spawn(move || {
            let s = restrict(&p).unwrap();
            let other = std::fs::read(vm.parent().unwrap().join("other/jit")).is_ok();
            (
                s,
                std::fs::read(&token).is_ok() || other,
                std::fs::read(&base).is_ok(),
                std::fs::write(&base, "x").is_ok(),
                std::fs::write(vm.join("disk"), "x").is_ok(),
            )
        })
        .join()
        .unwrap();
        let _ = std::fs::remove_dir_all(&d);
        if r.0 == RulesetStatus::NotEnforced {
            // CI sets this: a kernel without Landlock must not hide a broken ruleset.
            assert!(std::env::var_os("KILN_REQUIRE_LANDLOCK").is_none(), "Landlock required but not enforced");
            eprintln!("Landlock not available here: skipped");
            return;
        }
        assert!(!r.1, "the token and other VMs' files are out of reach");
        assert!(r.2, "the base image is readable");
        assert!(!r.3, "but not writable");
        assert!(r.4, "the VM directory is writable");
    }
}
