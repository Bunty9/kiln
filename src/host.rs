//! What differs between the hosts kiln runs on: Linux (KVM) and macOS on Apple
//! Silicon (Hypervisor.framework). Guests always match the host's architecture,
//! so an aarch64 host runs arm64 guests and advertises arm64 runners.

use std::sync::LazyLock;

pub const MACOS: bool = cfg!(target_os = "macos");
/// Guests are arm64 (and runners advertise `ARM64`); x86_64 otherwise.
pub const ARM64: bool = cfg!(target_arch = "aarch64");
/// QEMU accelerator: Hypervisor.framework on macOS, KVM on Linux.
pub const ACCEL: &str = if MACOS { "hvf" } else { "kvm" };

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).chain(["/usr/sbin".into(), "/sbin".into()]).any(|d| d.join(bin).is_file()))
}

/// The Tailscale CLI. The macOS app does not put it on PATH unless asked to.
pub fn tailscale() -> &'static str {
    static BIN: LazyLock<&str> = LazyLock::new(|| {
        const APP: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
        if MACOS && !which("tailscale") && std::path::Path::new(APP).is_file() { APP } else { "tailscale" }
    });
    &BIN
}

/// Stdout of a short host command (sysctl, vm_stat, ps); empty on failure.
fn run(bin: &str, args: &[&str]) -> String {
    // ponytail: blocking, a few ms per call on macOS; sysctlbyname via libc if it ever shows up.
    std::process::Command::new(bin).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Can this process run hardware-accelerated VMs? (ok, detail) for `kiln doctor`.
pub fn hypervisor() -> (bool, String) {
    if MACOS {
        let hv = run("sysctl", &["-n", "kern.hv_support"]);
        return match hv.trim() {
            "1" => (true, "Hypervisor.framework available (kern.hv_support = 1)".into()),
            v => (false, format!("Hypervisor.framework unavailable (kern.hv_support = {:?})", v)),
        };
    }
    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm");
    // The running process's groups, not `id -nG`: a group added after login shows up
    // in `id` but not in processes started by the old user manager.
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let warn = match (kvm_gid(&group), proc_uid(&status)) {
        (Some(g), uid) if !has_gid(&status, g) => format!(
            " (kvm group not active for this process yet — restart the user manager (sudo systemctl restart user@{}) or reboot)",
            uid.map_or("<uid>".into(), |u| u.to_string())
        ),
        _ => String::new(),
    };
    match kvm {
        Ok(_) => (true, format!("/dev/kvm opens read/write{warn}")),
        Err(e) => (false, format!("/dev/kvm: {e}{warn}")),
    }
}

/// gid of the `kvm` group from /etc/group text.
fn kvm_gid(etc_group: &str) -> Option<u32> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == "kvm").then(|| f.nth(1)?.parse().ok())?
    })
}

/// Is `gid` among the `Groups:` of /proc/self/status text?
fn has_gid(status: &str, gid: u32) -> bool {
    status.lines().find_map(|l| l.strip_prefix("Groups:")).is_some_and(|g| g.split_whitespace().any(|x| x.parse() == Ok(gid)))
}

fn proc_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace().next()?.parse().ok()
}

fn kb_of(meminfo: &str, key: &str) -> u64 {
    meminfo.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)).and_then(|n| n.parse().ok()).unwrap_or(0)
}

fn meminfo_kb(key: &str) -> u64 {
    kb_of(&std::fs::read_to_string("/proc/meminfo").unwrap_or_default(), key)
}

pub fn mem_total_mb() -> u64 {
    if MACOS { run("sysctl", &["-n", "hw.memsize"]).trim().parse::<u64>().unwrap_or(0) >> 20 } else { meminfo_kb("MemTotal:") / 1024 }
}

pub fn mem_avail_mb() -> u64 {
    if MACOS { vm_stat_avail(&run("vm_stat", &[])) >> 20 } else { meminfo_kb("MemAvailable:") / 1024 }
}

/// Free + inactive pages of `vm_stat` output, in bytes: what macOS hands out without swapping.
/// `Mach Virtual Memory Statistics: (page size of 16384 bytes)` / `Pages free:   12345.`
fn vm_stat_avail(out: &str) -> u64 {
    let page =
        out.lines().next().and_then(|l| l.split("page size of ").nth(1)?.split_whitespace().next()?.parse::<u64>().ok()).unwrap_or(4096);
    let pages = |key: &str| {
        out.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.trim().trim_end_matches('.').parse::<u64>().ok()).unwrap_or(0)
    };
    (pages("Pages free:") + pages("Pages inactive:")) * page
}

/// 1, 5 and 15 minute load averages, as text.
pub fn load_avg() -> Vec<String> {
    let s = if MACOS { run("sysctl", &["-n", "vm.loadavg"]) } else { std::fs::read_to_string("/proc/loadavg").unwrap_or_default() };
    parse_load(&s)
}

/// `/proc/loadavg` ("0.52 0.58 0.59 1/389 1234") or `sysctl -n vm.loadavg` ("{ 1.62 1.85 1.93 }").
fn parse_load(s: &str) -> Vec<String> {
    s.split_whitespace().filter(|w| *w != "{" && *w != "}").take(3).map(String::from).collect()
}

/// Command lines of the host's processes, to spot QEMUs nobody accounts for.
pub fn process_cmdlines() -> Vec<String> {
    if MACOS {
        return parse_ps(&run("ps", &["-axww", "-o", "pid=,command="]));
    }
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .map(|c| String::from_utf8_lossy(&c).into_owned())
        .collect()
}

/// `ps -axww -o pid=,command=` (-ww: never cut long command lines) lines ("  412 /opt/homebrew/bin/qemu-system-aarch64 -machine ...") without the pid.
fn parse_ps(out: &str) -> Vec<String> {
    out.lines().filter_map(|l| Some(l.trim_start().split_once(' ')?.1.trim_start().to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvm_group_parsing() {
        assert_eq!(kvm_gid("root:x:0:\nkvm:x:993:kame\n"), Some(993));
        assert_eq!(kvm_gid("root:x:0:\n"), None);
        let st = "Name:\tkiln\nUid:\t1000\t1000\t1000\t1000\nGroups:\t4 27 993 1000\n";
        assert!(has_gid(st, 993) && !has_gid(st, 994));
        assert_eq!(proc_uid(st), Some(1000));
    }

    #[test]
    fn linux_parsers() {
        assert_eq!(kb_of("MemTotal: 10 kB\nMemAvailable:    2048 kB\n", "MemAvailable:"), 2048);
        assert_eq!(parse_load("0.52 0.58 0.59 1/389 1234\n"), ["0.52", "0.58", "0.59"]);
    }

    /// The real readings of whatever host runs the tests (the macOS CI runner included).
    #[test]
    fn live_host_readings() {
        let (total, avail) = (mem_total_mb(), mem_avail_mb());
        assert!(total > 0 && avail > 0 && avail <= total, "memory {avail} of {total} MB");
        let load = load_avg();
        assert!(load.len() == 3 && load.iter().all(|l| l.parse::<f64>().is_ok()), "load {load:?}");
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().into_owned();
        assert!(process_cmdlines().iter().any(|c| c.contains(&name)), "this test process is among the processes");
        // A long command line is seen whole (QEMU's VM path sits far into its arguments).
        let tail = format!("/kiln-test-{}/vms/x/disk.qcow2", "y".repeat(400));
        let mut child = std::process::Command::new("sh").args(["-c", "sleep 5; :", "sh", &tail]).spawn().unwrap();
        let seen = process_cmdlines().iter().any(|c| c.contains(&tail));
        child.kill().ok();
        child.wait().ok();
        assert!(seen, "long command line cut short");
        eprintln!("hypervisor: {:?}; memory {avail}/{total} MB; load {load:?}", hypervisor());
    }

    #[test]
    fn macos_parsers() {
        let vm_stat = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
            Pages free:                               10000.\n\
            Pages active:                            400000.\n\
            Pages inactive:                           30000.\n\
            Pages speculative:                         5000.\n\
            Pages wired down:                        120000.\n";
        assert_eq!(vm_stat_avail(vm_stat), 40000 * 16384);
        assert_eq!(vm_stat_avail("Pages free: 2.\nPages inactive: 1.\n"), 3 * 4096, "no header: 4 KiB pages");
        assert_eq!(vm_stat_avail(""), 0);
        assert_eq!(parse_load("{ 1.62 1.85 1.93 }\n"), ["1.62", "1.85", "1.93"]);
        let ps = "    1 /sbin/launchd\n  412 /opt/homebrew/bin/qemu-system-aarch64 -machine virt -drive file=/x/vms/a/disk.qcow2\n";
        assert_eq!(parse_ps(ps), ["/sbin/launchd", "/opt/homebrew/bin/qemu-system-aarch64 -machine virt -drive file=/x/vms/a/disk.qcow2"]);
    }
}
