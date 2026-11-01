//! What differs between the hosts kiln runs on: Linux (KVM) and macOS on Apple
//! Silicon (Hypervisor.framework). Guests always match the host's architecture,
//! so an aarch64 host runs arm64 guests and advertises arm64 runners.

use std::sync::LazyLock;

pub const MACOS: bool = cfg!(target_os = "macos");
/// Guests are arm64 (and runners advertise `ARM64`); x86_64 otherwise.
pub const ARM64: bool = cfg!(target_arch = "aarch64");

/// Whether this host's runners and jobs carry the arm64 labels. Unit tests always run as x64:
/// the mock forge's fixtures are x64, and the arm64 label rules have their own tests.
pub fn host_arm64() -> bool {
    ARM64 && !cfg!(test)
}

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
    let warn = kvm_warn(kvm.is_ok(), &group, &status);
    match kvm {
        Ok(_) => (true, format!("/dev/kvm opens read/write{warn}")),
        Err(e) => (false, format!("/dev/kvm: {e}{warn}")),
    }
}

/// The "group not active" hint, only when /dev/kvm failed to open: if it opened, the process has access.
fn kvm_warn(opened: bool, group: &str, status: &str) -> String {
    match (opened, kvm_gid(group), proc_uid(status)) {
        (false, Some(g), uid) if !has_gid(status, g) => format!(
            " (kvm group not active for this process yet — restart the user manager (sudo systemctl restart user@{}) or reboot)",
            uid.map_or("<uid>".into(), |u| u.to_string())
        ),
        _ => String::new(),
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

/// A process as `ps` sees it: CPU time (user + system) in centiseconds, resident MB, command line.
pub struct Usage {
    pub pid: u32,
    pub cs: u64,
    pub mb: u64,
    pub cmd: String,
}

/// Every process's CPU time, resident size and command line (macOS: Linux reads /proc).
pub fn process_usage() -> Vec<Usage> {
    parse_usage(&run("ps", &["-axww", "-o", "pid=,time=,rss=,command="]))
}

/// `ps -axww -o pid=,time=,rss=,command=` lines ("53256 1009:01.21 1294208 /opt/homebrew/bin/qemu-system-aarch64 ...").
fn parse_usage(out: &str) -> Vec<Usage> {
    let word = |s: &str| -> Option<(String, String)> {
        let (w, rest) = s.trim_start().split_once(' ')?;
        Some((w.to_string(), rest.to_string()))
    };
    out.lines()
        .filter_map(|l| {
            let (pid, rest) = word(l)?;
            let (time, rest) = word(&rest)?;
            let (rss, cmd) = word(&rest)?;
            let cmd = cmd.trim_start().to_string();
            Some(Usage { pid: pid.parse().ok()?, cs: cputime_cs(&time)?, mb: rss.parse::<u64>().ok()? / 1024, cmd })
        })
        .collect()
}

/// macOS `ps` CPU time, minutes:seconds.hundredths with unbounded minutes ("1009:01.21"), in centiseconds.
fn cputime_cs(s: &str) -> Option<u64> {
    let (min, rest) = s.split_once(':')?;
    let (sec, cs) = rest.split_once('.')?;
    Some((min.parse::<u64>().ok()? * 60 + sec.parse::<u64>().ok()?) * 100 + cs.parse::<u64>().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvm_group_parsing() {
        assert_eq!(kvm_gid("root:x:0:\nkvm:x:993:alice\n"), Some(993));
        assert_eq!(kvm_gid("root:x:0:\n"), None);
        let st = "Name:\tkiln\nUid:\t1000\t1000\t1000\t1000\nGroups:\t4 27 993 1000\n";
        assert!(has_gid(st, 993) && !has_gid(st, 994));
        assert_eq!(proc_uid(st), Some(1000));
        let g = "kvm:x:994:alice\n";
        assert!(kvm_warn(false, g, st).contains("user@1000"));
        assert_eq!(kvm_warn(true, g, st), "");
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
        // The child may not have exec'd `sh` yet: poll briefly instead of reading once.
        let seen = (0..40).any(|_| {
            let hit = process_cmdlines().iter().any(|c| c.contains(&tail));
            if !hit {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            hit
        });
        child.kill().ok();
        child.wait().ok();
        assert!(seen, "long command line cut short");
        if MACOS {
            let u = process_usage();
            assert!(u.iter().any(|p| p.pid == std::process::id() && p.mb > 0 && p.cmd.contains(&name)), "this test process in ps usage");
        }
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
        // CPU time is minutes:seconds.hundredths, the minutes unbounded; rss is KiB.
        let ps = "  403 178:22.79 142592 /System/Library/WindowServer -daemon\n\
            53256 1009:01.21 1294208 /opt/homebrew/bin/qemu-system-aarch64 -machine virt\n\
            junk line\n    7   0:00.05   2048 sh\n";
        let u = parse_usage(ps);
        assert_eq!(u.len(), 3, "junk skipped");
        assert_eq!((u[0].pid, u[0].cs, u[0].mb, u[0].cmd.as_str()), (403, 1_070_279, 139, "/System/Library/WindowServer -daemon"));
        assert_eq!((u[1].cs, u[1].mb), (6_054_121, 1263));
        assert_eq!((u[2].pid, u[2].cs, u[2].mb, u[2].cmd.as_str()), (7, 5, 2, "sh"));
        assert_eq!(cputime_cs("1:02:03"), None, "not macOS's format");
    }
}
