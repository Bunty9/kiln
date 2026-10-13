//! Host CPU and memory sampled every 2 s, split by job VM, for the dashboard's Host card.
//! An hour is kept in memory only: a restart starts the graph empty. Linux reads /proc,
//! macOS (no /proc) one `ps` per sample.

use crate::{App, platform};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EVERY: Duration = Duration::from_secs(2);
const KEEP: usize = 1800;
/// Colour slots the dashboard has; a VM beyond them counts as host load.
const SLOTS: usize = 8;

#[derive(Serialize, Clone)]
pub struct Sample {
    /// Unix milliseconds.
    t: u64,
    /// Cores busy, whole host.
    cpu: f32,
    /// MB in use, whole host.
    mem: u64,
    /// (colour slot, VM id, cores busy, resident MB) per running VM.
    vms: Vec<(usize, String, f32, u64)>,
}

static HIST: Mutex<VecDeque<Sample>> = Mutex::new(VecDeque::new());

/// The last `n` samples, oldest first.
pub fn recent(n: usize) -> Vec<Sample> {
    let h = HIST.lock().unwrap();
    h.iter().skip(h.len().saturating_sub(n)).cloned().collect()
}

/// (busy, total) jiffies from /proc/stat's first line, and the CPUs that line sums (the
/// `cpuN` lines: all online CPUs, whatever kiln's own affinity). Guest time is inside user.
fn cpu_ticks(stat: &str) -> Option<(u64, u64, usize)> {
    let f: Vec<u64> = stat.lines().next()?.split_whitespace().skip(1).take(8).filter_map(|x| x.parse().ok()).collect();
    let total: u64 = f.iter().sum();
    let n = stat.lines().filter(|l| l.strip_prefix("cpu").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))).count();
    Some((total - f.get(3)? - f.get(4)?, total, n.max(1)))
}

/// utime + stime from /proc/<pid>/stat (guest time is inside utime).
fn proc_ticks(stat: &str) -> Option<u64> {
    let f: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// `cmd` is the QEMU of VM `id`: kiln puts paths under `vms/<id>/q/` on its command line.
/// Arguments are NUL-separated in /proc/<pid>/cmdline and space-separated in `ps`.
fn qemu_of(cmd: &str, id: &str) -> bool {
    cmd.split(['\0', ' ']).next().is_some_and(|a| a.rsplit('/').next().unwrap_or(a).starts_with("qemu-system"))
        && cmd.contains(&format!("/vms/{id}/q/"))
}

/// The QEMU process of each wanted VM, from /proc.
fn find_qemu(want: &[&str]) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        let cmd = String::from_utf8_lossy(&cmd);
        if let Some(id) = want.iter().find(|id| qemu_of(&cmd, id)) {
            out.insert(id.to_string(), pid);
        }
    }
    out
}

/// One sample's raw counters: the host's (busy, total, CPUs) ticks, and each found VM's
/// (busy ticks, resident MB). Only differences between two readings mean anything.
struct Reading {
    host: (u64, u64, usize),
    vms: HashMap<String, (u64, u64)>,
}

/// Linux: /proc/stat for the host, /proc/<pid>/stat and statm for each VM's QEMU, in jiffies.
#[derive(Default)]
struct ProcReader {
    pids: HashMap<String, u32>,
}

impl ProcReader {
    fn read(&mut self, ids: &[&str]) -> Option<Reading> {
        self.pids.retain(|id, pid| ids.contains(&id.as_str()) && std::path::Path::new(&format!("/proc/{pid}")).exists());
        let missing: Vec<&str> = ids.iter().copied().filter(|id| !self.pids.contains_key(*id)).collect();
        if !missing.is_empty() {
            self.pids.extend(find_qemu(&missing));
        }
        let host = cpu_ticks(&std::fs::read_to_string("/proc/stat").unwrap_or_default())?;
        let vms = self
            .pids
            .iter()
            .filter_map(|(id, pid)| {
                let t = proc_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
                let pages: u64 = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?.split_whitespace().nth(1)?.parse().ok()?;
                Some((id.clone(), (t, pages * 4096 / (1 << 20))))
            })
            .collect();
        Some(Reading { host, vms })
    }
}

/// macOS: one `ps` per sample, in centiseconds. HVF runs the vCPUs on QEMU's threads, so a
/// VM's guest time is in its QEMU's CPU time. macOS has no host-wide tick counter outside
/// the Mach API, so host busy time adds up every process's increase since the last sample (a
/// new process counts whole; one that exited in between loses its last slice), and total is
/// wall time times CPUs.
#[derive(Default)]
struct PsReader {
    prev: HashMap<u32, u64>,
    busy: u64,
    since: Option<Instant>,
}

impl PsReader {
    fn read(&mut self, ids: &[&str]) -> Option<Reading> {
        let procs = platform::process_usage();
        if procs.is_empty() {
            return None;
        }
        let elapsed = self.since.get_or_insert_with(Instant::now).elapsed();
        Some(self.fold(&procs, ids, elapsed.as_millis() as u64 / 10, crate::host_threads() as usize))
    }

    /// `elapsed_cs`: centiseconds since the first reading.
    fn fold(&mut self, procs: &[platform::Usage], ids: &[&str], elapsed_cs: u64, cpus: usize) -> Reading {
        self.busy += procs.iter().map(|p| p.cs.saturating_sub(self.prev.get(&p.pid).copied().unwrap_or(0))).sum::<u64>();
        self.prev = procs.iter().map(|p| (p.pid, p.cs)).collect();
        let vms = ids.iter().filter_map(|id| procs.iter().find(|p| qemu_of(&p.cmd, id)).map(|p| (id.to_string(), (p.cs, p.mb)))).collect();
        Reading { host: (self.busy, elapsed_cs * cpus as u64, cpus), vms }
    }
}

/// Keep each VM's slot while it lives; a new VM takes the lowest free one.
fn assign(slots: &mut HashMap<String, usize>, ids: &[&str]) {
    slots.retain(|id, _| ids.contains(&id.as_str()));
    for id in ids {
        if !slots.contains_key(*id)
            && let Some(free) = (0..SLOTS).find(|s| !slots.values().any(|v| v == s))
        {
            slots.insert(id.to_string(), free);
        }
    }
}

pub async fn run(app: Arc<App>) {
    let mut last: Option<(u64, u64, usize)> = None;
    let mut last_vm: HashMap<String, u64> = HashMap::new();
    let mut warned = false;
    let mut slots = HashMap::<String, usize>::new();
    let (mut procfs, mut ps) = (ProcReader::default(), PsReader::default());
    let mut tick = tokio::time::interval(EVERY);
    loop {
        tick.tick().await;
        let ids: Vec<String> = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).map(|v| v.id.clone()).collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        assign(&mut slots, &ids);
        let reading = if platform::MACOS { ps.read(&ids) } else { procfs.read(&ids) };
        let Some(Reading { host: now, vms: vm_now }) = reading else {
            if !std::mem::replace(&mut warned, true) {
                tracing::warn!(
                    "host graphs: no CPU counters ({}), no samples",
                    if platform::MACOS { "ps" } else { "/proc/stat unreadable" }
                );
            }
            continue;
        };
        if let Some(prev) = last.filter(|p| now.1 > p.1) {
            // Ticks over all CPUs in this interval, so ticks / per_cpu = cores busy.
            let per_cpu = (now.1 - prev.1) as f32 / now.2 as f32;
            let mut vms: Vec<_> = vm_now
                .iter()
                .filter_map(|(id, &(t, mb))| {
                    let busy = last_vm.get(id).map_or(0.0, |&p| t.saturating_sub(p) as f32 / per_cpu);
                    Some((*slots.get(id)?, id.clone(), (busy * 100.0).round() / 100.0, mb))
                })
                .collect();
            vms.sort_by_key(|v| v.0);
            let s = Sample {
                t: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64),
                cpu: ((now.0.saturating_sub(prev.0)) as f32 / per_cpu * 100.0).round() / 100.0,
                mem: platform::mem_total_mb().saturating_sub(platform::mem_avail_mb()),
                vms,
            };
            let mut h = HIST.lock().unwrap();
            h.push_back(s);
            if h.len() > KEEP {
                h.pop_front();
            }
        }
        last = Some(now);
        last_vm = vm_now.into_iter().map(|(id, (t, _))| (id, t)).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_and_keeps_slots() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        assert_eq!(cpu_ticks("cpu  100 0 50 800 50 0 0 0 40 0\ncpu0 1 2\ncpu1 3 4\nintr 5"), Some((150, 1000, 2)));
        assert_eq!(proc_ticks("123 (qemu-system-x86) S 1 2 3 4 5 6 7 8 9 10 700 30 0"), Some(730));
        assert_eq!(proc_ticks("9 (a) b) R 1 2 3 4 5 6 7 8 9 10 5 6"), Some(11), "comm may hold ')'");
        let mut s = HashMap::new();
        assign(&mut s, &["a", "b", "c"]);
        assign(&mut s, &["a", "c", "d"]);
        assert_eq!((s["a"], s["c"], s["d"]), (0, 2, 1), "survivors keep colour, newcomer takes the freed slot");
    }

    #[test]
    fn ps_reader_sums_increases() {
        let p = |pid, cs, mb, cmd: &str| platform::Usage { pid, cs, mb, cmd: cmd.into() };
        let q = "/opt/homebrew/bin/qemu-system-aarch64 -machine virt -fw_cfg name=opt/kiln/jit,file=/d/vms/vm-1/q/jit";
        let mut r = PsReader::default();
        let a = r.fold(&[p(1, 500, 10, "/sbin/launchd"), p(2, 1000, 3000, q), p(3, 40, 1, "sh")], &["vm-1", "vm-2"], 0, 8);
        assert_eq!(a.vms.len(), 1, "vm-2 has no QEMU");
        assert_eq!(a.vms["vm-1"], (1000, 3000));
        // 2 s later: launchd +10, QEMU +300 (1.5 cores), sh gone, a new pid 4 with 20.
        let b = r.fold(&[p(1, 510, 10, "/sbin/launchd"), p(2, 1300, 3100, q), p(4, 20, 1, "ls")], &["vm-1"], 200, 8);
        assert_eq!(b.host.0 - a.host.0, 10 + 300 + 20, "increases, new process whole, exited one dropped");
        assert_eq!((b.host.1 - a.host.1, b.host.2), (1600, 8), "wall centiseconds times CPUs");
        assert_eq!(b.vms["vm-1"], (1300, 3100));
        assert!(qemu_of(q, "vm-1") && !qemu_of(q, "vm-") && !qemu_of("sh -c qemu-system /d/vms/vm-1/q/", "vm-1"));
    }
}
