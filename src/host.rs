//! Host CPU and memory sampled every 2 s, split by job VM, for the dashboard's Host card.
//! An hour is kept in memory only: a restart starts the graph empty. Linux only: it reads
//! /proc, so on macOS it logs once and the graph stays empty.

use crate::{App, platform};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// The QEMU process of each wanted VM, found by its `vms/<id>/q/` paths on the command line.
fn find_qemu(want: &[&str]) -> HashMap<String, u32> {
    let mut out = HashMap::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        let cmd = String::from_utf8_lossy(&cmd);
        if !cmd.split('\0').next().is_some_and(|a| a.rsplit('/').next().unwrap_or(a).starts_with("qemu-system")) {
            continue;
        }
        if let Some(id) = want.iter().find(|id| cmd.contains(&format!("/vms/{id}/q/"))) {
            out.insert(id.to_string(), pid);
        }
    }
    out
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
    let (mut pids, mut slots) = (HashMap::<String, u32>::new(), HashMap::<String, usize>::new());
    let mut tick = tokio::time::interval(EVERY);
    loop {
        tick.tick().await;
        let ids: Vec<String> = app.vms.lock().unwrap().iter().filter(|v| v.state.is_active()).map(|v| v.id.clone()).collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        pids.retain(|id, pid| ids.contains(&id.as_str()) && std::path::Path::new(&format!("/proc/{pid}")).exists());
        let missing: Vec<&str> = ids.iter().copied().filter(|id| !pids.contains_key(*id)).collect();
        if !missing.is_empty() {
            pids.extend(find_qemu(&missing));
        }
        assign(&mut slots, &ids);
        let Some(now) = cpu_ticks(&std::fs::read_to_string("/proc/stat").unwrap_or_default()) else {
            if !std::mem::replace(&mut warned, true) {
                tracing::warn!("host graphs: /proc/stat unreadable, no samples");
            }
            continue;
        };
        let vm_now: HashMap<String, (u64, u64)> = pids
            .iter()
            .filter_map(|(id, pid)| {
                let t = proc_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
                let pages: u64 = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?.split_whitespace().nth(1)?.parse().ok()?;
                Some((id.clone(), (t, pages * 4096 / (1 << 20))))
            })
            .collect();
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
}
