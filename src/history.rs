//! `jobs.jsonl`: one compact line per finished job, kept 90 days, so Settings > Analytics can
//! cover a month. Rows carry the VM record's own field names (the dashboard's helpers read
//! them as-is) but only what Analytics needs: no URLs, logs, commits or branches. Older
//! binaries never open this file.
use crate::vm::{CacheUse, State, Vm};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const FILE: &str = "jobs.jsonl";
const KEEP_SECS: u64 = 90 * 86400;
const MAX_ROWS: usize = 50_000;
/// Appends and the rewrite of a prune must not interleave.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static LAST_PRUNE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Row {
    pub id: String,
    /// Forge-aware key: `acme/demo`, `gl:group/project`, `ge:owner/name`.
    pub repo: String,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// `refused:` notes only: the class of refusal the Jobs page shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// (call, ""): the verdict gate's call, without the job id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<(String, String)>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refuse_failure: bool,
    #[serde(default)]
    pub cpus: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<u64>,
    pub started: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online_at: Option<u64>,
    pub busy_since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub warm: bool,
    #[serde(default, skip_serializing_if = "is_none_cache")]
    pub cache: CacheUse,
    /// Run kind and event only (`{kind, event}`), as the Jobs list shows them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunKind>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RunKind {
    #[serde(default, skip_serializing_if = "kind_is_default")]
    pub kind: crate::forge::EventKind,
    pub event: String,
}

fn is_none_cache(c: &CacheUse) -> bool {
    *c == CacheUse::None
}
fn kind_is_default(k: &crate::forge::EventKind) -> bool {
    *k == Default::default()
}

impl Row {
    /// None for a VM that never ran a job or has no end yet.
    pub fn of(v: &Vm) -> Option<Row> {
        let busy_since = v.busy_since?;
        (v.done_at.or(v.ended)).map(|_| Row {
            id: v.id.clone(),
            repo: v.repo.clone(),
            state: v.state,
            job: v.job.clone(),
            result: v.result.as_ref().map(|r| r.chars().take(40).collect()),
            note: v.note.clone().filter(|n| n.starts_with("refused:")).map(|n| n.chars().take(200).collect()),
            verdict: v.verdict.as_ref().map(|(c, _)| (c.clone(), String::new())),
            refuse_failure: v.refuse_failure,
            cpus: v.cpus,
            queued_at: v.queued_at,
            started: v.started,
            online_at: v.online_at,
            busy_since,
            done_at: v.done_at,
            ended: v.ended,
            warm: v.warm,
            cache: v.cache,
            run: v.run.as_ref().map(|r| RunKind { kind: r.kind, event: r.event.clone() }),
        })
    }
    pub fn end(&self) -> u64 {
        self.done_at.or(self.ended).unwrap_or(self.busy_since)
    }
}

/// Add a finished job. Called wherever `record_usage` is.
pub fn append(data: &Path, v: &Vm) {
    let Some(row) = Row::of(v) else { return };
    let _g = LOCK.lock().unwrap();
    let mut line = serde_json::to_vec(&row).unwrap_or_default();
    line.push(b'\n');
    // One write call on an O_APPEND file: a crash leaves at worst one torn line, which `read` skips.
    if let Err(e) =
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(data.join(FILE)).and_then(|mut f| f.write_all(&line))
    {
        tracing::warn!("append {FILE}: {e}");
        return;
    }
    let now = crate::now();
    if now.saturating_sub(LAST_PRUNE.load(Ordering::Relaxed)) > 86400 {
        LAST_PRUNE.store(now, Ordering::Relaxed);
        prune_locked(data, now);
    }
}

fn read_all(data: &Path) -> Vec<Row> {
    let Ok(b) = std::fs::read(data.join(FILE)) else { return vec![] };
    // A torn or foreign line is skipped, never fatal.
    b.split(|&c| c == b'\n').filter_map(|l| serde_json::from_slice(l).ok()).collect()
}

/// Rows that ended at or after `since` (unix s), oldest first.
pub fn read(data: &Path, since: u64) -> Vec<Row> {
    let _g = LOCK.lock().unwrap();
    let mut r: Vec<Row> = read_all(data).into_iter().filter(|r| r.end() >= since).collect();
    r.sort_by_key(|r| r.end());
    r
}

pub(crate) fn prune_locked(data: &Path, now: u64) {
    let mut rows = read_all(data);
    let n = rows.len();
    rows.retain(|r| r.end() + KEEP_SECS >= now);
    if rows.len() > MAX_ROWS {
        rows.sort_by_key(|r| r.end());
        rows.drain(..rows.len() - MAX_ROWS);
    }
    if rows.len() == n {
        return;
    }
    rewrite(data, &rows);
}

fn rewrite(data: &Path, rows: &[Row]) {
    let path = data.join(FILE);
    let tmp = data.join(format!("{FILE}.tmp"));
    let body: Vec<u8> = rows.iter().flat_map(|r| serde_json::to_vec(r).unwrap_or_default().into_iter().chain(*b"\n")).collect();
    let w = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).and_then(|mut f| f.write_all(&body));
    if let Err(e) = w.and_then(|_| std::fs::rename(&tmp, &path)) {
        tracing::warn!("rewrite {FILE}: {e}");
    }
}

/// First start with this ledger: add what the VM records on disk know, once per VM id.
pub fn backfill(data: &Path, vms: &[Vm]) {
    let _g = LOCK.lock().unwrap();
    let mut rows = read_all(data);
    let have: std::collections::HashSet<String> = rows.iter().map(|r| r.id.clone()).collect();
    rows.extend(vms.iter().filter(|v| !have.contains(&v.id)).filter_map(Row::of));
    rows.sort_by_key(|r| r.end());
    let now = crate::now();
    rows.retain(|r| r.end() + KEEP_SECS >= now);
    rewrite(data, &rows);
}
