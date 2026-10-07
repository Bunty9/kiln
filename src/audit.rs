//! Audit trail: one JSON line per API write that passed admission, in `<data>/audit.log`
//! (mode 0600, rolled over to `audit.log.1` at 8 MiB); refusals go to kiln's log only (see
//! `web::admit`). Who (tailnet login, or "local" with the dashboard key), from where, what,
//! and the outcome: enough to answer "who switched egress to open" or "who killed that VM".

use serde_json::{Value, json};
use std::path::Path;
use std::sync::Mutex;

/// What a handler changed, for the record (a response extension `admit` picks up).
#[derive(Clone)]
pub struct Note(pub String);

/// Roll over past this size; one previous file is kept.
const MAX_BYTES: u64 = 8 << 20;

/// Serializes writers, so a roll-over never interleaves with an append.
static LOCK: Mutex<()> = Mutex::new(());

/// Append `entry` (plus a timestamp). Best effort: a full disk must not take the API down,
/// so a failure is logged, not returned.
pub fn record(data: &Path, mut entry: Value) {
    entry["at"] = json!(crate::now());
    tracing::info!(target: "audit", "audit: {entry}");
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = data.join("audit.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES)
        && let Err(e) = std::fs::rename(&path, data.join("audit.log.1"))
    {
        tracing::warn!("audit log roll-over: {e}");
    }
    if let Err(e) = append(&path, &format!("{entry}\n")) {
        tracing::warn!("audit log {}: {e}", path.display());
    }
}

fn append(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
    f.write_all(line.as_bytes())
}

/// The settings a config save changed, for the audit note: `egress: "filtered" -> "open",
/// repos`. Scalars show old and new (they hold no secrets: the token and keys are not in the
/// config); lists and maps (repos, users, SSH keys) only their name, to keep lines short.
/// `old` and `new` are the whole config as JSON objects.
pub fn config_changes(old: &Value, new: &Value) -> String {
    let empty = serde_json::Map::new();
    let (o, n) = (old.as_object().unwrap_or(&empty), new.as_object().unwrap_or(&empty));
    let keys: std::collections::BTreeSet<&String> = o.keys().chain(n.keys()).collect();
    let null = Value::Null;
    keys.into_iter()
        .filter_map(|k| {
            let (a, b) = (o.get(k).unwrap_or(&null), n.get(k).unwrap_or(&null));
            (a != b).then(|| {
                if a.is_array() || a.is_object() || b.is_array() || b.is_object() { k.clone() } else { format!("{k}: {a} -> {b}") }
            })
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_rolls_over_and_stays_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("kiln-test-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        record(&d, json!({ "actor": "me@x.com", "path": "/api/config" }));
        record(&d, json!({ "actor": "local", "path": "/api/vms/kiln-1-0/kill" }));
        let text = std::fs::read_to_string(d.join("audit.log")).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["path"], "/api/vms/kiln-1-0/kill");
        assert!(lines[0]["at"].is_u64());
        assert_eq!(std::fs::metadata(d.join("audit.log")).unwrap().permissions().mode() & 0o777, 0o600);
        // past the cap: the old file moves aside and a new one starts
        std::fs::write(d.join("audit.log"), vec![b'x'; MAX_BYTES as usize + 1]).unwrap();
        record(&d, json!({ "actor": "me@x.com" }));
        assert!(std::fs::metadata(d.join("audit.log.1")).unwrap().len() > MAX_BYTES);
        assert_eq!(std::fs::read_to_string(d.join("audit.log")).unwrap().lines().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn config_change_summary() {
        let old = json!({ "egress": "filtered", "max_vms": 2, "repos": ["a/b"] });
        let new = json!({ "egress": "open", "max_vms": 2, "repos": ["a/b"] });
        assert_eq!(config_changes(&old, &new), r#"egress: "filtered" -> "open""#);
        assert_eq!(config_changes(&old, &old), "");
        let new = json!({ "egress": "filtered", "max_vms": 2, "repos": ["a/b", "c/d"], "auto_update": true });
        assert_eq!(config_changes(&old, &new), "auto_update: null -> true, repos", "lists by name, new keys too");
    }
}
