//! `kiln status|jobs|logs|wait|rerun`: a thin client for the running kiln's own API, so scripts and
//! agents need no curl. It talks only to `<data>/serve.sock` (mode 0600; the key never goes over TCP)
//! with the dashboard key, and never starts a daemon or touches a forge itself.
//!
//! Exit codes (a contract, see docs/cli.md): 0 success or skipped, 1 failure (kiln's job timeout
//! included), 2 cancelled, 3 infrastructure loss (VM lost, killed, oom, no result), 4 refused by kiln,
//! 5 `wait` timed out, 6 kiln, auth or usage error.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

macro_rules! say {
    ($($a:tt)*) => { println!("{}", plain(&format!($($a)*))) };
}
macro_rules! esay {
    ($($a:tt)*) => { eprintln!("{}", plain(&format!($($a)*))) };
}

pub const OK: i32 = 0;
pub const FAILED: i32 = 1;
pub const CANCELLED: i32 = 2;
pub const INFRA: i32 = 3;
pub const REFUSED: i32 = 4;
pub const TIMED_OUT: i32 = 5;
pub const ERROR: i32 = 6;

const COMMANDS: [&str; 5] = ["status", "jobs", "logs", "wait", "rerun"];

/// `Some(exit code)` if `args` (without the program name) is a CLI command, else None.
pub fn dispatch(args: &[String]) -> Option<i32> {
    let cmd = args.first()?.as_str();
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(match run(cmd, &args[1..]) {
        Ok(code) => code,
        Err(e) => {
            esay!("kiln {cmd}: {e:#}");
            ERROR
        }
    })
}

fn run(cmd: &str, args: &[String]) -> Result<i32> {
    match cmd {
        "status" => status(&Args::parse(args, &["json", "doctor"], &[], 0)?),
        "jobs" => jobs(&Args::parse(args, &["json"], &["repo", "pr", "sha", "branch", "limit"], 0)?),
        "logs" => logs(&Args::parse(args, &["json", "console", "steps", "failed", "follow"], &["repo"], 1)?),
        "wait" => wait(&Args::parse(args, &["json"], &["repo", "timeout", "interval"], 1)?),
        _ => rerun(&Args::parse(args, &["json", "failed"], &["repo"], 1)?),
    }
}

// ---- arguments

struct Args {
    flags: Vec<String>,
    vals: BTreeMap<String, String>,
    pos: Vec<String>,
}

impl Args {
    /// `--flag`, `--key value` or `--key=value`; anything unknown is an error.
    fn parse(args: &[String], flags: &[&str], vals: &[&str], npos: usize) -> Result<Args> {
        let mut out = Args { flags: vec![], vals: BTreeMap::new(), pos: vec![] };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Some(name) = a.strip_prefix("--") else {
                out.pos.push(a.clone());
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            if flags.contains(&name) && inline.is_none() {
                out.flags.push(name.into());
            } else if vals.contains(&name) {
                let v = inline.or_else(|| it.next().cloned()).ok_or_else(|| anyhow!("--{name} needs a value"))?;
                out.vals.insert(name.into(), v);
            } else {
                bail!("unknown option --{name}");
            }
        }
        if out.pos.len() != npos {
            bail!("expected {npos} argument(s), got {}", out.pos.len());
        }
        Ok(out)
    }
    fn flag(&self, n: &str) -> bool {
        self.flags.iter().any(|f| f == n)
    }
    fn val(&self, n: &str) -> Option<&str> {
        self.vals.get(n).map(String::as_str)
    }
    fn num(&self, n: &str, default: u64) -> Result<u64> {
        self.val(n).map_or(Ok(default), |v| v.parse().map_err(|_| anyhow!("--{n} must be a number")))
    }
}

// ---- transport

struct Conn {
    data: PathBuf,
    key: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Resolved as main.rs does.
fn data_dir() -> Result<PathBuf> {
    let d = std::env::var_os("KILN_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share/kiln"));
    Ok(std::path::absolute(d)?)
}

impl Conn {
    fn open(data: &Path) -> Result<Conn> {
        let kp = data.join("dashboard.key");
        let key = std::fs::read_to_string(&kp)
            .with_context(|| {
                format!(
                    "cannot read the dashboard key {}: run as the user kiln runs as, with KILN_DATA set if the data dir is not the default",
                    kp.display()
                )
            })?
            .trim()
            .to_string();
        Ok(Conn { data: data.into(), key })
    }

    /// (status, body) of one HTTP/1.0 request: no chunked bodies to decode.
    fn request(&self, method: &str, target: &str) -> Result<(u16, Vec<u8>)> {
        use std::os::unix::net::UnixStream;
        let sock = self.data.join("serve.sock");
        // The key goes only over this 0600 socket: a TCP port can be bound by another local user while kiln is down.
        let s = UnixStream::connect(&sock).map_err(|e| {
            anyhow!(
                "cannot connect to {} ({e}): kiln is not running, or KILN_DATA is too long for a unix socket. \
                 If you accept sending the key over TCP, use curl with x-kiln-key against the listen address",
                sock.display()
            )
        })?;
        exchange(s, "localhost", method, target, &self.key)
    }

    fn call(&self, method: &str, target: &str) -> Result<Vec<u8>> {
        let (code, body) = self.request(method, target)?;
        if (200..300).contains(&code) {
            return Ok(body);
        }
        let msg = String::from_utf8_lossy(&body);
        match code {
            401 | 403 => bail!("refused ({code}): {}", msg.trim()),
            _ => bail!("{method} {} failed ({code}): {}", target.split('?').next().unwrap_or(target), msg.trim()),
        }
    }

    fn get(&self, target: &str) -> Result<Value> {
        let b = self.call("GET", target)?;
        serde_json::from_slice(&b).with_context(|| format!("{target}: not JSON"))
    }
}

trait Stream: Read + Write {
    fn timeout(&self);
}
impl Stream for std::os::unix::net::UnixStream {
    fn timeout(&self) {
        let _ = self.set_read_timeout(Some(Duration::from_secs(60)));
    }
}
fn exchange(mut s: impl Stream, host: &str, method: &str, target: &str, key: &str) -> Result<(u16, Vec<u8>)> {
    s.timeout();
    let post = if method == "GET" { "" } else { "x-kiln: 1\r\nContent-Length: 0\r\n" };
    write!(s, "{method} {target} HTTP/1.0\r\nHost: {host}\r\nx-kiln-key: {key}\r\n{post}\r\n")?;
    let mut raw = vec![];
    s.read_to_end(&mut raw).context("reading the response")?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("malformed response from kiln"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| anyhow!("malformed status line"))?;
    Ok((code, raw[split + 4..].to_vec()))
}

fn enc(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    s.extend_pairs(pairs);
    s.finish()
}

// ---- JSON helpers

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

fn vms(state: &Value) -> &[Value] {
    state["vms"].as_array().map_or(&[], Vec::as_slice)
}

fn is_active(vm: &Value) -> bool {
    matches!(s(vm, "state"), "booting" | "idle" | "busy" | "held")
}

/// Run id from `https://host/o/n/actions/runs/1/job/2`.
fn run_id_of(vm: &Value) -> Option<u64> {
    let u = s(vm, "job_url");
    let (_, rest) = u.split_once("/actions/runs/")?;
    rest.split(['/', '?']).next()?.parse().ok()
}

/// `Vm::fail_cause` (vm.rs), from the JSON: why a finished job did not pass (None: it passed or is still going).
fn fail_cause(vm: &Value) -> Option<&'static str> {
    let result = vm["result"].as_str();
    if result == Some("Succeeded") {
        return None;
    }
    let note = s(vm, "note");
    if vm["verdict"][0].as_str() == Some("refuse") || note.starts_with("refused:") {
        return Some(if vm["refuse_failure"].as_bool() == Some(true) { "refused_failure" } else { "refused_policy" });
    }
    let st = s(vm, "state");
    Some(match result {
        Some("Failed") => "failed",
        Some("Canceled" | "Cancelled") => "cancelled",
        Some(_) => "other",
        None if st == "lost" => "lost",
        None if note.starts_with("job timeout") => "timeout",
        None if note.starts_with("killed: the pipeline was cancelled") => "cancelled",
        None if note.starts_with("killed: likely out of memory") => "oom",
        None if note.starts_with("killed") || note == "kiln shutting down" => "killed",
        None if st == "failed" => "no_result",
        None => "other",
    })
}

/// Which repo a run command is about: `--repo`, else the one repo kiln serves (`config.repos`, not
/// every repo the GitHub App can see).
fn repo_of(c: &Conn, a: &Args) -> Result<String> {
    if let Some(r) = a.val("repo") {
        return Ok(r.into());
    }
    let st = c.get("/api/state")?;
    let repos: Vec<&str> = st["config"]["repos"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    match repos.as_slice() {
        [one] => Ok((*one).into()),
        [] => bail!("kiln serves no repos"),
        _ => bail!("kiln serves several repos ({}): pass --repo", repos.join(", ")),
    }
}

/// The runs in a `/api/runs` page (`{"runs": [...], "next": ...}`; a bare array is accepted too).
fn runs_of(page: &Value) -> impl Iterator<Item = &Value> {
    page.get("runs").unwrap_or(page).as_array().into_iter().flatten()
}

/// `kiln wait`'s target: digits are a run id (GitHub's are 11 digits and growing), `sha:<hex>` or any
/// other hex is a commit.
fn wait_target(t: &str) -> (bool, String) {
    match t.strip_prefix("sha:") {
        Some(h) => (false, h.to_lowercase()),
        None => (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()), t.to_lowercase()),
    }
}

fn ago(secs: u64) -> String {
    match secs {
        0..=119 => format!("{secs}s"),
        120..=7199 => format!("{}m", secs / 60),
        _ => format!("{}h{:02}m", secs / 3600, secs % 3600 / 60),
    }
}

/// Untrusted text (notes, titles, branch and job names, messages) for a terminal: no escapes or control characters but \n and \t.
fn plain(text: &str) -> String {
    clean(text).chars().filter(|&c| c == '\n' || c == '\t' || !c.is_control()).collect()
}

/// Log text for a terminal: keeps \n, \t, \r\n and SGR colours; drops every other escape sequence
/// (OSC 52 clipboard writes, titles, hyperlinks, cursor moves) and control character. Piped output is not filtered.
fn tty_filter(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(ch) = it.next() {
        match ch {
            '\n' | '\t' => out.push(ch),
            '\r' if it.peek() == Some(&'\n') => out.push(ch),
            '\x1b' => match it.next() {
                Some('[') => {
                    let mut params = String::new();
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            if c == 'm' && params.chars().all(|p| p.is_ascii_digit() || p == ';') {
                                out.push_str(&format!("\x1b[{params}m"));
                            }
                            break;
                        }
                        params.push(c);
                    }
                }
                // OSC, DCS, SOS, PM, APC: a string up to BEL or ST.
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    while let Some(c) = it.next() {
                        if c == '\x07' || (c == '\x1b' && it.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {}
            },
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Writes log text: filtered when stdout is a terminal, raw otherwise.
fn emit(text: &str) {
    use std::io::IsTerminal;
    let mut o = std::io::stdout();
    let _ = if o.is_terminal() { o.write_all(tty_filter(text).as_bytes()) } else { o.write_all(text.as_bytes()) };
    let _ = o.flush();
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

// ---- status

fn status(a: &Args) -> Result<i32> {
    let c = Conn::open(&data_dir()?)?;
    let st = c.get("/api/state")?;
    let doctor = if a.flag("doctor") { Some(c.get("/api/doctor")?) } else { None };
    if a.flag("json") {
        print_json(&match doctor {
            Some(d) => json!({ "state": st, "doctor": d }),
            None => st,
        });
        return Ok(OK);
    }
    let poll = &st["poll"];
    let health: Vec<&Value> = poll["health"].as_array().into_iter().flatten().collect();
    say!("kiln {} ({})", s(&st, "version"), if health.is_empty() && poll["error"].is_null() { "healthy" } else { "needs attention" });
    match poll["last_ok"].as_u64() {
        Some(t) => say!("polled {} ago", ago(now().saturating_sub(t))),
        None => say!("not polled yet"),
    }
    if let Some(e) = poll["error"].as_str() {
        say!("poll error: {e}");
    }
    let all = vms(&st);
    let active: Vec<&Value> = all.iter().filter(|v| is_active(v)).collect();
    let max = st["config"]["max_vms"].as_u64().unwrap_or(0);
    say!("slots: {}/{max}{}", active.len(), if max == 0 { " (paused)" } else { "" });
    for v in &active {
        say!("  {}", vm_line(v));
    }
    let queued: Vec<String> =
        poll["queued"].as_object().into_iter().flatten().filter(|(_, n)| n.as_u64() > Some(0)).map(|(r, n)| format!("{r}: {n}")).collect();
    say!("queued: {}", if queued.is_empty() { "none".into() } else { queued.join(", ") });
    if let Some(b) = poll["blocked"].as_str() {
        say!("blocked ({}): {b}", s(poll, "blocked_kind"));
    }
    for (r, b) in poll["backoff"].as_object().into_iter().flatten() {
        say!("backoff {r}: {} failure(s), retry in {}", b["fails"], ago(b["retry_at"].as_u64().unwrap_or(0).saturating_sub(now())));
    }
    // Added by a newer kiln (poll.waiting): optional, shown as it comes.
    for (r, w) in poll["waiting"].as_object().into_iter().flatten() {
        let why = w.as_str().map(String::from).unwrap_or_else(|| w.to_string());
        say!("waiting {r}: {why}");
    }
    for h in health {
        say!("health [{}]: {}", h[0].as_str().unwrap_or("?"), h[1].as_str().unwrap_or(""));
    }
    if let Some(d) = doctor {
        say!("doctor:");
        for ch in d["checks"].as_array().into_iter().flatten() {
            say!("  {} {}: {}", if ch["ok"].as_bool() == Some(true) { "ok  " } else { "FAIL" }, s(ch, "name"), s(ch, "detail"));
        }
    }
    Ok(OK)
}

/// `id state repo job #pr|branch elapsed`
fn vm_line(v: &Value) -> String {
    let end = v["ended"].as_u64().unwrap_or_else(now);
    format!(
        "{} {} {} {} {} {}",
        s(v, "id"),
        s(v, "state"),
        s(v, "repo"),
        s(v, "job"),
        target_of(v),
        ago(end.saturating_sub(v["started"].as_u64().unwrap_or(end)))
    )
}

fn target_of(v: &Value) -> String {
    match v["run"]["pr"].as_u64() {
        Some(pr) => format!("#{pr}"),
        None => s(&v["run"], "branch").into(),
    }
}

// ---- jobs

fn jobs(a: &Args) -> Result<i32> {
    let c = Conn::open(&data_dir()?)?;
    let st = c.get("/api/state")?;
    let pr: Option<u64> =
        a.val("pr").map(|p| p.trim_start_matches('#').parse().map_err(|_| anyhow!("--pr must be a number"))).transpose()?;
    let limit = a.num("limit", 20)? as usize;
    let picked: Vec<&Value> =
        vms(&st).iter().filter(|v| job_matches(v, a.val("repo"), pr, a.val("sha"), a.val("branch"))).take(limit).collect();
    if a.flag("json") {
        print_json(&json!(picked));
        return Ok(OK);
    }
    for v in picked {
        let sha = s(&v["run"], "sha");
        let note: String = s(v, "note").chars().take(60).collect();
        let end = v["ended"].as_u64().unwrap_or_else(now);
        let state = v["result"].as_str().map_or(s(v, "state").to_string(), |r| format!("{}/{r}", s(v, "state")));
        say!(
            "{} {state} {} {} {} {} {} {note}",
            s(v, "id"),
            s(v, "repo"),
            s(v, "job"),
            target_of(v),
            &sha[..sha.len().min(7)],
            ago(end.saturating_sub(v["started"].as_u64().unwrap_or(end)))
        );
    }
    Ok(OK)
}

fn job_matches(v: &Value, repo: Option<&str>, pr: Option<u64>, sha: Option<&str>, branch: Option<&str>) -> bool {
    repo.is_none_or(|r| s(v, "repo") == r)
        && pr.is_none_or(|p| v["run"]["pr"].as_u64() == Some(p))
        && sha.is_none_or(|x| !x.is_empty() && s(&v["run"], "sha").starts_with(x))
        && branch.is_none_or(|b| s(&v["run"], "branch") == b)
}

// ---- logs

/// Drops a byte order mark and ANSI escape sequences (colors, cursor moves, OSC).
fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(ch) = it.next() {
        match ch {
            '\u{feff}' => {}
            '\x1b' => match it.peek() {
                Some('[') => {
                    it.next();
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(c) = it.next() {
                        if c == '\x07' || (c == '\x1b' && it.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {
                    it.next();
                }
            },
            c => out.push(c),
        }
    }
    out
}

/// The lines around `##[error]` and `FAIL` markers (`ctx` before and after), runs of lines joined, gaps marked `--`.
fn failure_excerpt(log: &str, ctx: usize) -> String {
    let log = clean(log);
    let lines: Vec<&str> = log.lines().collect();
    let hit = |l: &str| l.contains("##[error]") || l.contains("FAIL");
    let mut keep = vec![false; lines.len()];
    for (i, l) in lines.iter().enumerate() {
        if hit(l) {
            keep[i.saturating_sub(ctx)..(i + ctx + 1).min(lines.len())].fill(true);
        }
    }
    let mut out = String::new();
    let mut prev = None;
    for (i, l) in lines.iter().enumerate().filter(|(i, _)| keep[*i]) {
        if prev.is_some_and(|p| p + 1 != i) {
            out.push_str("--\n");
        }
        out.push_str(l);
        out.push('\n');
        prev = Some(i);
    }
    out
}

fn logs(a: &Args) -> Result<i32> {
    let c = Conn::open(&data_dir()?)?;
    let id = &a.pos[0];
    let file = if a.flag("console") { "console" } else { "steps" };
    let state = c.get("/api/state")?;
    let vm =
        vms(&state).iter().find(|v| s(v, "id") == id).cloned().ok_or_else(|| anyhow!("no VM {id} in kiln's last 100 (see `kiln jobs`)"))?;
    let (mut from, mut text) = (0u64, String::new());
    let page = |from: u64| c.get(&format!("/api/log?{}&from={from}", enc(&[("src", id), ("file", file)])));
    loop {
        let p = page(from)?;
        let (data, next) = (s(&p, "data"), p["next"].as_u64().unwrap_or(from));
        if a.flag("failed") {
            text.push_str(data);
        } else if !a.flag("json") {
            emit(data);
        } else {
            text.push_str(data);
        }
        let more = !data.is_empty() && next > from;
        from = next;
        if more {
            continue;
        }
        // At the end: keep polling while the VM is active.
        if !a.flag("follow") || a.flag("failed") || a.flag("json") {
            break;
        }
        let now_active = c.get("/api/state").map(|st| vms(&st).iter().any(|v| s(v, "id") == id && is_active(v))).unwrap_or(false);
        if !now_active {
            // One last drain, then done.
            let p = page(from)?;
            emit(s(&p, "data"));
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if a.flag("failed") {
        let step = failed_step(&c, &vm, a.val("repo"));
        let ex = failure_excerpt(&text, 3);
        if a.flag("json") {
            print_json(&json!({ "vm": id, "failed_step": step, "excerpt": ex }));
        } else {
            if let Some(st) = step {
                say!("failed step: {st}");
            }
            print!("{}", plain(&ex));
        }
    } else if a.flag("json") {
        print_json(&json!({ "vm": id, "file": file, "text": text, "next": from }));
    }
    Ok(OK)
}

/// The name of the first failed step of this VM's job, when the VM has a run (best effort).
fn failed_step(c: &Conn, vm: &Value, repo: Option<&str>) -> Option<String> {
    let run = run_id_of(vm)?;
    let repo = repo.unwrap_or_else(|| s(vm, "repo"));
    let d = c.get(&format!("/api/runs/{run}?{}", enc(&[("repo", repo)]))).ok()?;
    let job_url_id = s(vm, "job_url").rsplit_once("/job/").and_then(|(_, j)| j.split(['/', '?']).next()?.parse::<u64>().ok());
    d["jobs"]
        .as_array()?
        .iter()
        .filter(|j| job_url_id.is_none_or(|id| j["id"].as_u64() == Some(id)))
        .flat_map(|j| j["steps"].as_array().cloned().unwrap_or_default())
        .find(|st| st["outcome"].as_str() == Some("Failed"))
        .map(|st| s(&st, "name").to_string())
}

// ---- rerun

fn rerun(a: &Args) -> Result<i32> {
    let c = Conn::open(&data_dir()?)?;
    let id: u64 = a.pos[0].parse().map_err(|_| anyhow!("run id must be a number"))?;
    let repo = repo_of(&c, a)?;
    let failed = a.flag("failed");
    let mut q = enc(&[("repo", &repo)]);
    if failed {
        q.push_str("&failed=1");
    }
    c.call("POST", &format!("/api/runs/{id}/rerun?{q}"))?;
    if a.flag("json") {
        print_json(&json!({ "ok": true, "run": id, "repo": repo, "failed": failed }));
    } else {
        say!("rerun requested: {repo} run {id}{}", if failed { " (failed jobs only)" } else { "" });
    }
    Ok(OK)
}

// ---- wait

/// A finished run's exit code, from the forge's outcome string.
fn outcome_code(outcome: &str) -> i32 {
    match outcome {
        "Succeeded" | "SucceededWithIssues" | "Skipped" => OK,
        "Canceled" => CANCELLED,
        _ => FAILED,
    }
}

/// Where a run stands, or None while it is still going. `vms` is state's VM list; `since` is when
/// the current attempt was first seen (a lost VM of an earlier attempt says nothing about it).
fn run_code(run: &Value, vms: &[Value], since: u64) -> Option<i32> {
    let id = run["id"].as_u64()?;
    let base = (s(run, "status") == "completed").then(|| outcome_code(run["outcome"].as_str().unwrap_or("Failed")));
    if base == Some(OK) {
        return Some(OK);
    }
    let mine: Vec<&Value> = vms.iter().filter(|v| run_id_of(v) == Some(id) && v["started"].as_u64().unwrap_or(0) >= since).collect();
    let causes: Vec<&str> = mine.iter().filter_map(|v| fail_cause(v)).collect();
    if causes.iter().any(|c| c.starts_with("refused")) {
        return Some(REFUSED);
    }
    // GitHub still says in progress (or cancelled) after kiln lost or killed the VM: kiln knows better.
    if matches!(base, None | Some(CANCELLED)) && !mine.iter().any(|v| is_active(v)) {
        if causes.iter().any(|c| matches!(*c, "lost" | "killed" | "oom" | "no_result")) {
            return Some(INFRA);
        }
        if causes.contains(&"timeout") {
            return Some(FAILED);
        }
    }
    base
}

/// The worst of several runs' codes: infra loss, then failure, refused, cancelled, success.
fn worst(codes: &[i32]) -> i32 {
    [INFRA, FAILED, REFUSED, CANCELLED].into_iter().find(|c| codes.contains(c)).unwrap_or(OK)
}

fn wait(a: &Args) -> Result<i32> {
    let c = Conn::open(&data_dir()?)?;
    let repo = repo_of(&c, a)?;
    let target = a.pos[0].clone();
    let (timeout, interval) = (Duration::from_secs(a.num("timeout", 60)? * 60), Duration::from_secs(a.num("interval", 10)?.max(1)));
    let (by_id, sha) = wait_target(&target);
    let q = |s: &str| enc(&[("repo", &repo)]) + s;
    let start = Instant::now();
    // run id -> (attempt, when this attempt was first seen)
    let mut seen: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    if by_id {
        seen.insert(target.parse()?, (0, 0));
    }
    let (mut details, mut fails) = (BTreeMap::<u64, Value>::new(), 0);
    let codes = loop {
        let polled = (|| -> Result<Vec<(u64, Option<i32>)>> {
            let st = c.get("/api/state")?;
            if !by_id {
                for r in runs_of(&c.get(&format!("/api/runs?{}", q("")))?) {
                    let rs = s(r, "sha").to_lowercase();
                    if !rs.is_empty() && (rs.starts_with(&sha) || sha.starts_with(&rs)) {
                        seen.entry(r["id"].as_u64().unwrap_or(0)).or_insert((0, 0));
                    }
                }
            }
            let mut out = vec![];
            for (&id, tr) in seen.iter_mut() {
                let d = c.get(&format!("/api/runs/{id}?{}", q("")))?;
                let attempt = d["attempt"].as_u64().unwrap_or(1);
                if tr.0 != attempt {
                    // First sight is attempt 0 -> n and counts everything; a later change starts over.
                    *tr = (attempt, if tr.0 == 0 { 0 } else { now() });
                }
                out.push((id, run_code(&d, vms(&st), tr.1)));
                details.insert(id, d);
            }
            Ok(out)
        })();
        match polled {
            Ok(v) => {
                fails = 0;
                if v.is_empty() && start.elapsed() > Duration::from_secs(120) {
                    bail!("no run for {target} appeared in {repo} within 2 minutes");
                }
                if !v.is_empty() && v.iter().all(|(_, c)| c.is_some()) {
                    break v.into_iter().filter_map(|(_, c)| c).collect::<Vec<_>>();
                }
            }
            // kiln restarting mid-wait is expected; a dead kiln is not.
            Err(e) if fails < 6 => {
                fails += 1;
                esay!("kiln wait: {e:#} (retrying)");
            }
            Err(e) => return Err(e),
        }
        if start.elapsed() >= timeout {
            esay!("kiln wait: timed out after {} minute(s)", timeout.as_secs() / 60);
            report(a, &details, &BTreeMap::new(), TIMED_OUT);
            return Ok(TIMED_OUT);
        }
        std::thread::sleep(interval);
    };
    let code = worst(&codes);
    report(a, &details, &seen.keys().copied().zip(codes).collect(), code);
    Ok(code)
}

fn report(a: &Args, details: &BTreeMap<u64, Value>, codes: &BTreeMap<u64, i32>, code: i32) {
    if a.flag("json") {
        print_json(&json!({ "exit": code, "result": exit_name(code), "runs": details.values().map(|d| json!({
            "id": d["id"], "attempt": d["attempt"], "status": d["status"], "outcome": d["outcome"], "url": d["links"]["run"],
            "exit": codes.get(&d["id"].as_u64().unwrap_or(0)), "jobs": d["jobs"].as_array().into_iter().flatten().map(|j| json!({ "name": j["name"], "outcome": j["outcome"] })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>() }));
        return;
    }
    for (id, d) in details {
        let rc = codes.get(id).copied();
        say!(
            "run {id} ({}) attempt {}: {}{}",
            s(d, "name"),
            d["attempt"],
            rc.map_or("not finished", exit_name),
            d["links"]["run"].as_str().map(|u| format!("  {u}")).unwrap_or_default()
        );
        for j in d["jobs"].as_array().into_iter().flatten() {
            say!("  {}: {}", s(j, "name"), j["outcome"].as_str().unwrap_or_else(|| s(j, "status")));
        }
    }
    say!("{} (exit {code})", exit_name(code));
}

fn exit_name(code: i32) -> &'static str {
    match code {
        OK => "success",
        FAILED => "failure",
        CANCELLED => "cancelled",
        INFRA => "infrastructure loss",
        REFUSED => "refused by kiln",
        TIMED_OUT => "wait timed out",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_arguments() {
        let a = Args::parse(&strs(&["12345", "--repo=acme/demo", "--timeout", "5", "--json"]), &["json"], &["repo", "timeout"], 1).unwrap();
        assert_eq!(
            (a.pos[0].as_str(), a.val("repo"), a.num("timeout", 60).unwrap(), a.flag("json")),
            ("12345", Some("acme/demo"), 5, true)
        );
        assert!(Args::parse(&strs(&["--nope"]), &[], &[], 0).is_err());
        assert!(Args::parse(&strs(&["--repo"]), &[], &["repo"], 0).is_err());
        assert!(Args::parse(&strs(&[]), &[], &[], 1).is_err());
        assert!(dispatch(&strs(&["serve"])).is_none());
    }

    #[test]
    fn terminal_filter_keeps_only_safe_output() {
        assert_eq!(tty_filter("a\x1b]52;c;ZXZpbA==\x07b"), "ab");
        assert_eq!(tty_filter("a\x1b]0;title\x1b\\b\x1b]8;;http://x\x07link\x1b]8;;\x07"), "ablink");
        assert_eq!(tty_filter("\x1b[1;31mred\x1b[0m"), "\x1b[1;31mred\x1b[0m");
        assert_eq!(tty_filter("a\x1b[2Jb\x1b[10;5Hc\x1b[?25ld"), "abcd");
        assert_eq!(tty_filter("a\r\nb\rc\x08\x07\u{9b}d\tz\x1bPdcs\x1b\\e"), "a\r\nbcd\tze");
        assert_eq!(plain("br\x1b]52;c;x\x07anch\r\x07"), "branch");
    }

    #[test]
    fn strips_bom_and_ansi() {
        assert_eq!(clean("\u{feff}\x1b[31;1mred\x1b[0m ok \x1b]0;title\x07done"), "red ok done");
    }

    #[test]
    fn extracts_failure_context() {
        let log = "\u{feff}a\nb\nc\nd\n\x1b[31m##[error]boom\x1b[0m\ne\nf\ng\nh\ni\nj\nk\nFAIL x\nl";
        let ex = failure_excerpt(log, 1);
        assert_eq!(ex, "d\n##[error]boom\ne\n--\nk\nFAIL x\nl\n");
        assert_eq!(failure_excerpt("all fine", 3), "");
        assert_eq!(failure_excerpt("x\n\x1b[31;1mFAIL\x1b[0m t\ny", 0), "FAIL t\n");
    }

    fn vm(run: u64, state: &str, result: Option<&str>, note: &str) -> Value {
        json!({ "id": "v", "state": state, "result": result, "note": note, "started": 100,
            "job_url": format!("https://x/o/n/actions/runs/{run}/job/9") })
    }

    #[test]
    fn mirrors_fail_cause() {
        assert_eq!(fail_cause(&vm(1, "done", Some("Succeeded"), "")), None);
        assert_eq!(fail_cause(&vm(1, "done", Some("Failed"), "")), Some("failed"));
        assert_eq!(fail_cause(&vm(1, "lost", None, "")), Some("lost"));
        assert_eq!(fail_cause(&vm(1, "killed", None, "job timeout after 60m")), Some("timeout"));
        assert_eq!(fail_cause(&vm(1, "killed", None, "killed: likely out of memory (x)")), Some("oom"));
        assert_eq!(fail_cause(&vm(1, "failed", None, "runner exited without a result")), Some("no_result"));
        assert_eq!(fail_cause(&vm(1, "done", Some("Failed"), "refused: fork")), Some("refused_policy"));
        let mut v = vm(1, "done", Some("Failed"), "");
        v["verdict"] = json!(["refuse", "5"]);
        v["refuse_failure"] = json!(true);
        assert_eq!(fail_cause(&v), Some("refused_failure"));
    }

    #[test]
    fn maps_exit_codes() {
        let run = |status: &str, outcome: Value| json!({ "id": 7, "status": status, "outcome": outcome });
        assert_eq!(run_code(&run("completed", json!("Succeeded")), &[], 0), Some(OK));
        assert_eq!(run_code(&run("completed", json!("Skipped")), &[], 0), Some(OK));
        assert_eq!(run_code(&run("completed", json!("Failed")), &[], 0), Some(FAILED));
        assert_eq!(run_code(&run("completed", json!("Canceled")), &[], 0), Some(CANCELLED));
        assert_eq!(run_code(&run("running", Value::Null), &[], 0), None);
        // A lost VM beats GitHub's in-progress and cancelled, but not a success or a different attempt.
        let lost = [vm(7, "lost", None, "")];
        assert_eq!(run_code(&run("running", Value::Null), &lost, 0), Some(INFRA));
        assert_eq!(run_code(&run("completed", json!("Canceled")), &lost, 0), Some(INFRA));
        assert_eq!(run_code(&run("completed", json!("Succeeded")), &lost, 0), Some(OK));
        assert_eq!(run_code(&run("running", Value::Null), &lost, 200), None);
        assert_eq!(run_code(&run("running", Value::Null), &[vm(8, "lost", None, "")], 0), None);
        // A retry already running means the loss is not final.
        assert_eq!(run_code(&run("running", Value::Null), &[lost[0].clone(), vm(7, "busy", None, "")], 0), None);
        assert_eq!(run_code(&run("running", Value::Null), &[vm(7, "killed", None, "job timeout after 1m")], 0), Some(FAILED));
        assert_eq!(run_code(&run("completed", json!("Failed")), &[vm(7, "done", Some("Failed"), "refused: fork")], 0), Some(REFUSED));
        assert_eq!(worst(&[OK, CANCELLED, FAILED]), FAILED);
        assert_eq!(worst(&[FAILED, INFRA]), INFRA);
        assert_eq!(worst(&[OK, OK]), OK);
    }

    #[test]
    fn filters_jobs() {
        let v = json!({ "repo": "acme/demo", "run": { "pr": 4, "sha": "abcdef1234", "branch": "feat" } });
        assert!(job_matches(&v, Some("acme/demo"), Some(4), Some("abcd"), Some("feat")));
        assert!(!job_matches(&v, None, Some(5), None, None));
        assert!(!job_matches(&v, None, None, Some("bcd"), None));
        assert!(!job_matches(&v, Some("acme/other"), None, None, None));
    }

    /// The HTTP/1.0 client against a one-shot unix socket server: key and Host sent, POST gets x-kiln.
    #[test]
    fn talks_http_over_a_unix_socket() {
        let dir = std::env::temp_dir().join(format!("kiln-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("serve.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::fs::write(dir.join("dashboard.key"), "sekret\n").unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = vec![];
            for body in ["{\"ok\":1}", ""] {
                let (mut s, _) = l.accept().unwrap();
                // The request arrives in pieces: read all of it, or closing early resets the connection.
                let mut req = vec![];
                while !req.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    s.read_exact(&mut b).unwrap();
                    req.push(b[0]);
                }
                seen.push(String::from_utf8_lossy(&req).to_string());
                let status = if body.is_empty() { "204 No Content" } else { "200 OK" };
                write!(s, "HTTP/1.0 {status}\r\ncontent-length: {}\r\n\r\n{body}", body.len()).unwrap();
            }
            seen
        });
        let c = Conn::open(&dir).unwrap();
        assert_eq!(c.get("/api/state?x=1").unwrap(), json!({ "ok": 1 }));
        assert!(c.call("POST", "/api/runs/1/rerun").unwrap().is_empty());
        let seen = server.join().unwrap();
        assert!(seen[0].starts_with("GET /api/state?x=1 HTTP/1.0\r\nHost: localhost\r\nx-kiln-key: sekret\r\n"), "{}", seen[0]);
        assert!(seen[1].contains("x-kiln: 1") && seen[1].starts_with("POST "), "{}", seen[1]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unreadable_key_is_an_error() {
        assert!(Conn::open(Path::new("/nonexistent-kiln-dir")).is_err());
    }

    #[test]
    fn wait_targets_run_ids_of_any_length_and_shas() {
        assert_eq!(wait_target("40855697510"), (true, "40855697510".into()));
        assert_eq!(wait_target("7"), (true, "7".into()));
        assert_eq!(wait_target("4B0B413"), (false, "4b0b413".into()));
        assert_eq!(wait_target("sha:1234567"), (false, "1234567".into()));
    }

    #[test]
    fn runs_come_from_the_page_object() {
        let page = json!({ "runs": [{ "id": 1 }, { "id": 2 }], "next": null });
        assert_eq!(runs_of(&page).count(), 2);
        assert_eq!(runs_of(&json!([{ "id": 3 }])).count(), 1);
    }
}
