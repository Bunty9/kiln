//! Outbound webhook notifications: generic signed JSON (Standard Webhooks), Slack, Discord
//! and ntfy. Nothing here may let a destination reach inward (SSRF), leak its secret, or let
//! text from a repo format, mention or inject into the target. See the Notifications section
//! of docs/configuration.md and SECURITY.md.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Generic,
    Slack,
    Discord,
    Ntfy,
}

/// May an alert connect to `ip`? Public unicast only; with `tailnet`, also the tailnet ranges
/// (100.64.0.0/10 and fd7a:115c:a1e0::/48). The same private ranges job egress filtering drops,
/// plus the IPv6 translation prefixes (local-use NAT64, SIIT, Teredo), discard (100::/64),
/// the deprecated site-local fec0::/10 and the documentation prefixes 2001:db8::/32 and 3fff::/20.
pub fn allowed(ip: IpAddr, tailnet: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => allowed_v4(v4, tailnet),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return allowed_v4(v4, tailnet);
            }
            let s = v6.segments();
            if v6.is_unspecified() || v6.is_loopback() {
                return false;
            }
            // Translation and discard prefixes whose target kiln cannot judge: refused outright.
            if s[..3] == [0x64, 0xff9b, 1] // 64:ff9b:1::/48, local-use NAT64
                || s[..6] == [0, 0, 0, 0, 0xffff, 0] // ::ffff:0:0:0/96, SIIT
                || s[..2] == [0x2001, 0] // 2001::/32, Teredo
                || s[..4] == [0x100, 0, 0, 0]
            // 100::/64, discard
            {
                return false;
            }
            if s[0] & 0xfe00 == 0xfc00 {
                return tailnet && s[..3] == [0xfd7a, 0x115c, 0xa1e0];
            }
            !(s[0] & 0xffc0 == 0xfe80 // link-local
                || s[0] & 0xffc0 == 0xfec0 // site-local
                || s[0] & 0xff00 == 0xff00 // multicast
                || s[..2] == [0x2001, 0x0db8] // documentation
                || (s[0] == 0x3fff && s[1] & 0xf000 == 0)) // documentation, 3fff::/20
        }
    }
}

/// The IPv4 address an IPv6 one stands for (mapped, compatible, NAT64, 6to4), if any:
/// such an address reaches that IPv4 host, so it is judged as one.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let v4 = |hi: u16, lo: u16| Some(Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8));
    if let Some(m) = v6.to_ipv4_mapped() {
        return Some(m);
    }
    if s[..6] == [0; 6] && !v6.is_unspecified() && !v6.is_loopback() {
        return v4(s[6], s[7]);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return v4(s[6], s[7]);
    }
    if s[0] == 0x2002 {
        return v4(s[1], s[2]);
    }
    None
}

fn allowed_v4(ip: Ipv4Addr, tailnet: bool) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 100 && b & 0xc0 == 64 {
        return tailnet;
    }
    !(a == 0
        || a == 10
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && b & 0xf0 == 16)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 168)
        || (a == 198 && b & 0xfe == 18)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

/// The host of `u` when it is an IP literal. Requests to a literal skip DNS, and so the
/// resolver's check, so callers check it themselves.
pub fn literal_ip(u: &reqwest::Url) -> Option<IpAddr> {
    u.host_str()?.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// Validate a destination URL for its kind; Err is a message for the dashboard.
pub fn check_url(kind: Kind, url: &str, tailnet: bool) -> Result<reqwest::Url, String> {
    let url = url.trim();
    if url.len() > 2048 {
        return Err("the URL is longer than 2048 characters".into());
    }
    let u = reqwest::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    // What is stored is the normalised form, which percent-encoding can make longer.
    if u.as_str().len() > 2048 {
        return Err("the URL is longer than 2048 characters".into());
    }
    if u.scheme() != "https" {
        return Err("the URL must start with https://".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("the URL must not contain a user name or password".into());
    }
    let host = u.host_str().ok_or("the URL has no host")?.to_ascii_lowercase();
    match kind {
        Kind::Slack if host != "hooks.slack.com" => return Err("a Slack webhook URL is on hooks.slack.com".into()),
        Kind::Discord if !(matches!(host.as_str(), "discord.com" | "discordapp.com") && u.path().starts_with("/api/webhooks/")) => {
            return Err("a Discord webhook URL looks like https://discord.com/api/webhooks/…".into());
        }
        _ => {}
    }
    if let Some(ip) = literal_ip(&u)
        && !allowed(ip, tailnet)
    {
        return Err(format!("{ip} is an internal address{}", if tailnet { "" } else { " (tick \"on my tailnet\" for a tailnet address)" }));
    }
    Ok(u)
}

/// Text that came from a repo, made inert: no control or bidi characters, one line, ≤ 100 chars.
pub fn clean(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).filter(|c| !c.is_control() && !invisible(*c)).collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > 100 { t.chars().take(99).chain(std::iter::once('…')).collect() } else { t }
}

/// Format characters that render as nothing but can split or disguise text.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}')
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct JobInfo {
    pub repo: String,
    pub workflow: Option<String>,
    pub workflow_name: Option<String>,
    pub job: String,
    pub branch: Option<String>,
    pub event: Option<String>,
    /// "failed", "cancelled", "killed", "lost" or "succeeded".
    pub outcome: String,
    pub duration_s: Option<u64>,
    pub url: Option<String>,
    #[serde(skip)]
    pub vm_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HealthInfo {
    pub kind: String,
    pub message: String,
    /// "raised" or "cleared".
    pub state: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SecurityInfo {
    pub actor: String,
    pub action: String,
    pub changed: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Detail {
    Job(JobInfo),
    Health(HealthInfo),
    Security(SecurityInfo),
    Test,
    /// Folded overflow of the rate limit: this many events were not sent one by one.
    More(u64),
}

/// Which per-destination switch an event obeys; `Direct` goes only to `Event::to`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Class {
    Job,
    Health,
    Security,
    Direct,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    /// "job.failed", "job.finished", "health.raised", "health.cleared", "security.changed",
    /// "test" or "more".
    pub ty: &'static str,
    pub class: Class,
    pub detail: Detail,
    /// Explicit destination ids (rules, tests). Empty: every destination with `class` on.
    pub to: Vec<String>,
}

pub struct Rendered {
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// `url` if it is a plain https://github.com/ URL with nothing that could break out of a link.
pub fn github_link(url: &str) -> Option<&str> {
    (url.starts_with("https://github.com/") && url.len() <= 300 && !url.contains(['|', '>', '<', ' ', '"', '\'', '\n'])).then_some(url)
}

fn dur(s: u64) -> String {
    if s >= 3600 {
        format!("{}h {}m", s / 3600, s / 60 % 60)
    } else if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// One human line for `e`; every piece of repo text passes through `esc` for the target.
fn summary(e: &Event, esc: &dyn Fn(&str) -> String) -> String {
    match &e.detail {
        Detail::Job(j) => {
            let icon = if j.outcome == "succeeded" { "✅" } else { "❌" };
            let wf = j.workflow.as_deref().unwrap_or("workflow unknown");
            let mut s = format!("{icon} {} · {} · {} {}", esc(&j.repo), esc(wf), esc(&j.job), j.outcome);
            if let Some(b) = &j.branch {
                s += &format!(" on {}", esc(b));
            }
            if let Some(d) = j.duration_s {
                s += &format!(" after {}", dur(d));
            }
            s
        }
        Detail::Health(h) if h.state == "cleared" => format!("✅ resolved: {}", esc(&h.message)),
        Detail::Health(h) => format!("⚠️ {}", esc(&h.message)),
        Detail::Security(x) => {
            let what = if x.changed.is_empty() { String::new() } else { format!(" ({})", esc(&x.changed.join(", "))) };
            format!("🔐 {}: {}{what}", esc(&x.actor), esc(&x.action))
        }
        Detail::Test => "kiln test notification: this destination works".into(),
        Detail::More(n) => format!("+{n} more events (rate limit: 30 a minute)"),
    }
}

/// Breaks auto-linking of repo text (`evil.example`, `https://…`) by putting a zero-width space
/// after every dot and colon. Only repo text is delinked; kiln's own links are added after.
fn delink(s: &str) -> String {
    s.replace('.', ".\u{200B}").replace(':', ":\u{200B}")
}

fn slack_esc(s: &str) -> String {
    delink(s).replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn discord_esc(s: &str) -> String {
    let s = delink(s);
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\*_~`|>#-[]()<".contains(c) {
            o.push('\\');
        }
        o.push(c);
        if c == '@' {
            o.push('\u{200B}');
        }
    }
    o
}

fn title(ty: &str) -> &'static str {
    match ty {
        "job.failed" => "kiln: job failed",
        "job.finished" => "kiln: workflow finished",
        "health.raised" => "kiln: needs attention",
        "health.cleared" => "kiln: resolved",
        "security.changed" => "kiln: security change",
        "test" => "kiln: test",
        _ => "kiln",
    }
}

fn generic_body(e: &Event, id: &str, at: u64, link: Option<&str>) -> Value {
    let mut v = json!({ "type": e.ty, "id": id, "at": at, "kiln": { "version": env!("CARGO_PKG_VERSION"), "link": link } });
    match &e.detail {
        Detail::Job(j) => v["job"] = json!(j),
        Detail::Health(h) => v["health"] = json!(h),
        Detail::Security(s) => v["security"] = json!(s),
        Detail::More(n) => v["more"] = json!(n),
        Detail::Test => {}
    }
    v
}

/// The request for one event to one destination. Repo text was `clean`ed when the event was
/// built; here it is escaped for the target, and kept out of headers entirely.
/// Errors only for Generic with no valid signing secret: it fails closed rather than send unsigned.
pub fn render(
    kind: Kind,
    secret: Option<&str>,
    token: Option<&str>,
    e: &Event,
    msg_id: &str,
    at: u64,
    link: Option<&str>,
) -> Result<Rendered, String> {
    let job_url = match &e.detail {
        Detail::Job(j) => j.url.as_deref().and_then(github_link),
        _ => None,
    };
    let json_h = ("Content-Type", "application/json".to_string());
    match kind {
        Kind::Generic => {
            let body = serde_json::to_vec(&generic_body(e, msg_id, at, link)).unwrap_or_default();
            let sig = secret.and_then(|s| sign(s, msg_id, at, &body)).ok_or("signing secret is invalid")?;
            let headers =
                vec![json_h, ("webhook-id", msg_id.to_string()), ("webhook-timestamp", at.to_string()), ("webhook-signature", sig)];
            Ok(Rendered { headers, body })
        }
        Kind::Slack => {
            let mut t = summary(e, &slack_esc);
            for (u, label) in [(job_url, "details"), (link, "kiln")] {
                if let Some(u) = u {
                    t += &format!(" <{u}|{label}>");
                }
            }
            let v = json!({ "text": t, "unfurl_links": false, "unfurl_media": false, "mrkdwn": false });
            Ok(Rendered { headers: vec![json_h], body: serde_json::to_vec(&v).unwrap_or_default() })
        }
        Kind::Discord => {
            let mut t = summary(e, &discord_esc);
            for u in [job_url, link].into_iter().flatten() {
                t += &format!("\n<{u}>");
            }
            let v = json!({ "content": t, "username": "kiln", "allowed_mentions": { "parse": [] } });
            Ok(Rendered { headers: vec![json_h], body: serde_json::to_vec(&v).unwrap_or_default() })
        }
        Kind::Ntfy => {
            let mut t = summary(e, &delink);
            for u in [job_url, link].into_iter().flatten() {
                t += &format!("\n{u}");
            }
            let mut headers = vec![("Content-Type", "text/plain; charset=utf-8".to_string()), ("Title", title(e.ty).to_string())];
            let (prio, tag) = match e.ty {
                "job.failed" | "health.raised" | "security.changed" => ("high", "warning"),
                _ => ("default", "white_check_mark"),
            };
            headers.push(("Priority", prio.into()));
            headers.push(("Tags", tag.into()));
            if let Some(tk) = token {
                headers.push(("Authorization", format!("Bearer {tk}")));
            }
            Ok(Rendered { headers, body: t.into_bytes() })
        }
    }
}

/// Standard Webhooks v1: `v1,` + base64(HMAC-SHA256(key, "id.timestamp.body")), the key being
/// the base64 after `whsec_`. None for a malformed secret.
pub fn sign(secret: &str, id: &str, ts: u64, body: &[u8]) -> Option<String> {
    let key = B64.decode(secret.strip_prefix("whsec_")?).ok()?;
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let mut m = Vec::with_capacity(id.len() + body.len() + 24);
    m.extend_from_slice(id.as_bytes());
    m.push(b'.');
    m.extend_from_slice(ts.to_string().as_bytes());
    m.push(b'.');
    m.extend_from_slice(body);
    Some(format!("v1,{}", B64.encode(ring::hmac::sign(&k, &m).as_ref())))
}

/// 32 random bytes as `whsec_<base64>`.
pub fn new_secret() -> String {
    format!("whsec_{}", B64.encode(random::<32>()))
}

/// `N` bytes from the system CSPRNG.
fn random<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut b).expect("system RNG");
    b
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Events {
    #[serde(default = "yes")]
    pub job: bool,
    #[serde(default = "yes")]
    pub health: bool,
    #[serde(default = "yes")]
    pub security: bool,
}

fn yes() -> bool {
    true
}

impl Default for Events {
    fn default() -> Self {
        Events { job: true, health: true, security: true }
    }
}

/// One destination as stored in `<data>/notify.json` (0600). `url`, `secret` and `token` are
/// secrets: they leave this module only towards the destination itself, except a new signing
/// secret, returned once to the admin who caused it (create, rotate, kind or origin change).
#[derive(Serialize, Deserialize, Clone)]
pub struct Dest {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default)]
    pub tailnet: bool,
    #[serde(default)]
    pub link: bool,
    #[serde(default)]
    pub events: Events,
}

impl Dest {
    pub fn host(&self) -> String {
        reqwest::Url::parse(&self.url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| "?".into())
    }

    /// How logs and audit notes name it: never the URL.
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, self.host())
    }

    pub fn wants(&self, e: &Event) -> bool {
        if e.to.iter().any(|t| t == &self.id) {
            return true;
        }
        match e.class {
            Class::Job => self.events.job,
            Class::Health => self.events.health,
            Class::Security => self.events.security,
            Class::Direct => false,
        }
    }
}

#[derive(Serialize, Default, Clone)]
pub struct Status {
    pub last_ok: Option<u64>,
    /// (when, what): an HTTP status or error kind, ≤ 200 chars, no secrets.
    pub last_error: Option<(u64, String)>,
    pub failing_since: Option<u64>,
    pub permanent_streak: u32,
    pub dropped: u64,
}

/// A missing file is no destinations. An unreadable one is an error and is never rewritten.
pub fn load(data: &Path) -> Result<Vec<Dest>, String> {
    match std::fs::read(data.join("notify.json")) {
        // Only the category and position: serde's message can echo file values (secrets).
        Ok(b) => serde_json::from_slice(&b).map_err(|e| {
            format!("notify.json unreadable ({:?} error at line {}, column {}): fix or remove it", e.classify(), e.line(), e.column())
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("notify.json unreadable ({:?}): fix or remove it", e.kind())),
    }
}

pub fn save(data: &Path, d: &[Dest]) -> anyhow::Result<()> {
    crate::app_auth::write_private(&data.join("notify.json"), &serde_json::to_vec_pretty(d)?)
}

/// What the API and dashboard may see of a destination.
pub fn public(d: &Dest, st: &Status) -> Value {
    json!({ "id": d.id, "name": d.name, "kind": d.kind, "host": d.host(), "tailnet": d.tailnet, "link": d.link, "events": d.events, "status": st })
}

/// One destination's queue: bounded, dropping the oldest.
#[derive(Default)]
pub struct Queue {
    pub q: Mutex<VecDeque<Event>>,
    pub wake: tokio::sync::Notify,
    /// Set when the destination was removed or replaced: the worker drains, then exits.
    pub retired: std::sync::atomic::AtomicBool,
    /// True while the worker is sending (so `flush` waits for in-flight alerts).
    pub busy: std::sync::atomic::AtomicBool,
}

/// All notification state, on `App`. Lock order: dests, then queues, then status; never take an earlier one while holding a later one.
#[derive(Default)]
pub struct Hub {
    pub dests: Mutex<Vec<Dest>>,
    /// Why notify.json could not be loaded (notifications off until fixed).
    pub load_error: Mutex<Option<String>>,
    pub status: Mutex<HashMap<String, Status>>,
    pub queues: Mutex<HashMap<String, std::sync::Arc<Queue>>>,
    /// VM ids already alerted, so a VM never alerts twice.
    pub alerted: Mutex<std::collections::HashSet<String>>,
    pub health: Mutex<HealthTrack>,
    pub last_test: Mutex<HashMap<String, std::time::Instant>>,
}

/// Which problem kinds are announced as active, and candidates for a change.
#[derive(Default)]
pub struct HealthTrack {
    /// kind -> message as last announced.
    active: HashMap<String, String>,
    /// kind -> (wants to be active, first seen in that state, consecutive ticks).
    pending: HashMap<String, (bool, u64, u32)>,
}

/// Stable changes since the last call: a kind must hold its new state for 2 ticks and 60 s.
pub fn transitions(t: &mut HealthTrack, now_list: &[(String, String)], now: u64) -> Vec<HealthInfo> {
    let mut kinds: Vec<String> = t.active.keys().chain(t.pending.keys()).cloned().collect();
    kinds.extend(now_list.iter().map(|(k, _)| k.clone()));
    kinds.sort();
    kinds.dedup();
    let mut out = vec![];
    for k in kinds {
        let msg = now_list.iter().find(|(x, _)| *x == k).map(|(_, m)| m.clone());
        let want = msg.is_some();
        if want == t.active.contains_key(&k) {
            t.pending.remove(&k);
            continue;
        }
        let p = t.pending.entry(k.clone()).or_insert((want, now, 0));
        if p.0 != want {
            *p = (want, now, 0);
        }
        p.2 += 1;
        if p.2 >= 2 && now.saturating_sub(p.1) >= 60 {
            t.pending.remove(&k);
            if let Some(m) = msg {
                t.active.insert(k.clone(), m.clone());
                out.push(HealthInfo { kind: k, message: clean(&m), state: "raised" });
            } else if let Some(m) = t.active.remove(&k) {
                out.push(HealthInfo { kind: k, message: clean(&m), state: "cleared" });
            }
        }
    }
    out
}

/// Feed this tick's problems; emit raised/cleared alerts.
pub fn health(app: &crate::App, now_list: Vec<(String, String)>, now: u64) {
    let changes = transitions(&mut app.notify.health.lock().unwrap(), &now_list, now);
    for h in changes {
        let ty = if h.state == "raised" { "health.raised" } else { "health.cleared" };
        emit(app, Event { ty, class: Class::Health, detail: Detail::Health(h), to: vec![] });
    }
}

/// DNS for alert requests: system resolution, then only addresses `allowed` may pass. The
/// connection uses exactly these, so there is no gap for a rebind between check and connect.
struct Guard {
    tailnet: bool,
}

impl reqwest::dns::Resolve for Guard {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let tailnet = self.tailnet;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs = keep_allowed(tokio::net::lookup_host((host.as_str(), 0)).await?, tailnet);
            if addrs.is_empty() {
                return Err(format!("{host} resolves only to internal addresses").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Only the addresses an alert may connect to.
fn keep_allowed(addrs: impl Iterator<Item = SocketAddr>, tailnet: bool) -> Vec<SocketAddr> {
    addrs.filter(|a| allowed(a.ip(), tailnet)).collect()
}

/// The client for one destination. `open_for_tests` allows plain HTTP to the loopback
/// receiver, and only in test builds: a release build ignores it.
fn client(d: &Dest, open_for_tests: bool) -> reqwest::Client {
    let b = reqwest::Client::builder()
        .user_agent(concat!("kiln/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    let open = open_for_tests && cfg!(test);
    let b = if open { b } else { b.https_only(true).dns_resolver(Arc::new(Guard { tailnet: d.tailnet })) };
    b.build().expect("notify http client")
}

#[derive(Debug)]
pub enum Outcome {
    Ok,
    Retry(String, Option<Duration>),
    Permanent(String),
}

fn classify(status: u16, retry_after: Option<&str>) -> Outcome {
    match status {
        200..=299 => Outcome::Ok,
        429 => Outcome::Retry(
            "HTTP 429".into(),
            Some(Duration::from_secs(retry_after.and_then(|s| s.trim().parse().ok()).unwrap_or(30).clamp(1, 300))),
        ),
        408 | 500..=599 => Outcome::Retry(format!("HTTP {status}"), None),
        _ => Outcome::Permanent(format!("HTTP {status}")),
    }
}

/// The dashboard's own address for links: an https `.ts.net` URL, else none (a LAN or loopback
/// address in a chat message is useless and leaks topology).
fn dashboard_base() -> Option<String> {
    // ponytail: no link until web.rs caches the serve URL; never shell out to tailscale from the send path
    None::<String>.filter(|b| link_base_ok(b))
}

/// Only `https://<lowercase host>.ts.net[:port][/path]`: no userinfo, query or fragment, and nothing
/// that could break out of a chat link.
fn link_base_ok(s: &str) -> bool {
    if s.chars().any(|c| c.is_whitespace() || matches!(c, '|' | '<' | '>' | '"' | '\'')) {
        return false;
    }
    let Ok(u) = reqwest::Url::parse(s) else { return false };
    let host = u.host_str().unwrap_or("");
    u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && s.split("://").nth(1).and_then(|r| r.split(['/', ':']).next()) == Some(host) // Url lowercases; the original must already be
        && host.strip_suffix(".ts.net").is_some_and(|l| !l.is_empty())
}

/// Writes worth a security alert. Destination changes are announced by their own handlers
/// (before the change, so a removed destination hears it), so they are not here.
fn action_for(path: &str) -> Option<&'static str> {
    match path {
        "/api/config" => Some("settings changed"),
        "/api/token" => Some("GitHub token replaced"),
        // Every write to /api/app is a real change (create or remove); refresh and manifest are not.
        "/api/app" | "/api/app/convert" => Some("GitHub App changed"),
        _ => None,
    }
}

/// The setting names in a `config_changes` note: `egress: "a" -> "b", repos` -> [egress, repos].
/// Quote-aware (values are JSON strings), and only identifier-like keys survive, so a value
/// containing ", " or ":" cannot inject text.
fn changed_keys(note: &str) -> Vec<String> {
    let mut out = vec![];
    let (mut key, mut key_done, mut quoted, mut esc) = (String::new(), false, false, false);
    let flush = |key: &mut String, key_done: &mut bool, out: &mut Vec<String>| {
        let k = key.trim();
        if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && out.len() < 20 {
            out.push(k.to_string());
        }
        key.clear();
        *key_done = false;
    };
    let mut it = note.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => quoted = false,
                _ => {}
            }
        } else if c == '"' {
            quoted = true;
        } else if c == ',' && it.peek() == Some(&' ') {
            it.next();
            flush(&mut key, &mut key_done, &mut out);
            continue;
        } else if c == ':' {
            key_done = true;
        }
        if !key_done {
            key.push(c);
        }
    }
    flush(&mut key, &mut key_done, &mut out);
    out
}

/// Called by `web::admit` for every admitted, successful API write.
pub fn security(app: &crate::App, actor: &str, path: &str, note: Option<&str>) {
    let Some(action) = action_for(path) else { return };
    let changed = note.map(changed_keys).unwrap_or_default();
    if path == "/api/config" && changed.is_empty() {
        return; // a save that changed nothing
    }
    emit(
        app,
        Event {
            ty: "security.changed",
            class: Class::Security,
            to: vec![],
            detail: Detail::Security(SecurityInfo { actor: clean(actor), action: action.into(), changed }),
        },
    );
}

/// A fresh Standard Webhooks message id.
fn new_msg_id() -> String {
    format!("msg_{}", B64.encode(random::<12>()).replace(['+', '/', '='], ""))
}

/// One POST. Every message returned is a fixed string: never the URL, path, query or body.
/// `msg_id` is the event's: the same on every retry, so a receiver can de-duplicate.
async fn send_once(c: &reqwest::Client, d: &Dest, e: &Event, msg_id: &str, open_for_tests: bool) -> Outcome {
    let Ok(u) = reqwest::Url::parse(&d.url) else { return Outcome::Permanent("bad URL".into()) };
    let open = open_for_tests && cfg!(test);
    if !open && literal_ip(&u).is_some_and(|ip| !allowed(ip, d.tailnet)) {
        return Outcome::Permanent("refused: internal address".into());
    }
    // The URL rules again, on every send: a hand-edited notify.json must not get past them.
    if !open && check_url(d.kind, &d.url, d.tailnet).is_err() {
        return Outcome::Permanent("refused: stored URL no longer allowed".into());
    }
    let link = match (&e.detail, d.link) {
        (Detail::Job(j), true) => dashboard_base().map(|b| format!("{b}/#/jobs/{}", j.vm_id)),
        _ => None,
    };
    let r = match render(d.kind, d.secret.as_deref(), d.token.as_deref(), e, msg_id, crate::now(), link.as_deref()) {
        Ok(r) => r,
        Err(m) => return Outcome::Permanent(m),
    };
    let mut req = c.post(u).body(r.body);
    for (k, v) in r.headers {
        req = req.header(k, v);
    }
    match req.send().await {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let ra = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_string);
            // Read (and discard) at most 4 KiB; the body never matters beyond the status.
            let mut seen = 0;
            while seen < 4096 {
                match resp.chunk().await {
                    Ok(Some(b)) => seen += b.len(),
                    _ => break,
                }
            }
            classify(status, ra.as_deref())
        }
        Err(err) if err.is_timeout() => Outcome::Retry("timed out".into(), None),
        Err(err) if err.is_connect() => {
            // The error's Display carries the URL: inspect it, never store it.
            let inward = std::iter::successors(std::error::Error::source(&err), |e| e.source())
                .any(|e| e.to_string().contains("internal addresses"));
            if inward {
                Outcome::Permanent("refused: resolves only to internal addresses".into())
            } else {
                Outcome::Retry("could not connect".into(), None)
            }
        }
        Err(err) if err.is_builder() => Outcome::Permanent("request refused (URL)".into()),
        Err(_) => Outcome::Retry("request failed".into(), None),
    }
}

/// Queue `e` for every destination that wants it. Never blocks; a full queue drops its oldest.
pub fn emit(app: &crate::App, e: Event) {
    let h = &app.notify;
    let skip = failing_ids(app, &e);
    let ids: Vec<String> = h.dests.lock().unwrap().iter().filter(|d| d.wants(&e) && !skip.contains(&d.id)).map(|d| d.id.clone()).collect();
    for id in ids {
        let Some(q) = h.queues.lock().unwrap().get(&id).cloned() else { continue };
        let mut g = q.q.lock().unwrap();
        if g.len() >= 256 {
            g.pop_front();
            h.status.lock().unwrap().entry(id.clone()).or_default().dropped += 1;
        }
        g.push_back(e.clone());
        drop(g);
        q.wake.notify_one();
    }
}

/// A notify_failing health event goes only to destinations that are not themselves failing.
fn failing_ids(app: &crate::App, e: &Event) -> Vec<String> {
    match &e.detail {
        Detail::Health(hi) if hi.kind == "notify_failing" => failing(app).into_iter().map(|(id, _)| id).collect(),
        _ => vec![],
    }
}

/// Destinations whose failures have gone on for an hour (an Ok resets the status), or with 3
/// permanent failures in a row: (id, message).
pub fn failing(app: &crate::App) -> Vec<(String, String)> {
    let dests = app.notify.dests.lock().unwrap();
    let st = app.notify.status.lock().unwrap();
    dests
        .iter()
        .filter_map(|d| {
            let s = st.get(&d.id)?;
            let hour = s.failing_since.zip(s.last_error.as_ref()).is_some_and(|(f, (t, _))| t.saturating_sub(f) >= 3600);
            let bad = s.permanent_streak >= 3 || hour;
            bad.then(|| (d.id.clone(), format!("{}: {}", d.label(), s.last_error.as_ref().map_or("failing", |e| e.1.as_str()))))
        })
        .collect()
}

fn jitter(d: Duration) -> Duration {
    let r = u16::from_le_bytes(random::<2>()) as f64 / u16::MAX as f64; // 0..1
    d.mul_f64(0.8 + 0.4 * r)
}

/// Deliver one event with the retry schedule, recording the outcome.
async fn deliver(app: &crate::App, c: &reqwest::Client, d: &Dest, e: &Event) {
    let waits = [5u64, 30, 120];
    let id = new_msg_id();
    for attempt in 0..=waits.len() {
        let out = send_once(c, d, e, &id, false).await;
        let now = crate::now();
        // Record under the lock in its own scope: a guard must not live across the sleep.
        let (m, after) = {
            let mut st = app.notify.status.lock().unwrap();
            let s = st.entry(d.id.clone()).or_default();
            match out {
                Outcome::Ok => {
                    *s = Status { last_ok: Some(now), dropped: s.dropped, ..Default::default() };
                    return;
                }
                Outcome::Permanent(m) => {
                    s.last_error = Some((now, m.chars().take(200).collect()));
                    s.failing_since.get_or_insert(now);
                    s.permanent_streak += 1;
                    tracing::warn!("notify {}: {m}", d.label());
                    return;
                }
                Outcome::Retry(m, after) => {
                    s.last_error = Some((now, m.chars().take(200).collect()));
                    s.failing_since.get_or_insert(now);
                    (m, after)
                }
            }
        };
        let Some(w) = waits.get(attempt) else {
            tracing::warn!("notify {}: {m}, giving up after {} attempts", d.label(), attempt + 1);
            return;
        };
        tokio::time::sleep(after.unwrap_or_else(|| jitter(Duration::from_secs(*w)))).await;
    }
}

/// Fold `e` into "+N more"? Over 30 sends a minute, except security changes: always sent.
fn folds(e: &Event, recent: usize) -> bool {
    recent >= 30 && e.ty != "security.changed"
}

async fn send_more(app: &crate::App, q: &Queue, c: &reqwest::Client, d: &Dest, n: u64) {
    let more = Event { ty: "more", class: Class::Direct, detail: Detail::More(n), to: vec![d.id.clone()] };
    q.busy.store(true, std::sync::atomic::Ordering::SeqCst);
    deliver(app, c, d, &more).await;
    q.busy.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub fn spawn_worker(app: &Arc<crate::App>, d: Dest) {
    let q = Arc::new(Queue::default());
    app.notify.queues.lock().unwrap().insert(d.id.clone(), q.clone());
    // Unit tests inspect the queue and must never reach the network: no delivery task.
    if cfg!(test) {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        let c = client(&d, false);
        let mut sent: VecDeque<std::time::Instant> = VecDeque::new();
        let mut folded = 0u64;
        loop {
            let next = q.q.lock().unwrap().pop_front();
            let Some(e) = next else {
                if q.retired.load(std::sync::atomic::Ordering::SeqCst) {
                    if folded > 0 {
                        send_more(&app, &q, &c, &d, folded).await;
                    }
                    return;
                }
                // Wake on new events, or after a minute to flush folded overflow.
                let _ = tokio::time::timeout(Duration::from_secs(60), q.wake.notified()).await;
                if folded > 0 && sent.front().is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                    send_more(&app, &q, &c, &d, folded).await;
                    folded = 0;
                }
                continue;
            };
            while sent.front().is_some_and(|t| t.elapsed() >= Duration::from_secs(60)) {
                sent.pop_front();
            }
            if folds(&e, sent.len()) {
                folded += 1;
                continue;
            }
            sent.push_back(std::time::Instant::now());
            q.busy.store(true, std::sync::atomic::Ordering::SeqCst);
            deliver(&app, &c, &d, &e).await;
            q.busy.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    });
}

/// On shutdown: give queued alerts up to 2 s to go out.
pub async fn flush(app: &crate::App) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline
        && app
            .notify
            .queues
            .lock()
            .unwrap()
            .values()
            .any(|q| !q.q.lock().unwrap().is_empty() || q.busy.load(std::sync::atomic::Ordering::SeqCst))
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Load destinations and start one worker each. An unreadable notify.json leaves
/// notifications off and is reported, never rewritten.
pub fn start(app: &Arc<crate::App>) {
    match load(&app.data) {
        Ok(ds) => {
            for d in &ds {
                spawn_worker(app, d.clone());
            }
            *app.notify.dests.lock().unwrap() = ds;
        }
        Err(m) => {
            tracing::error!("{m}");
            *app.notify.load_error.lock().unwrap() = Some(m);
        }
    }
}

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::{Extension, Json};

/// A workflow rule, saved in config.json: a finished job whose repo, workflow and outcome match
/// (see `rule_matches`) goes to the destinations in `to`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Rule {
    pub repo: String,
    pub workflow: String,
    pub outcome: String,
    pub to: Vec<String>,
}

pub fn rule_matches(r: &Rule, repo: &str, workflow: Option<&str>, succeeded: bool) -> bool {
    (r.repo == "*" || r.repo.eq_ignore_ascii_case(repo))
        && (r.workflow == "*" || workflow == Some(r.workflow.as_str()))
        && match r.outcome.as_str() {
            "success" => succeeded,
            "failure" => !succeeded,
            _ => true,
        }
}

/// A finished VM's job outcome; None when no job ran on it (or it was a registration failure).
pub fn outcome(v: &crate::vm::Vm) -> Option<&'static str> {
    use crate::vm::State;
    if v.mint_failed || v.busy_since.is_none() {
        return None;
    }
    Some(match v.state {
        State::Done => match v.result.as_deref() {
            Some("Succeeded") => "succeeded",
            Some(r) if r.to_ascii_lowercase().contains("cancel") => "cancelled",
            _ => "failed",
        },
        State::Failed => "failed",
        State::Killed => "killed",
        State::Lost => "lost",
        _ => return None,
    })
}

/// Alert for a VM that just ended: `job.failed` for any non-success, `job.finished` for a
/// success matching a rule. At most once per VM id.
pub fn job_ended(app: &crate::App, v: &crate::vm::Vm) {
    // A fork PR job kiln refused itself is policy, not a failure.
    if v.fork || v.note.as_deref().is_some_and(|n| n.starts_with("refused: pull request from a fork")) {
        return;
    }
    let Some(oc) = outcome(v) else { return };
    let ok = oc == "succeeded";
    let wf = v.run.as_ref().map(|r| r.file.as_str()).filter(|w| !w.is_empty());
    let mut to: Vec<String> =
        app.cfg().notify_rules.iter().filter(|r| rule_matches(r, &v.repo, wf, ok)).flat_map(|r| r.to.clone()).collect();
    if ok && to.is_empty() {
        return;
    }
    {
        let mut seen = app.notify.alerted.lock().unwrap();
        // ponytail: forget everything past 2000 ids; a VM id carries its start time, so it cannot recur
        // within 2000 later VMs. Upgrade to an LRU only if a repeat alert is ever seen.
        if seen.len() > 2000 {
            seen.clear();
        }
        if !seen.insert(v.id.clone()) {
            return;
        }
    }
    let run = v.run.clone().unwrap_or_default();
    let opt = |s: &str| (!s.is_empty()).then(|| clean(s));
    let info = JobInfo {
        repo: clean(&v.repo),
        workflow: opt(&run.file),
        workflow_name: opt(&run.workflow),
        job: clean(v.job.as_deref().unwrap_or("job")),
        branch: opt(&run.branch),
        event: opt(&run.event),
        outcome: oc.to_string(),
        // A lost VM with no measurable run has no duration worth stating.
        duration_s: v.busy_since.zip(v.done_at.or(v.ended)).map(|(a, b)| b.saturating_sub(a)).filter(|d| *d > 0 || oc != "lost"),
        url: v.job_url.clone(),
        vm_id: v.id.clone(),
    };
    let (ty, class) = if ok { ("job.finished", Class::Direct) } else { ("job.failed", Class::Job) };
    to.sort();
    to.dedup();
    emit(app, Event { ty, class, detail: Detail::Job(info), to });
}

/// Rule problems a config save must refuse, for the rules in `new` that are not in `old` (by
/// value): an unknown destination id (`dest_ids` None: destinations unknown, not checked) or a
/// repo that is neither "*" nor in `repos`. Existing rules are never re-checked, so a broken
/// notify.json or a removed repo never blocks an unrelated save.
pub fn rule_errors(old: &[Rule], new: &[Rule], dest_ids: Option<&[String]>, repos: &[String]) -> Vec<String> {
    let mut errs = vec![];
    for r in new.iter().filter(|r| !old.contains(r)) {
        if let Some(ids) = dest_ids {
            errs.extend(r.to.iter().filter(|t| !ids.contains(t)).map(|t| format!("notify_rules: unknown destination {t}")));
        }
        if r.repo != "*" && !repos.iter().any(|x| x.eq_ignore_ascii_case(&r.repo)) {
            errs.push(format!("notify_rules: {:?} is not one of your repos (or \"*\")", r.repo));
        }
    }
    let mut seen = std::collections::HashSet::new();
    errs.retain(|e| seen.insert(e.clone()));
    errs
}

/// Who made an admitted request, set by `web::admit` for handlers that announce changes.
#[derive(Clone)]
pub struct Actor(pub String);

type ApiResult<T> = Result<T, (StatusCode, String)>;
type Noted = ApiResult<(Extension<crate::audit::Note>, Json<Value>)>;

fn bad(m: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, m.into())
}

fn missing() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "no such destination".to_string())
}

#[derive(Deserialize)]
pub struct DestBody {
    name: String,
    kind: Kind,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    tailnet: bool,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    events: Option<Events>,
}

fn new_id() -> String {
    random::<4>().iter().map(|b| format!("{b:02x}")).collect()
}

/// Validate `b` into `d` (an existing destination for edits, or a fresh one).
fn apply(b: DestBody, mut d: Dest, others: &[Dest]) -> ApiResult<Dest> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(|c| c.is_control() || invisible(c)) {
        return Err(bad("name: 1 to 40 characters"));
    }
    if others.iter().any(|o| o.id != d.id && o.name.eq_ignore_ascii_case(name)) {
        return Err(bad("another destination already has that name"));
    }
    if b.kind != d.kind && b.url.as_deref().is_none_or(|u| u.trim().is_empty()) {
        return Err(bad("changing the kind needs the URL again"));
    }
    d.name = name.to_string();
    d.kind = b.kind;
    d.tailnet = b.tailnet;
    d.link = b.link;
    if let Some(ev) = b.events {
        d.events = ev;
    }
    let origin = |u: &str| reqwest::Url::parse(u).ok().map(|u| u.origin());
    let was = origin(&d.url);
    if let Some(u) = b.url.filter(|u| !u.trim().is_empty()) {
        d.url = check_url(d.kind, &u, d.tailnet).map_err(bad)?.to_string();
    } else {
        // Re-check the stored URL: `tailnet` may have just been switched off.
        check_url(d.kind, &d.url, d.tailnet).map_err(bad)?;
    }
    // A new scheme, host or port is a new party: it never inherits the old one's credentials.
    // The token is dropped unless a new one comes with this edit; a generic secret is replaced.
    if origin(&d.url) != was {
        d.token = None;
        d.secret = None;
    }
    match b.token.map(|t| t.trim().to_string()) {
        Some(t) if d.kind == Kind::Ntfy && !t.is_empty() => {
            if t.len() > 200 || !t.chars().all(|c| c.is_ascii_graphic()) {
                return Err(bad("ntfy token: up to 200 visible ASCII characters"));
            }
            d.token = Some(t);
        }
        _ if d.kind != Kind::Ntfy => d.token = None,
        _ => {}
    }
    if d.kind == Kind::Generic && d.secret.is_none() {
        d.secret = Some(new_secret());
    }
    if d.kind != Kind::Generic {
        d.secret = None;
    }
    Ok(d)
}

/// Which settings differ, by name only: never a URL or token value.
fn changed_fields(a: &Dest, b: &Dest) -> Vec<&'static str> {
    [
        ("name", a.name != b.name),
        ("kind", a.kind != b.kind),
        ("url", a.url != b.url),
        ("token", a.token != b.token),
        ("tailnet", a.tailnet != b.tailnet),
        ("link", a.link != b.link),
        ("events.job", a.events.job != b.events.job),
        ("events.health", a.events.health != b.events.health),
        ("events.security", a.events.security != b.events.security),
    ]
    .into_iter()
    .filter_map(|(f, c)| c.then_some(f))
    .collect()
}

/// Tell every current destination (whatever its event switches say) about a change.
fn announce(app: &crate::App, actor: &str, action: String) {
    let to: Vec<String> = app.notify.dests.lock().unwrap().iter().map(|d| d.id.clone()).collect();
    emit(
        app,
        Event {
            ty: "security.changed",
            class: Class::Direct,
            to,
            detail: Detail::Security(SecurityInfo { actor: clean(actor), action, changed: vec![] }),
        },
    );
}

/// One edit at a time: no lost updates, no getting past the destination cap.
static EDIT: Mutex<()> = Mutex::new(());

fn edit_lock() -> std::sync::MutexGuard<'static, ()> {
    EDIT.lock().unwrap_or_else(|e| e.into_inner())
}

fn persist(app: &crate::App, ds: &[Dest]) -> ApiResult<()> {
    // The io error names the path, never a destination's contents.
    save(&app.data, ds).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("saving notify.json: {e:#}")))
}

/// Stop a destination's worker after it drains what is queued (the announcement included).
fn retire(app: &crate::App, id: &str) {
    if let Some(q) = app.notify.queues.lock().unwrap().remove(id) {
        q.retired.store(true, std::sync::atomic::Ordering::SeqCst);
        q.wake.notify_one();
    }
}

async fn list(State(app): State<Arc<crate::App>>) -> Json<Value> {
    Json(state_json(&app))
}

/// The redacted destination list plus `load_error`: no URL, secret or token.
pub fn state_json(app: &crate::App) -> Value {
    let dests = app.notify.dests.lock().unwrap().clone();
    let st = app.notify.status.lock().unwrap();
    let ds: Vec<Value> = dests.iter().map(|d| public(d, &st.get(&d.id).cloned().unwrap_or_default())).collect();
    drop(st);
    json!({ "dests": ds, "load_error": *app.notify.load_error.lock().unwrap() })
}

async fn create(State(app): State<Arc<crate::App>>, Extension(actor): Extension<Actor>, Json(b): Json<DestBody>) -> Noted {
    let _edit = edit_lock();
    if app.notify.load_error.lock().unwrap().is_some() {
        return Err(bad("notify.json is unreadable: fix or remove it first"));
    }
    if b.url.as_deref().is_none_or(|u| u.trim().is_empty()) {
        return Err(bad("url is required"));
    }
    let mut ds = app.notify.dests.lock().unwrap().clone();
    if ds.len() >= 20 {
        return Err(bad("at most 20 destinations"));
    }
    let blank = Dest {
        id: new_id(),
        name: String::new(),
        kind: b.kind,
        url: String::new(),
        secret: None,
        token: None,
        tailnet: false,
        link: false,
        events: Events::default(),
    };
    let d = apply(b, blank, &ds)?;
    ds.push(d.clone());
    persist(&app, &ds)?;
    *app.notify.dests.lock().unwrap() = ds;
    spawn_worker(&app, d.clone());
    let what = format!("added notification destination {} ({:?})", d.label(), d.kind);
    announce(&app, &actor.0, what.clone());
    let shown = public(&d, &Status::default());
    Ok((Extension(crate::audit::Note(what)), Json(json!({ "dest": shown, "secret": d.secret }))))
}

async fn update(
    State(app): State<Arc<crate::App>>,
    Extension(actor): Extension<Actor>,
    UrlPath(id): UrlPath<String>,
    Json(b): Json<DestBody>,
) -> Noted {
    let _edit = edit_lock();
    let mut ds = app.notify.dests.lock().unwrap().clone();
    let i = ds.iter().position(|d| d.id == id).ok_or_else(missing)?;
    let new = apply(b, ds[i].clone(), &ds)?;
    let url_changed = new.url != ds[i].url;
    // A new secret (the kind just became generic, or the URL moved to another origin): shown once.
    let fresh = if new.secret != ds[i].secret { new.secret.clone() } else { None };
    let fields = changed_fields(&ds[i], &new);
    let what = if fields.is_empty() {
        format!("saved notification destination {} unchanged", new.label())
    } else {
        format!("changed notification destination {}: {}", new.label(), fields.join(", "))
    };
    ds[i] = new.clone();
    persist(&app, &ds)?;
    // Queued to the current (old) worker first, so the old target hears it.
    announce(&app, &actor.0, what.clone());
    *app.notify.dests.lock().unwrap() = ds;
    retire(&app, &id);
    spawn_worker(&app, new.clone());
    let st = {
        let mut sts = app.notify.status.lock().unwrap();
        if url_changed {
            let dropped = sts.get(&id).map_or(0, |s| s.dropped);
            sts.insert(id.clone(), Status { dropped, ..Default::default() });
        }
        sts.get(&id).cloned().unwrap_or_default()
    };
    Ok((Extension(crate::audit::Note(what)), Json(json!({ "dest": public(&new, &st), "secret": fresh }))))
}

async fn rotate(State(app): State<Arc<crate::App>>, Extension(actor): Extension<Actor>, UrlPath(id): UrlPath<String>) -> Noted {
    let _edit = edit_lock();
    let mut ds = app.notify.dests.lock().unwrap().clone();
    let d = ds.iter_mut().find(|d| d.id == id).ok_or_else(missing)?;
    if d.kind != Kind::Generic {
        return Err(bad("only generic destinations have a signing secret"));
    }
    let secret = new_secret();
    d.secret = Some(secret.clone());
    let (what, d2) = (format!("rotated the signing secret of {}", d.label()), d.clone());
    persist(&app, &ds)?;
    // Queued to the old worker, which signs it with the old secret the receiver still knows.
    announce(&app, &actor.0, what.clone());
    *app.notify.dests.lock().unwrap() = ds;
    retire(&app, &id);
    spawn_worker(&app, d2);
    Ok((Extension(crate::audit::Note(what)), Json(json!({ "secret": secret }))))
}

async fn remove(State(app): State<Arc<crate::App>>, Extension(actor): Extension<Actor>, UrlPath(id): UrlPath<String>) -> Noted {
    let _edit = edit_lock();
    let mut ds = app.notify.dests.lock().unwrap().clone();
    let i = ds.iter().position(|d| d.id == id).ok_or_else(missing)?;
    let what = format!("removed notification destination {}", ds[i].label());
    ds.remove(i);
    // Rules first: rules naming it lose that target, and a rule left with none is dropped. If
    // this fails nothing has changed; the other order could leave rules naming a dead id.
    let mut c = app.cfg();
    c.notify_rules.iter_mut().for_each(|r| r.to.retain(|t| t != &id));
    c.notify_rules.retain(|r| !r.to.is_empty());
    let rules_saved = c.notify_rules != app.cfg().notify_rules;
    if rules_saved {
        app.save_cfg(c).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    }
    if let Err((code, e)) = persist(&app, &ds) {
        if !rules_saved {
            return Err((code, e));
        }
        tracing::error!("removing notification destination {id}: rules updated, but {e}");
        return Err((code, format!("rules updated, but the destination could not be removed: {e}")));
    }
    announce(&app, &actor.0, what.clone());
    *app.notify.dests.lock().unwrap() = ds;
    retire(&app, &id);
    app.notify.status.lock().unwrap().remove(&id);
    Ok((Extension(crate::audit::Note(what)), Json(json!({ "ok": true }))))
}

async fn test(State(app): State<Arc<crate::App>>, UrlPath(id): UrlPath<String>) -> ApiResult<Json<Value>> {
    if !app.notify.dests.lock().unwrap().iter().any(|d| d.id == id) {
        return Err(missing());
    }
    {
        let mut lt = app.notify.last_test.lock().unwrap();
        if lt.get(&id).is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "one test every 10 seconds".into()));
        }
        lt.insert(id.clone(), std::time::Instant::now());
    }
    emit(&app, Event { ty: "test", class: Class::Direct, detail: Detail::Test, to: vec![id] });
    Ok(Json(json!({ "queued": true })))
}

pub fn routes() -> axum::Router<Arc<crate::App>> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route("/api/notify", get(list).post(create))
        .route("/api/notify/{id}", put(update).delete(remove))
        .route("/api/notify/{id}/rotate", post(rotate))
        .route("/api/notify/{id}/test", post(test))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Vm;

    #[test]
    fn security_actions_and_keys() {
        assert_eq!(action_for("/api/config"), Some("settings changed"));
        assert_eq!(action_for("/api/token"), Some("GitHub token replaced"));
        assert_eq!(action_for("/api/app"), Some("GitHub App changed"));
        assert_eq!(action_for("/api/app/convert"), Some("GitHub App changed"));
        assert_eq!(action_for("/api/app/manifest"), None, "starting the manifest flow changes nothing");
        assert_eq!(action_for("/api/app/refresh"), None, "refreshing the installation list changes nothing");
        assert_eq!(action_for("/api/notify/a1b2c3d4"), None, "announced by the notify handlers themselves");
        assert_eq!(action_for("/api/vms/kiln-1-0/kill"), None);
        assert_eq!(changed_keys(r#"egress: "filtered" -> "open", repos, allowed_users"#), vec!["egress", "repos", "allowed_users"]);
        assert!(changed_keys("").is_empty());
        assert_eq!(changed_keys("a b: x, <b>, ok"), vec!["ok"]);
    }

    #[test]
    fn changed_keys_are_quote_aware() {
        assert_eq!(changed_keys(r#"egress: "a, evil: x" -> "b", repos"#), vec!["egress", "repos"]);
        assert_eq!(changed_keys(r#"label: "x, y" -> "z""#), vec!["label"]);
        assert_eq!(changed_keys(r#"listen: "0.0.0.0:7878" -> "127.0.0.1:7878""#), vec!["listen"]);
        assert_eq!(changed_keys(r#"label: "a\", evil" -> "b""#), vec!["label"]);
    }

    #[test]
    fn link_base_is_https_tailnet_only() {
        for ok in ["https://box.example.ts.net:8443", "https://box.example.ts.net", "https://box.tail1234.ts.net"] {
            assert!(link_base_ok(ok), "{ok}");
        }
        for bad in [
            "https://evil.example?.ts.net",
            "https://evil.example#.ts.net",
            "https://user@x.ts.net",
            "https://evil.example@x.ts.net",
            "https://X.TS.NET",
            "http://x.ts.net",
            "https://ts.net",
            "https://x.ts.net.evil.example",
            "https://evil.example",
            "https://box.ts.net|x",
            "https://box.ts.net/ a",
            "https://box.ts.net\"",
            "https://box.ts.net/'",
        ] {
            assert!(!link_base_ok(bad), "{bad}");
        }
    }

    #[test]
    fn noop_config_save_alerts_nobody() {
        let app = crate::App::for_tests();
        let d = dest(Kind::Ntfy, "https://ntfy.sh/acme-a");
        app.notify.dests.lock().unwrap().push(d.clone());
        let q = Arc::new(Queue::default());
        app.notify.queues.lock().unwrap().insert(d.id.clone(), q.clone());
        security(&app, "me", "/api/config", Some(""));
        assert!(q.q.lock().unwrap().is_empty());
        security(&app, "me", "/api/config", Some("repos"));
        assert_eq!(q.q.lock().unwrap().len(), 1);
        security(&app, "me", "/api/token", None);
        assert_eq!(q.q.lock().unwrap().len(), 2, "token has no keys but still alerts");
    }

    #[test]
    fn health_needs_two_ticks_and_a_minute() {
        let mut t = HealthTrack::default();
        let disk = vec![("disk".to_string(), "low disk".to_string())];
        assert!(transitions(&mut t, &disk, 0).is_empty(), "first sight");
        assert!(transitions(&mut t, &disk, 30).is_empty(), "two ticks but under a minute");
        let r = transitions(&mut t, &disk, 61);
        assert_eq!((r.len(), r[0].kind.as_str(), r[0].state), (1, "disk", "raised"));
        assert!(transitions(&mut t, &disk, 120).is_empty(), "still active: nothing new");
        assert!(transitions(&mut t, &[], 130).is_empty());
        assert!(transitions(&mut t, &[], 140).is_empty());
        let c = transitions(&mut t, &[], 200);
        assert_eq!((c.len(), c[0].state), (1, "cleared"));
    }

    #[test]
    fn flapping_condition_never_alerts() {
        let mut t = HealthTrack::default();
        let mem = vec![("memory".to_string(), "low memory".to_string())];
        for i in 0..40 {
            let list = if i % 2 == 0 { mem.clone() } else { vec![] };
            assert!(transitions(&mut t, &list, i * 10).is_empty(), "tick {i}");
        }
    }

    fn vm_end(state: crate::vm::State, result: Option<&str>) -> Vm {
        let mut v: Vm = serde_json::from_value(json!({
            "id": "kiln-9-0", "repo": "acme/kiln", "runner_id": 1, "state": "booting", "job": "test", "result": null,
            "started": 100, "busy_since": 110, "ended": 422, "note": null
        }))
        .unwrap();
        v.state = state;
        v.result = result.map(String::from);
        v.run = Some(crate::vm::Run {
            file: "release.yml".into(),
            workflow: "release".into(),
            branch: "main".into(),
            event: "push".into(),
            ..Default::default()
        });
        v
    }

    #[test]
    fn outcomes() {
        use crate::vm::State::*;
        assert_eq!(outcome(&vm_end(Done, Some("Succeeded"))), Some("succeeded"));
        assert_eq!(outcome(&vm_end(Done, Some("Failed"))), Some("failed"));
        assert_eq!(outcome(&vm_end(Done, Some("Canceled"))), Some("cancelled"));
        assert_eq!(outcome(&vm_end(Killed, None)), Some("killed"));
        assert_eq!(outcome(&vm_end(Lost, None)), Some("lost"));
        let mut never_ran = vm_end(Failed, None);
        never_ran.busy_since = None;
        assert_eq!(outcome(&never_ran), None, "a VM that never ran a job is not a job outcome");
        let mut mint = vm_end(Failed, None);
        mint.mint_failed = true;
        assert_eq!(outcome(&mint), None);
    }

    #[test]
    fn rules_match_repo_workflow_outcome() {
        let r = |repo: &str, wf: &str, oc: &str| Rule {
            repo: repo.into(),
            workflow: wf.into(),
            outcome: oc.into(),
            to: vec!["a1b2c3d4".into()],
        };
        assert!(rule_matches(&r("acme/kiln", "release.yml", "any"), "Acme/Kiln", Some("release.yml"), true));
        assert!(rule_matches(&r("*", "*", "success"), "x/y", None, true));
        assert!(!rule_matches(&r("*", "*", "success"), "x/y", None, false));
        assert!(rule_matches(&r("*", "release.yml", "failure"), "x/y", Some("release.yml"), false));
        assert!(!rule_matches(&r("*", "release.yml", "any"), "x/y", None, true), "unknown workflow matches only \"*\"");
        assert!(!rule_matches(&r("acme/other", "*", "any"), "acme/kiln", Some("ci.yml"), true));
    }

    #[test]
    fn job_alerts_once_per_vm() {
        let app = crate::App::for_tests();
        let d = dest(Kind::Ntfy, "https://ntfy.sh/acme-a");
        app.notify.dests.lock().unwrap().push(d.clone());
        let q = std::sync::Arc::new(Queue::default());
        app.notify.queues.lock().unwrap().insert(d.id.clone(), q.clone());
        let v = vm_end(crate::vm::State::Done, Some("Failed"));
        job_ended(&app, &v);
        job_ended(&app, &v);
        assert_eq!(q.q.lock().unwrap().len(), 1);
        let e = q.q.lock().unwrap()[0].clone();
        assert_eq!(e.ty, "job.failed");
        match e.detail {
            Detail::Job(j) => assert_eq!((j.workflow.as_deref(), j.duration_s), (Some("release.yml"), Some(312))),
            _ => panic!(),
        }
        // A success alerts only through a rule.
        let ok = Vm { id: "kiln-9-1".into(), ..vm_end(crate::vm::State::Done, Some("Succeeded")) };
        job_ended(&app, &ok);
        assert_eq!(q.q.lock().unwrap().len(), 1);
        let mut c = app.cfg();
        c.notify_rules = vec![Rule { repo: "*".into(), workflow: "release.yml".into(), outcome: "success".into(), to: vec![d.id.clone()] }];
        *app.cfg.write().unwrap() = c;
        let ok2 = Vm { id: "kiln-9-2".into(), ..vm_end(crate::vm::State::Done, Some("Succeeded")) };
        job_ended(&app, &ok2);
        assert_eq!(q.q.lock().unwrap().back().unwrap().ty, "job.finished");
    }

    fn job_app() -> (Arc<crate::App>, Arc<Queue>) {
        let app = crate::App::for_tests();
        let d = dest(Kind::Ntfy, "https://ntfy.sh/acme-a");
        app.notify.dests.lock().unwrap().push(d.clone());
        let q = Arc::new(Queue::default());
        app.notify.queues.lock().unwrap().insert(d.id.clone(), q.clone());
        (app, q)
    }

    #[test]
    fn refused_fork_jobs_never_alert() {
        let (app, q) = job_app();
        let fork = Vm { fork: true, ..vm_end(crate::vm::State::Killed, None) };
        job_ended(&app, &fork);
        let noted =
            Vm { id: "kiln-9-3".into(), note: Some("refused: pull request from a fork".into()), ..vm_end(crate::vm::State::Killed, None) };
        job_ended(&app, &noted);
        assert!(q.q.lock().unwrap().is_empty(), "kiln refused these jobs itself");
        job_ended(&app, &Vm { id: "kiln-9-4".into(), ..vm_end(crate::vm::State::Killed, None) });
        assert_eq!(q.q.lock().unwrap().len(), 1, "a plain kill still alerts");
    }

    #[test]
    fn lost_vm_without_duration_omits_it() {
        let (app, q) = job_app();
        let lost = Vm { ended: Some(110), ..vm_end(crate::vm::State::Lost, None) };
        job_ended(&app, &lost);
        match &q.q.lock().unwrap()[0].detail {
            Detail::Job(j) => assert_eq!((j.outcome.as_str(), j.duration_s), ("lost", None)),
            _ => panic!(),
        }
    }

    #[test]
    fn security_events_are_never_folded() {
        let ev = |ty| Event { ty, class: Class::Direct, detail: Detail::Test, to: vec![] };
        assert!(!folds(&ev("job.failed"), 29));
        assert!(folds(&ev("job.failed"), 30));
        assert!(!folds(&ev("security.changed"), 30));
        assert!(!folds(&ev("security.changed"), 500));
    }

    #[test]
    fn rule_checks_cover_only_new_or_changed_rules() {
        let r = |repo: &str, to: &str| Rule { repo: repo.into(), workflow: "*".into(), outcome: "any".into(), to: vec![to.into()] };
        let ids = vec!["a1b2c3d4".to_string()];
        let repos = vec!["acme/kiln".to_string()];
        let old = vec![r("acme/kiln", "ffffffff")];
        assert!(rule_errors(&old, &old, Some(&ids), &repos).is_empty(), "an unchanged rule is never re-checked");
        let new = vec![old[0].clone(), r("*", "eeeeeeee")];
        let e = rule_errors(&old, &new, Some(&ids), &repos);
        assert!(e.len() == 1 && e[0].contains("eeeeeeee") && !e[0].contains("ffffffff"), "{e:?}");
        assert!(rule_errors(&old, &[r("acme/new", "a1b2c3d4")], Some(&ids), &repos).len() == 1, "unknown repo");
        let with_new = vec!["acme/kiln".to_string(), "acme/new".to_string()];
        assert!(rule_errors(&old, &[r("acme/new", "a1b2c3d4")], Some(&ids), &with_new).is_empty(), "repo added in the same save");
        assert!(rule_errors(&old, &[r("*", "eeeeeeee")], None, &repos).is_empty(), "destinations unknown: not checked");
        assert!(rule_errors(&[], &[r("Acme/Kiln", "a1b2c3d4")], Some(&ids), &repos).is_empty(), "repo case does not matter");
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn address_policy() {
        for s in ["1.1.1.1", "8.8.8.8", "140.82.112.3", "2606:4700::1111", "2001:4860:4860::8888"] {
            assert!(allowed(ip(s), false), "{s} is public");
        }
        for s in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.7",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:0101::1",
            "64:ff9b:1::a9fe:a9fe",
            "::ffff:0:a9fe:a9fe",
            "::ffff:0:101:101",
            "2001:0:4136:e378::1",
            "100::1",
        ] {
            assert!(!allowed(ip(s), false), "{s} is internal");
        }
        // Translation prefixes are refused outright, tailnet or not.
        for s in ["64:ff9b:1::a9fe:a9fe", "64:ff9b:1::101:101", "::ffff:0:a9fe:a9fe", "2001:0:4136:e378::1", "100::1"] {
            assert!(!allowed(ip(s), true), "{s} is refused even on a tailnet");
        }
        // Just outside each private range: public.
        for s in ["172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "223.255.255.255"] {
            assert!(allowed(ip(s), false), "{s} is public");
        }
        // The embedded-IPv4 forms are still judged by their IPv4 address.
        assert!(allowed(ip("64:ff9b::101:101"), false), "NAT64 of a public address");
        assert!(allowed(ip("2001:4860::1"), false), "2001::/32 is only Teredo, not all of 2001::/16");
        // The tailnet opt-in opens exactly the tailnet ranges, nothing else private.
        assert!(allowed(ip("100.64.0.7"), true) && allowed(ip("fd7a:115c:a1e0::7"), true));
        assert!(!allowed(ip("10.0.0.1"), true) && !allowed(ip("fd12::1"), true) && !allowed(ip("127.0.0.1"), true));
        assert!(allowed(ip("::ffff:1.1.1.1"), false), "mapped public stays public");
    }

    #[test]
    fn url_rules() {
        let ok = |k, u| check_url(k, u, false).is_ok();
        assert!(ok(Kind::Slack, "https://hooks.slack.com/services/T000/B000/XXXX"));
        assert!(!ok(Kind::Slack, "https://hooks.slack.com.evil.example/services/x"));
        assert!(!ok(Kind::Slack, "http://hooks.slack.com/services/T000/B000/XXXX"), "https only");
        assert!(ok(Kind::Discord, "https://discord.com/api/webhooks/1/abc"));
        assert!(ok(Kind::Discord, "https://discordapp.com/api/webhooks/1/abc"));
        assert!(!ok(Kind::Discord, "https://discord.com/channels/1/2"));
        assert!(ok(Kind::Ntfy, "https://ntfy.sh/acme-alerts"));
        assert!(ok(Kind::Generic, "https://hooks.example.com:8443/kiln?x=1"));
        assert!(!ok(Kind::Generic, "https://user:pw@hooks.example.com/"), "no user info");
        assert!(!ok(Kind::Generic, "https://127.0.0.1/"), "literal loopback");
        assert!(!ok(Kind::Generic, "https://[::1]/"), "literal v6 loopback");
        assert!(!ok(Kind::Generic, "https://169.254.169.254/latest/meta-data/"), "metadata");
        for alt in ["https://2130706433/", "https://0x7f.1/", "https://127.1/", "https://[::ffff:7f00:1]/"] {
            assert!(!ok(Kind::Generic, alt), "alternate spelling of loopback: {alt}");
        }
        assert!(!ok(Kind::Generic, "ftp://example.com/"));
        assert!(!ok(Kind::Generic, &format!("https://example.com/{}", "a".repeat(2100))));
        assert!(check_url(Kind::Ntfy, "https://100.64.0.7/alerts", true).is_ok(), "tailnet opt-in");
        assert!(check_url(Kind::Ntfy, "https://100.64.0.7/alerts", false).is_err());
        // Under 2048 as typed, over it once percent-encoded (each space becomes %20): refused at save.
        let long = format!("https://ntfy.sh/a{}b", " ".repeat(1000));
        assert!(long.len() < 2048);
        assert_eq!(check_url(Kind::Ntfy, &long, false).unwrap_err(), "the URL is longer than 2048 characters");
    }

    fn job(repo: &str, job: &str, branch: &str) -> Event {
        Event {
            ty: "job.failed",
            class: Class::Job,
            to: vec![],
            detail: Detail::Job(JobInfo {
                repo: clean(repo),
                workflow: Some(clean("ci.yml")),
                workflow_name: Some(clean("ci")),
                job: clean(job),
                branch: Some(clean(branch)),
                event: Some(clean("push")),
                outcome: "failed".into(),
                duration_s: Some(312),
                url: Some("https://github.com/acme/kiln/actions/runs/1/job/2".into()),
                vm_id: "kiln-1-0".into(),
            }),
        }
    }

    fn body(r: &Rendered) -> serde_json::Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    #[test]
    fn cleaning_strips_controls_bidi_and_length() {
        assert_eq!(clean("a\r\nb\tc"), "a b c");
        assert_eq!(clean("x\u{202E}gnp.exe\u{2066}y\u{200F}"), "xgnp.exey");
        assert_eq!(clean("\u{7}bell\u{1b}[31m"), "bell[31m");
        assert_eq!(clean("a\u{200B}b\u{061C}c\u{FEFF}d\u{E0041}e\u{00AD}f"), "abcdef");
        let long = clean(&"é".repeat(500));
        assert_eq!(long.chars().count(), 100);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn slack_cannot_mention_or_link() {
        let e = job("acme/kiln", "<!channel> <@U123> <https://evil.example|click>", "main & co");
        let r = render(Kind::Slack, None, None, &e, "msg_1", 1, None).unwrap();
        let t = body(&r)["text"].as_str().unwrap().to_string();
        assert!(!t.contains("<!channel>") && !t.contains("<@U123>") && !t.contains("<https://evil"), "{t}");
        assert!(t.contains("&lt;!channel&gt;") && t.contains("main &amp; co"), "{t}");
        assert_eq!(body(&r)["unfurl_links"], false);
        assert_eq!(body(&r)["unfurl_media"], false);
        assert_eq!(body(&r)["mrkdwn"], false);
        // kiln's own link is the only real link
        assert!(t.contains("<https://github.com/acme/kiln/actions/runs/1/job/2|details>"), "{t}");
    }

    #[test]
    fn discord_cannot_ping_or_format() {
        let e = job("acme/kiln", "@everyone **bold** [x](https://evil.example)", "@here");
        let r = render(Kind::Discord, None, None, &e, "msg_1", 1, None).unwrap();
        let v = body(&r);
        let c = v["content"].as_str().unwrap();
        assert!(!c.contains("@everyone") && !c.contains("@here"), "{c}");
        assert!(c.contains("\\*\\*bold\\*\\*") && c.contains("\\[x\\]"), "{c}");
        assert!(c.contains("\\(https") && !c.replace("\\(https", "").contains("(https"), "{c}");
        assert_eq!(v["allowed_mentions"], serde_json::json!({ "parse": [] }));
        assert_eq!(v["username"], "kiln");
    }

    #[test]
    fn discord_escapes_angle_brackets_in_repo_text() {
        let e = job("acme/kiln", "<t:1:R> </cmd:1> <:x:1>", "main");
        let r = render(Kind::Discord, None, None, &e, "msg_1", 1, None).unwrap();
        let c = body(&r)["content"].as_str().unwrap().to_string();
        // The first line is the summary; the kiln link follows on its own line.
        let summary = c.lines().next().unwrap();
        assert!(summary.contains('<'), "{c}");
        for (i, _) in summary.match_indices('<') {
            assert_eq!(summary[..i].chars().last(), Some('\\'), "unescaped < in {summary}");
        }
    }

    #[test]
    fn chat_targets_do_not_autolink_repo_text() {
        let e = job("acme/kiln", "evil.example", "https://evil.example/login");
        let s = render(Kind::Slack, None, None, &e, "msg_1", 1, None).unwrap();
        let d = render(Kind::Discord, None, None, &e, "msg_1", 1, None).unwrap();
        let n = render(Kind::Ntfy, None, None, &e, "msg_1", 1, None).unwrap();
        let slack = body(&s)["text"].as_str().unwrap().to_string();
        let discord = body(&d)["content"].as_str().unwrap().to_string();
        let ntfy = String::from_utf8(n.body.clone()).unwrap();
        for t in [&slack, &discord, &ntfy] {
            assert!(!t.contains("https://evil") && !t.contains("evil.example"), "{t}");
            assert!(t.contains("https://github.com/acme/kiln/actions/runs/1/job/2"), "{t}");
        }
    }

    #[test]
    fn ntfy_keeps_untrusted_text_out_of_headers() {
        let e = job("acme/kiln", "evil\r\nX-Injected: 1", "main");
        let r = render(Kind::Ntfy, None, Some("tk_secret"), &e, "msg_1", 1, None).unwrap();
        for (k, v) in &r.headers {
            assert!(v.is_ascii() && !v.contains('\n') && !v.contains("evil"), "{k}: {v}");
        }
        assert!(r.headers.contains(&("Title", "kiln: job failed".into())));
        assert!(r.headers.contains(&("Authorization", "Bearer tk_secret".into())));
        assert!(String::from_utf8(r.body.clone()).unwrap().contains("evil X-Injected:\u{200B} 1"));
    }

    #[test]
    fn generic_fails_closed_without_a_valid_secret() {
        let e = job("acme/kiln", "test", "main");
        assert!(render(Kind::Generic, Some("whsec_!!notbase64"), None, &e, "msg_1", 1, None).is_err());
        assert!(render(Kind::Generic, None, None, &e, "msg_1", 1, None).is_err());
        assert!(render(Kind::Slack, None, None, &e, "msg_1", 1, None).is_ok());
    }

    #[test]
    fn generic_is_typed_and_signed() {
        let e = job("acme/kiln", "test", "main");
        let s = new_secret();
        assert!(s.starts_with("whsec_") && s.len() > 40);
        let r = render(Kind::Generic, Some(&s), None, &e, "msg_1", 1791402114, None).unwrap();
        let v = body(&r);
        assert_eq!((v["type"].as_str(), v["id"].as_str(), v["at"].as_u64()), (Some("job.failed"), Some("msg_1"), Some(1791402114)));
        assert_eq!(v["job"]["workflow"], "ci.yml");
        assert!(v["job"].get("vm_id").is_none());
        let sig = r.headers.iter().find(|(k, _)| *k == "webhook-signature").unwrap().1.clone();
        assert_eq!(Some(sig), sign(&s, "msg_1", 1791402114, &r.body));
        assert!(r.headers.contains(&("webhook-id", "msg_1".into())));
        assert!(r.headers.contains(&("webhook-timestamp", "1791402114".into())));
    }

    #[test]
    fn standard_webhooks_test_vector() {
        // From the Standard Webhooks specification's reference test vector. If this ever fails,
        // check the vector against github.com/standard-webhooks/standard-webhooks before
        // touching `sign`.
        let got = sign("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, br#"{"test": 2432232314}"#);
        assert_eq!(got.as_deref(), Some("v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="));
    }

    #[test]
    fn links_only_to_github() {
        assert!(github_link("https://github.com/acme/kiln/actions/runs/1/job/2").is_some());
        for bad in ["http://github.com/x", "https://github.com.evil.example/x", "https://github.com/x|y>", "javascript:alert(1)"] {
            assert!(github_link(bad).is_none(), "{bad}");
        }
    }

    fn dest(kind: Kind, url: &str) -> Dest {
        Dest {
            id: "a1b2c3d4".into(),
            name: "ops".into(),
            kind,
            url: url.into(),
            secret: Some(new_secret()),
            token: Some("tk_marker_9f3".into()),
            tailnet: false,
            link: false,
            events: Events::default(),
        }
    }

    #[test]
    fn store_is_private_and_redacted() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("kiln-test-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(load(&d).unwrap().len(), 0, "missing file = none");
        let x = dest(Kind::Slack, "https://hooks.slack.com/services/T000/B000/MARKERURL");
        save(&d, std::slice::from_ref(&x)).unwrap();
        assert_eq!(std::fs::metadata(d.join("notify.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&d).unwrap()[0].url, x.url);
        let shown = public(&x, &Status::default()).to_string();
        for secret in ["MARKERURL", "tk_marker_9f3", x.secret.as_deref().unwrap(), "services/T000"] {
            assert!(!shown.contains(secret), "leaked {secret}: {shown}");
        }
        assert!(shown.contains("hooks.slack.com") && shown.contains("\"ops\""));
        std::fs::write(d.join("notify.json"), "{not json").unwrap();
        assert!(load(&d).is_err());
        assert_eq!(std::fs::read_to_string(d.join("notify.json")).unwrap(), "{not json", "never rewritten");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn load_errors_never_echo_file_contents() {
        let d = std::env::temp_dir().join(format!("kiln-test-notify-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let bad_type = r#"[{"id":"a1b2c3d4","name":"x","kind":"slack","url":"https://hooks.slack.com/services/T000/B000/XXXX","tailnet":"SECRETMARK_42"}]"#;
        std::fs::write(d.join("notify.json"), bad_type).unwrap();
        let Err(e) = load(&d) else { panic!("expected an error") };
        assert!(!e.contains("SECRETMARK_42"), "leaked: {e}");
        let cut = r#"[{"id":"a1b2c3d4","name":"x","kind":"slack","url":"https://hooks.slack.com/services/T000/B000/SECRETMARK_43"}]"#;
        std::fs::write(d.join("notify.json"), &cut[..cut.find("SECRETMARK_43").unwrap() + 8]).unwrap();
        let Err(e) = load(&d) else { panic!("expected an error") };
        assert!(!e.contains("SECRETMARK_43") && !e.contains("SECRETMARK"), "leaked: {e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn partial_events_default_on() {
        let e: Events = serde_json::from_str(r#"{"job":false}"#).unwrap();
        assert_eq!(e, Events { job: false, health: true, security: true });
    }

    #[test]
    fn routing_obeys_switches_and_explicit_targets() {
        let mut x = dest(Kind::Generic, "https://hooks.example.com/k");
        let ev = |class, to: Vec<&str>| Event { ty: "test", class, detail: Detail::Test, to: to.into_iter().map(String::from).collect() };
        assert!(x.wants(&ev(Class::Job, vec![])));
        assert!(x.wants(&ev(Class::Job, vec!["ffffffff"])), "job-enabled destinations also get a failed job matching a rule");
        x.events.job = false;
        assert!(!x.wants(&ev(Class::Job, vec![])));
        assert!(x.wants(&ev(Class::Job, vec!["a1b2c3d4"])), "a rule naming it wins over the switch");
        assert!(!x.wants(&ev(Class::Direct, vec!["ffffffff"])));
        assert!(x.wants(&ev(Class::Direct, vec!["a1b2c3d4"])));
    }

    #[tokio::test]
    async fn resolver_drops_internal_answers() {
        use reqwest::dns::Resolve;
        let g = Guard { tailnet: false };
        let r = g.resolve("localhost".parse().unwrap()).await;
        assert!(r.err().unwrap().to_string().contains("internal"), "localhost only resolves inward");
    }

    #[test]
    fn retry_classification() {
        assert!(matches!(classify(200, None), Outcome::Ok));
        assert!(matches!(classify(204, None), Outcome::Ok));
        assert!(matches!(classify(429, Some("12")), Outcome::Retry(_, Some(d)) if d == Duration::from_secs(12)));
        assert!(matches!(classify(429, Some("99999")), Outcome::Retry(_, Some(d)) if d == Duration::from_secs(300)), "capped");
        assert!(matches!(classify(503, None), Outcome::Retry(_, None)));
        assert!(matches!(classify(408, None), Outcome::Retry(_, None)));
        assert!(matches!(classify(429, Some("0")), Outcome::Retry(_, Some(d)) if d == Duration::from_secs(1)), "floored");
        assert!(matches!(classify(404, None), Outcome::Permanent(_)));
        assert!(matches!(classify(302, None), Outcome::Permanent(_)), "redirects are never followed");
    }

    type Seen = std::sync::Arc<Mutex<Vec<(axum::http::HeaderMap, Vec<u8>)>>>;

    /// A local receiver that records requests and answers with `status`.
    async fn receiver(status: u16) -> (String, Seen) {
        use axum::{Router, routing::post};
        let got: Seen = Default::default();
        let g = got.clone();
        let app = Router::new().route(
            "/hook",
            post(move |h: axum::http::HeaderMap, b: axum::body::Bytes| {
                let g = g.clone();
                async move {
                    g.lock().unwrap().push((h, b.to_vec()));
                    let mut r = axum::response::Response::new(axum::body::Body::from("x".repeat(10_000)));
                    *r.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
                    r.headers_mut().insert("location", "http://127.0.0.1:1/elsewhere".parse().unwrap());
                    r
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, got)
    }

    #[tokio::test]
    async fn delivers_signed_and_never_follows_redirects() {
        let (url, got) = receiver(204).await;
        let mut d = dest(Kind::Generic, &url);
        let c = client(&d, true);
        assert!(matches!(send_once(&c, &d, &job("acme/kiln", "t", "main"), "msg_a", true).await, Outcome::Ok));
        let (h, b) = got.lock().unwrap()[0].clone();
        let (id, ts) = (h["webhook-id"].to_str().unwrap(), h["webhook-timestamp"].to_str().unwrap().parse().unwrap());
        assert_eq!(h["webhook-signature"].to_str().unwrap(), sign(d.secret.as_deref().unwrap(), id, ts, &b).unwrap());
        assert!(h["user-agent"].to_str().unwrap().starts_with("kiln/"));
        let (url, got) = receiver(302).await;
        d.url = url;
        assert!(matches!(send_once(&client(&d, true), &d, &job("acme/kiln", "t", "main"), "msg_a", true).await, Outcome::Permanent(_)));
        assert_eq!(got.lock().unwrap().len(), 1, "the redirect target was not requested");
    }

    #[tokio::test]
    async fn retries_keep_the_webhook_id() {
        let (url, got) = receiver(503).await;
        let d = dest(Kind::Generic, &url);
        let c = client(&d, true);
        let e = job("acme/kiln", "t", "main");
        let id = new_msg_id();
        for _ in 0..2 {
            assert!(matches!(send_once(&c, &d, &e, &id, true).await, Outcome::Retry(..)));
        }
        let got = got.lock().unwrap();
        let ids: Vec<&str> = got.iter().map(|(h, _)| h["webhook-id"].to_str().unwrap()).collect();
        assert_eq!(ids, vec![id.as_str(), id.as_str()], "a retry is the same message to the receiver");
        assert_ne!(new_msg_id(), id);
    }

    #[tokio::test]
    async fn bad_secret_is_permanent_and_sends_nothing() {
        let (url, got) = receiver(204).await;
        let mut d = dest(Kind::Generic, &url);
        d.secret = Some("whsec_!!bad".into());
        assert!(matches!(send_once(&client(&d, true), &d, &job("acme/kiln", "t", "main"), "msg_a", true).await, Outcome::Permanent(_)));
        assert!(got.lock().unwrap().is_empty(), "nothing is sent unsigned");
    }

    #[tokio::test]
    async fn refuses_literal_internal_address_before_connecting() {
        let d = dest(Kind::Generic, "https://169.254.169.254/latest");
        match send_once(&client(&d, false), &d, &job("acme/kiln", "t", "main"), "msg_a", false).await {
            Outcome::Permanent(m) => assert!(m.contains("internal"), "{m}"),
            _ => panic!("must be refused"),
        }
    }

    #[tokio::test]
    async fn queue_drops_oldest_and_counts() {
        let app = crate::App::for_tests();
        let d = dest(Kind::Generic, "https://hooks.example.com/k");
        app.notify.dests.lock().unwrap().push(d.clone());
        spawn_worker(&app, d.clone());
        let q = app.notify.queues.lock().unwrap()[&d.id].clone();
        for _ in 0..300 {
            emit(&app, Event { ty: "test", class: Class::Direct, detail: Detail::Test, to: vec![d.id.clone()] });
        }
        assert_eq!(q.q.lock().unwrap().len(), 256);
        assert_eq!(app.notify.status.lock().unwrap()[&d.id].dropped, 44);
    }

    #[tokio::test]
    async fn name_resolving_inward_is_refused_not_retried() {
        let d = dest(Kind::Generic, "https://localhost/hook");
        match send_once(&client(&d, false), &d, &job("acme/kiln", "t", "main"), "msg_a", false).await {
            Outcome::Permanent(m) => assert!(m.contains("internal"), "{m}"),
            o => panic!("must be refused, got {o:?}"),
        }
    }

    #[test]
    fn resolver_keeps_only_allowed_answers() {
        let a = |s: &str| SocketAddr::new(ip(s), 0);
        let all = ["93.184.215.14", "127.0.0.1", "10.0.0.1", "2606:4700::1111", "100.64.0.7"].map(a);
        assert_eq!(keep_allowed(all.into_iter(), false), vec![a("93.184.215.14"), a("2606:4700::1111")]);
        assert!(keep_allowed(all.into_iter(), true).contains(&a("100.64.0.7")));
    }

    #[tokio::test]
    async fn flush_waits_for_in_flight_sends() {
        let app = crate::App::for_tests();
        let q = Arc::new(Queue::default());
        app.notify.queues.lock().unwrap().insert("x".into(), q.clone());
        let t = std::time::Instant::now();
        flush(&app).await;
        assert!(t.elapsed() < Duration::from_millis(200), "idle returns at once");
        q.busy.store(true, std::sync::atomic::Ordering::SeqCst);
        let t = std::time::Instant::now();
        flush(&app).await;
        assert!(t.elapsed() >= Duration::from_millis(1900), "busy waits for the cap");
    }

    // Handlers are called directly (no router): a handler error maps to its status code.
    fn out(r: ApiResult<Json<Value>>) -> (u16, Value) {
        match r {
            Ok(Json(v)) => (200, v),
            Err((c, m)) => (c.as_u16(), Value::String(m)),
        }
    }
    fn noted(r: Noted) -> (u16, Value) {
        out(r.map(|(_, j)| j))
    }
    fn me() -> Extension<Actor> {
        Extension(Actor("me@example.com".into()))
    }
    fn dbody(v: Value) -> Json<DestBody> {
        Json(serde_json::from_value(v).unwrap())
    }
    async fn add(app: &Arc<crate::App>, v: Value) -> (u16, Value) {
        noted(create(State(app.clone()), me(), dbody(v)).await)
    }
    fn test_app() -> Arc<crate::App> {
        let app = crate::App::for_tests();
        let _ = std::fs::create_dir_all(&app.data);
        app
    }

    #[tokio::test]
    async fn api_never_returns_secrets() {
        let app = test_app();
        let url = "https://hooks.example.com/kiln/MARKER_URL_7c1";
        let (st, created) = add(&app, json!({ "name": "ops", "kind": "generic", "url": url })).await;
        assert_eq!(st, 200, "{created}");
        let secret = created["secret"].as_str().unwrap().to_string();
        let id = created["dest"]["id"].as_str().unwrap().to_string();
        let (_, list) = out(Ok(list(State(app.clone())).await));
        let state = state_json(&app).to_string();
        for blob in [list.to_string(), state] {
            assert!(!blob.contains("MARKER_URL_7c1") && !blob.contains(&secret), "{blob}");
        }
        let (st, edited) =
            noted(update(State(app.clone()), me(), UrlPath(id.clone()), dbody(json!({ "name": "ops2", "kind": "generic" }))).await);
        assert_eq!(st, 200, "{edited}");
        assert_eq!(load(&app.data).unwrap()[0].url, url, "an omitted URL keeps the stored one");
        let (_, rot) = noted(rotate(State(app.clone()), me(), UrlPath(id)).await);
        assert_ne!(rot["secret"].as_str().unwrap(), secret);
        let (st, msg) = add(&app, json!({ "name": "bad", "kind": "generic", "url": "https://10.0.0.1/x" })).await;
        assert_eq!(st, 400, "{msg}");
        assert!(!msg.to_string().contains("10.0.0.1/x"), "errors never echo the URL: {msg}");
    }

    #[tokio::test]
    async fn no_secret_reaches_config_notes_state_or_list() {
        let app = test_app();
        let note = |r: Noted| r.map(|(Extension(n), Json(v))| (n.0, v)).unwrap();
        let mut notes = vec![];
        let (n, g) = note(
            create(
                State(app.clone()),
                me(),
                dbody(json!({ "name": "g", "kind": "generic", "url": "https://hooks.example.com/MARKER_URL_g1" })),
            )
            .await,
        );
        notes.push(n);
        let (gid, mut secrets) = (g["dest"]["id"].as_str().unwrap().to_string(), vec![g["secret"].as_str().unwrap().to_string()]);
        let (n, t) = note(
            create(
                State(app.clone()),
                me(),
                dbody(json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/MARKER_URL_n1", "token": "tk_MARKER_TOKEN_1" })),
            )
            .await,
        );
        notes.push(n);
        let nid = t["dest"]["id"].as_str().unwrap().to_string();
        let mut c = app.cfg();
        c.notify_rules = vec![Rule { repo: "*".into(), workflow: "*".into(), outcome: "any".into(), to: vec![gid.clone(), nid.clone()] }];
        app.save_cfg(c).unwrap();
        notes.push(
            note(
                update(
                    State(app.clone()),
                    me(),
                    UrlPath(nid.clone()),
                    dbody(json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/MARKER_URL_n2", "token": "tk_MARKER_TOKEN_2" })),
                )
                .await,
            )
            .0,
        );
        notes.push(
            note(
                update(
                    State(app.clone()),
                    me(),
                    UrlPath(gid.clone()),
                    dbody(json!({ "name": "g2", "kind": "generic", "url": "https://hooks.example.com/MARKER_URL_g2" })),
                )
                .await,
            )
            .0,
        );
        let (n, r) = note(rotate(State(app.clone()), me(), UrlPath(gid.clone())).await);
        notes.push(n);
        secrets.push(r["secret"].as_str().unwrap().to_string());
        let (_, listed) = out(Ok(list(State(app.clone())).await));
        let state = state_json(&app).to_string();
        notes.push(note(remove(State(app.clone()), me(), UrlPath(nid)).await).0);
        let config = std::fs::read_to_string(app.data.join("config.json")).unwrap();
        assert!(config.contains(&gid), "config.json holds the rule: {config}");
        let mut markers = vec!["MARKER_URL".to_string(), "MARKER_TOKEN".to_string()];
        markers.extend(secrets);
        for (what, blob) in [("config.json", config), ("list", listed.to_string()), ("state", state), ("notes", notes.join("\n"))] {
            for m in &markers {
                assert!(!blob.contains(m.as_str()), "{what} leaked {m}: {blob}");
            }
        }
    }

    #[tokio::test]
    async fn announcements_reach_every_destination_and_secrets_show_once() {
        let app = test_app();
        let (_, a) =
            add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a", "events": { "security": false } })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let q = app.notify.queues.lock().unwrap()[&id].clone();
        let (st, u) = noted(
            update(
                State(app.clone()),
                me(),
                UrlPath(id.clone()),
                dbody(json!({ "name": "a", "kind": "generic", "url": "https://hooks.example.com/x" })),
            )
            .await,
        );
        assert_eq!(st, 200, "{u}");
        assert!(u["secret"].as_str().unwrap().starts_with("whsec_"), "{u}");
        assert!(q.q.lock().unwrap().iter().any(|e| e.ty == "security.changed"), "security switch off still hears it");
        let (_, u) = noted(update(State(app.clone()), me(), UrlPath(id), dbody(json!({ "name": "a2", "kind": "generic" }))).await);
        assert!(u["secret"].is_null(), "{u}");
        let (st, _) = add(&app, json!({ "name": "ops\u{202E}x", "kind": "ntfy", "url": "https://ntfy.sh/acme-b" })).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn change_announcements_name_the_fields() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let q = app.notify.queues.lock().unwrap()[&id].clone();
        let last = |q: &Queue| match &q.q.lock().unwrap().back().unwrap().detail {
            Detail::Security(s) => s.action.clone(),
            _ => panic!(),
        };
        let r = update(
            State(app.clone()),
            me(),
            UrlPath(id.clone()),
            dbody(json!({ "name": "a", "kind": "ntfy", "events": { "job": true, "health": true, "security": false } })),
        )
        .await;
        let Ok((Extension(note), _)) = r else { panic!() };
        let what = last(&q);
        assert!(what.ends_with(": events.security"), "{what}");
        assert_eq!(note.0, what, "the audit note says the same");
        let q = app.notify.queues.lock().unwrap()[&id].clone();
        let r = update(
            State(app.clone()),
            me(),
            UrlPath(id.clone()),
            dbody(json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-SECRETPATH" })),
        )
        .await;
        assert!(r.is_ok());
        let what = last(&q);
        assert!(what.contains(": url") && !what.contains("SECRETPATH") && !what.contains("acme-"), "{what}");
    }

    #[tokio::test]
    async fn removed_destination_gets_announcement_then_stops() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let q = app.notify.queues.lock().unwrap()[&id].clone();
        let (st, _) = noted(remove(State(app.clone()), me(), UrlPath(id)).await);
        assert_eq!(st, 200);
        let queued: Vec<&'static str> = q.q.lock().unwrap().iter().map(|e| e.ty).collect();
        assert!(queued.contains(&"security.changed"), "the removed destination hears about its removal: {queued:?}");
        assert!(q.retired.load(std::sync::atomic::Ordering::SeqCst));
        assert!(app.notify.dests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_destination_prunes_rules() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let mut c = app.cfg();
        c.notify_rules = vec![Rule { repo: "*".into(), workflow: "release.yml".into(), outcome: "any".into(), to: vec![id.clone()] }];
        app.save_cfg(c).unwrap();
        noted(remove(State(app.clone()), me(), UrlPath(id)).await);
        assert!(app.cfg().notify_rules.is_empty(), "a rule left with no destination is dropped");
    }

    #[tokio::test]
    async fn test_sends_are_rate_limited() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        assert_eq!(out(test(State(app.clone()), UrlPath(id.clone())).await).0, 200);
        assert_eq!(out(test(State(app.clone()), UrlPath(id)).await).0, 429);
    }

    // --- PR #38 review fixes

    fn stored(app: &crate::App, id: &str) -> Dest {
        app.notify.dests.lock().unwrap().iter().find(|d| d.id == id).unwrap().clone()
    }

    async fn put(app: &Arc<crate::App>, id: &str, v: Value) -> (u16, Value) {
        noted(update(State(app.clone()), me(), UrlPath(id.to_string()), dbody(v)).await)
    }

    #[tokio::test]
    async fn origin_change_drops_the_ntfy_token() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/acme", "token": "tk_old" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let (st, r) = put(&app, &id, json!({ "name": "n", "kind": "ntfy", "url": "https://attacker.example/x" })).await;
        assert_eq!(st, 200, "{r}");
        let d = stored(&app, &id);
        assert_eq!(d.token, None, "a new host never inherits the token");
        assert_eq!(load(&app.data).unwrap()[0].token, None);
        let e = job("acme/kiln", "t", "main");
        let h = render(d.kind, d.secret.as_deref(), d.token.as_deref(), &e, "msg_1", 1, None).unwrap().headers;
        assert!(!h.iter().any(|(k, _)| *k == "Authorization"), "{:?}", h);
    }

    #[tokio::test]
    async fn origin_change_with_a_new_token_keeps_it() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/acme", "token": "tk_old" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let (st, _) = put(&app, &id, json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.example.com/x", "token": "tk_new" })).await;
        assert_eq!(st, 200);
        assert_eq!(stored(&app, &id).token.as_deref(), Some("tk_new"));
    }

    #[tokio::test]
    async fn generic_origin_change_issues_a_new_secret() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "g", "kind": "generic", "url": "https://hooks.example.com/a" })).await;
        let (id, old) = (a["dest"]["id"].as_str().unwrap().to_string(), a["secret"].as_str().unwrap().to_string());
        for url in ["https://other.example.com/a", "https://other.example.com:8443/a"] {
            let before = stored(&app, &id).secret.unwrap();
            let (st, r) = put(&app, &id, json!({ "name": "g", "kind": "generic", "url": url })).await;
            assert_eq!(st, 200, "{r}");
            let now = stored(&app, &id).secret.unwrap();
            assert!(now != before && now != old, "{url}: the secret is replaced");
            assert_eq!(r["secret"].as_str(), Some(now.as_str()), "{url}: and returned once");
        }
    }

    #[tokio::test]
    async fn same_origin_path_change_keeps_secret_and_token() {
        let app = test_app();
        let (_, g) = add(&app, json!({ "name": "g", "kind": "generic", "url": "https://hooks.example.com/a" })).await;
        let gid = g["dest"]["id"].as_str().unwrap().to_string();
        let secret = stored(&app, &gid).secret;
        let (st, r) = put(&app, &gid, json!({ "name": "g", "kind": "generic", "url": "https://hooks.example.com/b?x=1" })).await;
        assert_eq!(st, 200);
        assert!(r["secret"].is_null(), "{r}");
        assert_eq!(stored(&app, &gid).secret, secret);
        let (_, n) = add(&app, json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/acme", "token": "tk_old" })).await;
        let nid = n["dest"]["id"].as_str().unwrap().to_string();
        let (st, _) = put(&app, &nid, json!({ "name": "n", "kind": "ntfy", "url": "https://ntfy.sh/other" })).await;
        assert_eq!(st, 200);
        assert_eq!(stored(&app, &nid).token.as_deref(), Some("tk_old"));
    }

    #[test]
    fn site_local_and_documentation_v6_are_refused() {
        for s in ["fec0::1", "feff::1", "3fff::1", "3fff:fff:ffff::1"] {
            assert!(!allowed(ip(s), false), "{s}");
            assert!(!allowed(ip(s), true), "{s} even on a tailnet");
        }
        for s in ["3ffe::1", "3fff:1000::1"] {
            assert!(allowed(ip(s), false), "{s} is just outside 3fff::/20");
        }
    }

    #[tokio::test]
    async fn stored_url_is_rechecked_on_send() {
        let d = dest(Kind::Slack, "https://evil.example/x");
        match send_once(&client(&d, false), &d, &job("acme/kiln", "t", "main"), "msg_a", false).await {
            Outcome::Permanent(m) => assert_eq!(m, "refused: stored URL no longer allowed"),
            o => panic!("must be refused, got {o:?}"),
        }
    }

    #[tokio::test]
    async fn production_client_refuses_plain_http() {
        let (url, got) = receiver(204).await;
        let d = dest(Kind::Generic, &url);
        assert!(matches!(send_once(&client(&d, false), &d, &job("acme/kiln", "t", "main"), "msg_a", false).await, Outcome::Permanent(_)));
        assert!(got.lock().unwrap().is_empty(), "nothing reached the receiver");
    }

    fn failing_with(st: Status) -> bool {
        let app = crate::App::for_tests();
        let d = dest(Kind::Ntfy, "https://ntfy.sh/acme-a");
        app.notify.dests.lock().unwrap().push(d.clone());
        app.notify.status.lock().unwrap().insert(d.id.clone(), st);
        !failing(&app).is_empty()
    }

    #[test]
    fn failing_means_failures_kept_coming_for_an_hour() {
        let t = crate::now() - 3600;
        let one = Status { last_error: Some((t, "HTTP 503".into())), failing_since: Some(t), ..Default::default() };
        assert!(!failing_with(one), "one failure an hour ago is not an hour of failing");
        let hour = Status { last_error: Some((t + 3600, "HTTP 503".into())), failing_since: Some(t), ..Default::default() };
        assert!(failing_with(hour));
        let perm = Status { last_error: Some((t, "HTTP 404".into())), failing_since: Some(t), permanent_streak: 3, ..Default::default() };
        assert!(failing_with(perm));
    }

    #[tokio::test]
    async fn update_rechecks_the_stored_url() {
        let app = test_app();
        let (st, a) = add(&app, json!({ "name": "t", "kind": "ntfy", "url": "https://100.64.0.7/x", "tailnet": true })).await;
        assert_eq!(st, 200, "{a}");
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        assert_eq!(put(&app, &id, json!({ "name": "t", "kind": "ntfy", "tailnet": false })).await.0, 400);
        let (_, g) = add(&app, json!({ "name": "g", "kind": "generic", "url": "https://hooks.example.com/x" })).await;
        let gid = g["dest"]["id"].as_str().unwrap().to_string();
        assert_eq!(put(&app, &gid, json!({ "name": "g", "kind": "slack", "url": "https://hooks.example.com/x" })).await.0, 400);
    }

    fn rule_to(id: &str) -> Rule {
        Rule { repo: "*".into(), workflow: "*".into(), outcome: "any".into(), to: vec![id.into()] }
    }

    #[tokio::test]
    async fn remove_saves_rules_first_and_changes_nothing_if_that_fails() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let mut c = app.cfg();
        c.notify_rules = vec![rule_to(&id)];
        app.save_cfg(c).unwrap();
        std::fs::remove_file(app.data.join("config.json")).unwrap();
        std::fs::create_dir(app.data.join("config.json")).unwrap(); // the config save now fails
        let q = app.notify.queues.lock().unwrap()[&id].clone();
        let queued = q.q.lock().unwrap().len();
        let (st, _) = noted(remove(State(app.clone()), me(), UrlPath(id.clone())).await);
        assert_eq!(st, 500);
        assert_eq!(app.notify.dests.lock().unwrap().len(), 1, "still there");
        assert_eq!(load(&app.data).unwrap().len(), 1, "still stored");
        assert_eq!(app.cfg().notify_rules.len(), 1);
        assert!(!q.retired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(q.q.lock().unwrap().len(), queued, "nothing announced");
    }

    #[tokio::test]
    async fn remove_reports_rules_saved_but_destination_kept() {
        let app = test_app();
        let (_, a) = add(&app, json!({ "name": "a", "kind": "ntfy", "url": "https://ntfy.sh/acme-a" })).await;
        let id = a["dest"]["id"].as_str().unwrap().to_string();
        let mut c = app.cfg();
        c.notify_rules = vec![rule_to(&id)];
        app.save_cfg(c).unwrap();
        std::fs::remove_file(app.data.join("notify.json")).unwrap();
        std::fs::create_dir(app.data.join("notify.json")).unwrap(); // the notify.json save now fails
        let (st, m) = noted(remove(State(app.clone()), me(), UrlPath(id)).await);
        assert_eq!(st, 500);
        assert!(m.as_str().unwrap().starts_with("rules updated, but the destination could not be removed: "), "{m}");
        assert!(app.cfg().notify_rules.is_empty(), "the rules were saved");
        assert_eq!(app.notify.dests.lock().unwrap().len(), 1);
    }
}
