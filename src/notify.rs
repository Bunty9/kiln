//! Outbound webhook notifications: generic signed JSON (Standard Webhooks), Slack, Discord
//! and ntfy. Nothing here may let a destination reach inward (SSRF), leak its secret, or let
//! text from a repo format, mention or inject into the target. See
//! docs/superpowers/specs/2026-10-08-webhook-notifications-design.md.

#![allow(dead_code)]

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
/// (100.64.0.0/10 and fd7a:115c:a1e0::/48). The same private ranges job egress filtering drops.
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
            if s[0] & 0xfe00 == 0xfc00 {
                return tailnet && s[..3] == [0xfd7a, 0x115c, 0xa1e0];
            }
            !(s[0] & 0xffc0 == 0xfe80 || s[0] & 0xff00 == 0xff00 || s[..2] == [0x2001, 0x0db8])
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

#[cfg(test)]
mod tests {
    use super::*;

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
        ] {
            assert!(!allowed(ip(s), false), "{s} is internal");
        }
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
        assert!(!ok(Kind::Generic, "ftp://example.com/"));
        assert!(!ok(Kind::Generic, &format!("https://example.com/{}", "a".repeat(2100))));
        assert!(check_url(Kind::Ntfy, "https://100.64.0.7/alerts", true).is_ok(), "tailnet opt-in");
        assert!(check_url(Kind::Ntfy, "https://100.64.0.7/alerts", false).is_err());
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
}
