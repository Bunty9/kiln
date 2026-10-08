//! Outbound webhook notifications: generic signed JSON (Standard Webhooks), Slack, Discord
//! and ntfy. Nothing here may let a destination reach inward (SSRF), leak its secret, or let
//! text from a repo format, mention or inject into the target. See
//! docs/superpowers/specs/2026-10-08-webhook-notifications-design.md.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
}
