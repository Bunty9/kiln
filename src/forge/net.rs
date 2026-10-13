//! SSRF-safe HTTP for everything that dials a URL an operator typed: notify destinations and
//! forge APIs. Redirects are never followed, timeouts are set, response size is capped, and the
//! address check runs inside the resolver so the connection uses exactly the addresses judged
//! (no gap for a DNS rebind). Extracted from `notify`, which keeps its own rules on top.

use super::Network;
use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Which addresses a client may connect to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Public unicast only, https only.
    Public,
    /// `Public` plus the tailnet ranges (notify's "on my tailnet").
    Tailnet,
    /// A forge on a LAN, ULA or tailnet: RFC 1918, ULA, CGNAT and public addresses, http allowed.
    /// Loopback, the host's own addresses, link-local, multicast and the rest stay refused.
    Internal,
}

impl From<Network> for Mode {
    fn from(n: Network) -> Self {
        match n {
            Network::Public => Self::Public,
            Network::Internal => Self::Internal,
        }
    }
}

impl Mode {
    pub fn public(tailnet: bool) -> Self {
        if tailnet { Self::Tailnet } else { Self::Public }
    }

    /// May a client in this mode connect to `ip`? `own` are the host's own addresses; they and
    /// the cloud/tailscale service addresses are refused in every mode.
    pub fn permits(self, ip: IpAddr, own: &[IpAddr]) -> bool {
        let inner = match ip {
            IpAddr::V6(v6) => embedded_v4(v6).map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        if own.contains(&ip) || own.contains(&inner) || service_addr(inner) {
            return false;
        }
        match self {
            Self::Public => allowed(inner, false),
            Self::Tailnet => allowed(inner, true),
            Self::Internal => match inner {
                IpAddr::V4(v4) => {
                    let [a, b, ..] = v4.octets();
                    a == 10
                        || (a == 172 && b & 0xf0 == 16)
                        || (a == 192 && b == 168)
                        || (a == 100 && b & 0xc0 == 64)
                        || allowed(inner, false)
                }
                IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00 || allowed(inner, false),
            },
        }
    }

    fn https_only(self) -> bool {
        self != Self::Internal
    }
}

/// Host-local services that sit on routable-looking addresses: tailscaled (100.100.100.100,
/// fd7a:115c:a1e0::53), Alibaba metadata (100.100.100.200), Azure wireserver (168.63.129.16)
/// and AWS IPv6 metadata (fd00:ec2::/32). Link-local metadata (169.254/16) is refused by `allowed`.
fn service_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(v4.octets(), [100, 100, 100, 100 | 200] | [168, 63, 129, 16]),
        IpAddr::V6(v6) => v6 == Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53) || v6.segments()[..2] == [0xfd00, 0x0ec2],
    }
}

/// The addresses of this host's own interfaces.
pub fn own_addrs() -> std::io::Result<Vec<IpAddr>> {
    let mut out = vec![];
    // SAFETY: getifaddrs fills a list we only read until freeifaddrs; each sockaddr is cast
    // to the struct its family names.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut p = head;
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be((*(a as *const libc::sockaddr_in)).sin_addr.s_addr)))),
                    libc::AF_INET6 => out.push(IpAddr::V6(Ipv6Addr::from((*(a as *const libc::sockaddr_in6)).sin6_addr.s6_addr))),
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    Ok(out)
}

/// Only the addresses `mode` permits.
pub fn keep(addrs: impl Iterator<Item = SocketAddr>, mode: Mode, own: &[IpAddr]) -> Vec<SocketAddr> {
    addrs.filter(|a| mode.permits(a.ip(), own)).collect()
}

/// DNS for guarded requests: system resolution, then only addresses `mode` permits. The
/// connection uses exactly these.
pub struct Guard(pub Mode);

impl reqwest::dns::Resolve for Guard {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let mode = self.0;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let own = own_addrs()?;
            let addrs = keep(tokio::net::lookup_host((host.as_str(), 0)).await?, mode, &own);
            if addrs.is_empty() {
                return Err(format!("{host} resolves only to internal addresses").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// A client with no address guard: no redirects, no proxy, 20 s timeout. For tests and for
/// callers that add their own guard; `client` is the safe one.
pub fn base() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(concat!("kiln/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(20))
}

/// `base()` plus the resolver guard (and https only unless `Internal`).
pub fn builder(mode: Mode) -> reqwest::ClientBuilder {
    base().https_only(mode.https_only()).dns_resolver(Arc::new(Guard(mode)))
}

pub fn client(mode: Mode) -> reqwest::Client {
    builder(mode).build().expect("forge http client")
}

/// The one way to send a request on a `client(mode)`: reqwest skips the resolver for an IP-literal
/// host, so the literal is judged here on every call (not just when the URL was saved).
pub async fn send(c: &reqwest::Client, mode: Mode, rb: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let req = rb.build()?;
    if let Some(ip) = literal_ip(req.url())
        && !mode.permits(ip, &own_addrs()?)
    {
        bail!("{ip} is an internal address");
    }
    Ok(c.execute(req).await?)
}

/// The body of `r`, refused past `max` bytes.
pub async fn read_capped(r: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let (body, cut) = read_prefix(r, max).await?;
    if cut {
        bail!("response larger than {max} bytes");
    }
    Ok(body)
}

/// The first `max` bytes of `r`, and whether there was more.
pub async fn read_prefix(mut r: reqwest::Response, max: usize) -> Result<(Vec<u8>, bool)> {
    let mut body = vec![];
    while let Some(c) = r.chunk().await? {
        if body.len() + c.len() > max {
            body.extend_from_slice(&c[..max - body.len()]);
            return Ok((body, true));
        }
        body.extend_from_slice(&c);
    }
    Ok((body, false))
}

/// A forge `url` before it is stored, dialled or templated into guest TOML or `.runner` JSON:
/// ASCII, no quote, backslash, whitespace/control or userinfo, a host, https (http only on
/// `internal`), and an IP literal the mode permits (so loopback and host-own are refused).
pub fn check_forge_url(url: &str, network: Network) -> Result<reqwest::Url> {
    if !url.is_ascii() || url.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '\\')) {
        bail!("forge url must be plain ASCII without quotes, backslashes or whitespace");
    }
    let u = reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("forge url: {e}"))?;
    if !u.username().is_empty() || u.password().is_some() {
        bail!("forge url must not contain a user name or password");
    }
    match (u.scheme(), network) {
        ("https", _) | ("http", Network::Internal) => {}
        ("http", Network::Public) => bail!("forge url must be https (or set network: internal for a private forge)"),
        _ => bail!("forge url must start with http:// or https://"),
    }
    if u.host_str().is_none() {
        bail!("forge url has no host");
    }
    // The stored string, not this Url, is what later code templates into guest config, so it must
    // be exactly what the parser would write: no 0x7f.1 / 2130706433 / %31%32%37 hosts, no
    // uppercase, no default port, no dot segments, where another parser could read another host.
    if u.as_str().trim_end_matches('/') != url.trim_end_matches('/') {
        bail!("forge url must be written in canonical form: {}", u.as_str().trim_end_matches('/'));
    }
    if let Some(ip) = literal_ip(&u)
        && !Mode::from(network).permits(ip, &own_addrs()?)
    {
        bail!(
            "forge url {ip} is not reachable by design: loopback, host-own, link-local and other non-routable addresses are refused (bind the forge to a non-loopback address)"
        );
    }
    Ok(u)
}

/// Is `link` on the same origin as `base`? Returned URLs (`web_url`, `html_url`, `Link`) are used
/// only after this, and are never fetched.
pub fn same_origin(base: &str, link: &str) -> bool {
    match (reqwest::Url::parse(base), reqwest::Url::parse(link)) {
        (Ok(b), Ok(l)) => b.origin().is_tuple() && b.origin() == l.origin(),
        _ => false,
    }
}

/// Text that can sit in a chat link or HTML attribute without breaking out of it.
pub fn link_safe(url: &str) -> bool {
    url.len() <= 300 && !url.contains(['|', '>', '<', ' ', '"', '\'', '\n'])
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
    // ISATAP: any /64 prefix, interface id 0:5efe:a.b.c.d (or 200:5efe with the u/l bit).
    if s[4] & 0xfdff == 0 && s[5] == 0x5efe {
        return v4(s[6], s[7]);
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
    // `Url::host()` is the host exactly as the parser (and so reqwest/hyper, which get this same
    // Url) will dial it. The parser has already turned every IPv4 spelling (decimal, hex, octal,
    // short, percent-encoded, trailing dot) into `Ipv4`, so a `Domain` is a real name; the parse
    // is belt and braces.
    match u.host()? {
        url::Host::Ipv4(v4) => Some(v4.into()),
        url::Host::Ipv6(v6) => Some(v6.into()),
        url::Host::Domain(d) => d.trim_end_matches('.').parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn internal_allows_private_refuses_inward() {
        let own = [ip("192.168.1.5"), ip("fd00::5")];
        for ok in ["10.1.2.3", "172.16.0.9", "192.168.1.9", "100.64.0.7", "fd12::1", "93.184.215.14", "::ffff:10.0.0.1"] {
            assert!(Mode::Internal.permits(ip(ok), &own), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "100.100.100.100",
            "fd7a:115c:a1e0::53",
            "::1",
            "0.0.0.0",
            "169.254.169.254",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "64:ff9b:1::1",
            "192.168.1.5",
            "fd00::5",
            "::ffff:192.168.1.5",
            "::ffff:127.0.0.1",
        ] {
            assert!(!Mode::Internal.permits(ip(bad), &own), "{bad}");
        }
    }

    #[test]
    fn public_refuses_private() {
        for bad in ["10.0.0.1", "192.168.1.9", "fd12::1", "100.64.0.7", "127.0.0.1"] {
            assert!(!Mode::Public.permits(ip(bad), &[]), "{bad}");
        }
        assert!(Mode::Tailnet.permits(ip("100.64.0.7"), &[]));
    }

    #[test]
    fn host_own_addresses_include_loopback() {
        assert!(own_addrs().unwrap().contains(&ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn resolver_refuses_loopback_in_every_mode() {
        for m in [Mode::Public, Mode::Tailnet, Mode::Internal] {
            let r = Guard(m).resolve("localhost".parse().unwrap()).await;
            assert!(r.err().unwrap().to_string().contains("internal"), "{m:?}");
        }
    }

    #[tokio::test]
    async fn guarded_client_refuses_loopback_and_http_on_public() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(client(Mode::Public).get(format!("https://localhost:{port}/")).send().await.is_err());
        assert!(client(Mode::Public).get(format!("http://localhost:{port}/")).send().await.is_err(), "http on public");
        assert!(client(Mode::Internal).get(format!("http://localhost:{port}/")).send().await.is_err(), "loopback on internal");
    }

    #[tokio::test]
    async fn send_refuses_ip_literals_the_resolver_never_sees() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        for (m, scheme) in [(Mode::Public, "https"), (Mode::Tailnet, "https"), (Mode::Internal, "http")] {
            let c = client(m);
            for host in ["127.0.0.1", "[::1]", "169.254.169.254"] {
                let e = send(&c, m, c.get(format!("{scheme}://{host}:{port}/"))).await.unwrap_err();
                assert!(e.to_string().contains("internal address"), "{m:?} {host}: {e}");
            }
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0; 1024];
            let _ = s.read(&mut b).await;
            s.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        // `base()` has no address guard, so the loopback test server is reachable.
        let r = base().build().unwrap().get(format!("http://127.0.0.1:{port}/")).send().await.unwrap();
        assert_eq!(r.status(), 302);
    }

    #[test]
    fn forge_url_hygiene() {
        use Network::*;
        assert!(check_forge_url("https://gitea.example.com", Public).is_ok());
        assert!(check_forge_url("http://10.1.2.3:3000", Internal).is_ok());
        for (bad, n) in [
            ("http://gitea.example.com", Public),
            ("ftp://gitea.example.com", Internal),
            ("https://u:p@gitea.example.com", Public),
            ("https://git\"ea.example.com", Public),
            ("https://gitea.example.com\\x", Public),
            ("https://gitea.example.com/a b", Public),
            ("https://gité.example.com", Public),
            ("https://gitea.example.com/\n", Public),
            ("http://127.0.0.1:3000", Internal),
            ("http://[::1]:3000", Internal),
            ("http://169.254.169.254", Internal),
            ("https://127.0.0.1", Public),
            ("https://10.0.0.1", Public),
        ] {
            assert!(check_forge_url(bad, n).is_err(), "{bad}");
        }
    }

    #[test]
    fn origins() {
        assert!(same_origin("https://git.example.com", "https://git.example.com/a/b?x=1"));
        for bad in [
            "http://git.example.com/a",
            "https://git.example.com:8443/a",
            "https://git.example.com.evil.example/a",
            "https://evil.example/",
        ] {
            assert!(!same_origin("https://git.example.com", bad), "{bad}");
        }
    }

    #[test]
    fn every_ipv4_spelling_is_judged_as_the_address_it_is() {
        for u in [
            "https://2130706433/",
            "https://0x7f.1/",
            "https://0x7f000001/",
            "https://017700000001/",
            "https://127.1/",
            "https://127.0.0.1./",
            "https://0/",
            "https://0.0.0.0/",
            "https://[::]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:7f00:1]/",
            "https://[0:0:0:0:0:ffff:a9fe:a9fe]/",
            "https://%31%32%37.0.0.1/",
            "HTTPS://[::1]/",
            "https://[64:ff9b::7f00:1]/",
            "https://[2002:7f00:1::]/",
            "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",
            "https://[fe80::1]/",
            "https://[ff02::1]/",
            "https://[fd00:ec2::254]/",
            "https://[::5efe:7f00:1]/",
            "https://100.100.100.100/",
            "https://100.100.100.200/",
            "https://168.63.129.16/",
        ] {
            let url = reqwest::Url::parse(u).unwrap();
            let ip = literal_ip(&url).unwrap_or_else(|| panic!("{u} is not a literal"));
            for m in [Mode::Public, Mode::Tailnet, Mode::Internal] {
                assert!(!m.permits(ip, &[]), "{u} {m:?}");
            }
        }
        // A zone id is not a valid URL host at all.
        assert!(reqwest::Url::parse("https://[fe80::1%25eth0]/").is_err());
        assert!(reqwest::Url::parse("https://[fe80::1%eth0]/").is_err());
    }

    #[test]
    fn host_own_addresses_are_refused_in_every_mode() {
        let own = [ip("203.0.113.9"), ip("93.184.215.14"), ip("100.64.0.9"), ip("2001:4860::5")];
        for m in [Mode::Public, Mode::Tailnet, Mode::Internal] {
            assert!(!m.permits(ip("93.184.215.14"), &own), "{m:?}");
            assert!(!m.permits(ip("::ffff:93.184.215.14"), &own), "{m:?}");
            assert!(!m.permits(ip("2001:4860::5"), &own), "{m:?}");
            assert!(m.permits(ip("93.184.215.15"), &own), "{m:?}");
        }
        assert!(!Mode::Tailnet.permits(ip("100.64.0.9"), &own));
        assert!(Mode::Tailnet.permits(ip("100.64.0.10"), &own));
        assert!(!Mode::Public.permits(ip("100.64.0.10"), &own), "CGNAT in public mode");
    }

    #[test]
    fn tailnet_mode_keeps_tailscaled_out() {
        assert!(!Mode::Tailnet.permits(ip("100.100.100.100"), &[]));
        assert!(!Mode::Tailnet.permits(ip("fd7a:115c:a1e0::53"), &[]));
        assert!(Mode::Tailnet.permits(ip("fd7a:115c:a1e0:ab12::7"), &[]));
    }

    #[test]
    fn forge_urls_cannot_smuggle_internal_hosts() {
        use Network::*;
        for (bad, n) in [
            ("http://evil@127.0.0.1", Internal),
            ("http://evil.example@127.0.0.1/", Internal),
            ("http://127.0.0.1\\@evil.example/", Internal),
            ("HTTP://127.0.0.1:3000", Internal),
            ("HTTPS://127.0.0.1", Public),
            ("http://0x7f.1", Internal),
            ("http://2130706433", Internal),
            ("http://017700000001", Internal),
            ("http://[::ffff:127.0.0.1]:3000", Internal),
            ("http://0.0.0.0:3000", Internal),
            ("http://[::]:3000", Internal),
            ("https://[::ffff:10.0.0.1]", Public),
            ("https://[64:ff9b::a00:1]", Public),
            ("https://[2002:a00:1::]", Public),
            ("http://100.100.100.100", Internal),
            ("https://[fe80::1%25eth0]", Public),
        ] {
            assert!(check_forge_url(bad, n).is_err(), "{bad}");
        }
        // The scheme is case-insensitive, so an uppercase one is still held to the https rule.
        assert!(check_forge_url("HTTP://gitea.example.com", Public).is_err());
        assert!(check_forge_url("HTTPS://gitea.example.com", Public).is_err(), "only the canonical spelling is stored");
        assert!(check_forge_url("https://gitea.example.com/", Public).is_ok());
    }

    #[tokio::test]
    async fn send_refuses_every_loopback_spelling_before_dialling() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        for host in ["2130706433", "0x7f.1", "017700000001", "127.0.0.1.", "[::ffff:127.0.0.1]", "0.0.0.0", "[::]"] {
            for (m, scheme) in [(Mode::Public, "https"), (Mode::Internal, "http")] {
                let c = client(m);
                let e = send(&c, m, c.get(format!("{scheme}://{host}:{port}/"))).await.unwrap_err();
                assert!(e.to_string().contains("internal address"), "{m:?} {host}: {e}");
            }
        }
    }

    #[tokio::test]
    async fn trailing_dot_localhost_is_refused_by_the_resolver() {
        for m in [Mode::Public, Mode::Tailnet, Mode::Internal] {
            assert!(Guard(m).resolve("localhost.".parse().unwrap()).await.is_err(), "{m:?}");
        }
    }

    #[test]
    fn origins_ignore_userinfo_and_case_tricks() {
        assert!(same_origin("https://git.example.com", "HTTPS://GIT.EXAMPLE.COM/a"));
        for bad in [
            "https://git.example.com@evil.example/a",
            "https://git.example.com:443@evil.example/",
            "//evil.example/a",
            "/a/b",
            "https://git.example.com:8443/a",
            "file:///etc/passwd",
        ] {
            assert!(!same_origin("https://git.example.com", bad), "{bad}");
        }
        assert!(!same_origin("file:///a", "file:///a"), "opaque origins never match");
    }

    #[test]
    fn check_and_connect_read_the_same_host() {
        // (input, host the parser dials). Stored forge urls must already be the parser's own text.
        for (raw, dialled) in [
            ("http://0x7f.1/", "127.0.0.1"),
            ("http://2130706433/", "127.0.0.1"),
            ("http://017700000001/", "127.0.0.1"),
            ("http://127.1/", "127.0.0.1"),
            ("http://%31%32%37.0.0.1/", "127.0.0.1"),
            ("http://127.0.0.1./", "127.0.0.1"),
            ("http://[::ffff:7f00:1]/", "[::ffff:7f00:1]"),
            ("http://[::ffff:127.0.0.1]/", "[::ffff:7f00:1]"),
            ("http://a@127.0.0.1/", "127.0.0.1"),
            ("http://127.0.0.1\\@evil.example/", "127.0.0.1"),
            ("http://evil.example\\@127.0.0.1/", "evil.example"),
            ("http://GIT.Example.com/", "git.example.com"),
        ] {
            let u = reqwest::Url::parse(raw).unwrap();
            assert_eq!(u.host_str(), Some(dialled), "{raw}");
            // The literal check sees the very host reqwest is handed: loopback, however spelled.
            if dialled.starts_with("127.") || dialled.starts_with("[::ffff") {
                assert!(!Mode::Internal.permits(literal_ip(&u).unwrap(), &[]), "{raw}");
            }
            // Non-canonical spellings are refused at save, even when the host would be allowed.
            if raw != u.as_str() {
                assert!(check_forge_url(raw, Network::Internal).is_err(), "{raw}");
            }
        }
        // A public host in a non-canonical spelling is refused too: one spelling, one parser.
        for raw in ["https://GIT.example.com", "https://git.example.com:443", "https://git.example.com/a/../b", "https://%67it.example.com"]
        {
            assert!(check_forge_url(raw, Network::Public).is_err(), "{raw}");
        }
        assert!(check_forge_url("https://git.example.com:8443/gitea", Network::Public).is_ok());
    }
}
