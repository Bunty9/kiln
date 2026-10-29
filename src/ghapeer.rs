//! Who owns the other end of a connection to the Actions cache listener, decided by the kernel and never by the
//! request: the peer's socket inode comes from /proc/net/tcp, the process owning it from /proc/<pid>/fd, and the VM from
//! that process's cgroup scope (`kiln-vm-<id>.scope`) or, without scopes, from the pids kiln started for each VM.
//! Anything unknown is `None`, which the listener proxies to GitHub untouched. The /proc parsing is pure and tested.

use axum::http::{HeaderMap, header};
use base64::Engine;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a resolved peer stands, and how many peers are remembered.
const TTL: Duration = Duration::from_secs(600);
const MAX_PEERS: usize = 1024;

/// A socket address as /proc/net/tcp prints it: each 32-bit word of the address in the machine's byte order.
fn proc_addr(ip: IpAddr, port: u16) -> String {
    let words: Vec<String> = match ip {
        IpAddr::V4(a) => vec![format!("{:08X}", u32::from_ne_bytes(a.octets()))],
        IpAddr::V6(a) => a.octets().chunks(4).map(|c| format!("{:08X}", u32::from_ne_bytes(c.try_into().unwrap()))).collect(),
    };
    format!("{}:{port:04X}", words.concat())
}

/// The inode of the socket with local address `local` and remote address `remote` in the text of /proc/net/tcp (or tcp6).
pub fn socket_inode(table: &str, local: &str, remote: &str) -> Option<u64> {
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 9 && f[1].eq_ignore_ascii_case(local) && f[2].eq_ignore_ascii_case(remote))
            .then(|| f[9].parse::<u64>().ok().filter(|&i| i != 0))
            .flatten()
    })
}

/// The VM id in a /proc/<pid>/cgroup text: a path component `kiln-vm-<id>.scope`.
pub fn cgroup_vm(text: &str) -> Option<String> {
    text.lines().flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/')).find_map(|c| {
        let id = c.strip_prefix("kiln-vm-")?.strip_suffix(".scope")?;
        (!id.is_empty()).then(|| id.to_string())
    })
}

/// The parent pid in a /proc/<pid>/stat text (the command name in parentheses may hold anything).
pub fn parse_ppid(stat: &str) -> Option<u32> {
    stat[stat.rfind(')')? + 1..].split_whitespace().nth(1)?.parse().ok()
}

/// `Authorization: Bearer <jwt>` -> the unverified `runner_id` claim. A cross-check only, never an identity.
pub fn bearer_runner_id(h: &HeaderMap) -> Option<u64> {
    let t = h.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    let payload = t.split('.').nth(1)?.trim_end_matches('=');
    let c: serde_json::Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    match &c["runner_id"] {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The pid (of kiln's own user) that owns socket `inode`. Stops at the first match.
fn owner_pid(inode: u64) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let want = format!("socket:[{inode}]");
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        if e.metadata().is_ok_and(|m| m.uid() != me) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        if fds.flatten().any(|f| std::fs::read_link(f.path()).is_ok_and(|l| l.to_str() == Some(want.as_str()))) {
            return Some(pid);
        }
    }
    None
}

/// The VM a process belongs to: its cgroup scope, else the pid or an ancestor kiln started for a VM.
pub fn vm_of_pid(pid: u32, tracked: &[(String, Option<u32>)]) -> Option<String> {
    if let Some(id) = cgroup_vm(&read(&format!("/proc/{pid}/cgroup"))) {
        return Some(id);
    }
    let mut p = pid;
    for _ in 0..32 {
        if let Some((id, _)) = tracked.iter().find(|(_, t)| *t == Some(p)) {
            return Some(id.clone());
        }
        p = parse_ppid(&read(&format!("/proc/{p}/stat"))).filter(|&q| q > 1)?;
    }
    None
}

/// Peer -> VM id, remembered per connection: (socket inode, VM id, when). The inode is re-checked in /proc/net/tcp on
/// every use, so a port reused by another process never inherits the earlier answer.
#[derive(Default)]
pub struct Peers {
    seen: Mutex<HashMap<SocketAddr, (u64, String, Instant)>>,
    /// VMs already warned about (a runner_id that disagrees with the one kiln minted).
    pub warned: Mutex<std::collections::HashSet<String>>,
}

impl Peers {
    fn inode(peer: SocketAddr, server: SocketAddr) -> Option<u64> {
        let to6 = |a: IpAddr| match a {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };
        if peer.ip().is_ipv4() && server.ip().is_ipv4() {
            let t = read("/proc/net/tcp");
            if let Some(i) = socket_inode(&t, &proc_addr(peer.ip(), peer.port()), &proc_addr(server.ip(), server.port())) {
                return Some(i);
            }
        }
        // A dual-stack client socket shows up in tcp6 with IPv4-mapped addresses.
        let (p, s) = (to6(peer.ip()), to6(server.ip()));
        socket_inode(&read("/proc/net/tcp6"), &proc_addr(p.into(), peer.port()), &proc_addr(s.into(), server.port()))
    }

    /// The VM whose process holds the client end of the connection `peer` -> `server`; `vm_of` maps a pid to a VM.
    // ponytail: synchronous /proc reads on the request path (a table read per call, an fd scan per new connection);
    // a spawn_blocking and a netlink sock_diag query if this ever shows up in a profile.
    pub fn vm_for_peer(&self, peer: SocketAddr, server: SocketAddr, vm_of: &dyn Fn(u32) -> Option<String>) -> Option<String> {
        let inode = Self::inode(peer, server)?;
        {
            let mut m = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            match m.get(&peer) {
                Some((i, vm, at)) if *i == inode && at.elapsed() < TTL => return Some(vm.clone()),
                Some(_) => drop(m.remove(&peer)),
                None => {}
            }
        }
        let vm = vm_of(owner_pid(inode)?)?;
        let mut m = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= MAX_PEERS {
            m.retain(|_, (_, _, at)| at.elapsed() < TTL);
        }
        if m.len() < MAX_PEERS {
            m.insert(peer, (inode, vm.clone(), Instant::now()));
        }
        Some(vm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:E2A4 0100007F:1389 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:1389 0100007F:E2A4 01 00000000:00000000 00:00000000 00000000  1000        0 515151 1 0000000000000000 20 4 30 10 -1\n\
   2: 0100007F:E2A5 0100007F:1389 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 20 4 30 10 -1\n";

    #[test]
    fn proc_addresses_and_inodes() {
        if cfg!(target_endian = "little") {
            assert_eq!(proc_addr("127.0.0.1".parse().unwrap(), 5001), "0100007F:1389");
            assert_eq!(proc_addr("::ffff:127.0.0.1".parse().unwrap(), 5001), "0000000000000000FFFF00000100007F:1389");
        }
        // The client end (local = the peer, remote = the listener), not kiln's accepted socket.
        assert_eq!(socket_inode(TCP, "0100007F:E2A4", "0100007F:1389"), Some(424242));
        assert_eq!(socket_inode(TCP, "0100007f:e2a4", "0100007F:1389"), Some(424242), "hex case");
        assert_eq!(socket_inode(TCP, "0100007F:E2A5", "0100007F:1389"), None, "inode 0 is no owner");
        assert_eq!(socket_inode(TCP, "0100007F:E2A6", "0100007F:1389"), None);
        assert_eq!(socket_inode("garbage\nshort line", "a", "b"), None);
    }

    #[test]
    fn cgroup_stat_and_jwt_parsing() {
        assert_eq!(
            cgroup_vm("0::/user.slice/user-1000.slice/user@1000.service/app.slice/kiln-vm-kiln-1760000000-3.scope\n").as_deref(),
            Some("kiln-1760000000-3")
        );
        assert_eq!(cgroup_vm("12:cpu:/a/kiln-vm-x.scope/leaf\n0::/b\n").as_deref(), Some("x"), "v1 lines, a deeper leaf");
        for none in ["0::/user.slice/session-2.scope\n", "0::/kiln-vm-.scope\n", "0::/kiln-vm-x.service\n", ""] {
            assert_eq!(cgroup_vm(none), None, "{none:?}");
        }
        assert_eq!(parse_ppid("1234 (qemu (x) y) S 77 1234 1234 0"), Some(77));
        assert_eq!(parse_ppid("garbage"), None);
        let jwt = |claims: &str| {
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, format!("Bearer e30.{}.sig", b.encode(claims)).parse().unwrap());
            h
        };
        assert_eq!(bearer_runner_id(&jwt(r#"{"runner_id":4242,"run_id":1}"#)), Some(4242));
        assert_eq!(bearer_runner_id(&jwt(r#"{"runner_id":"77"}"#)), Some(77));
        assert_eq!(bearer_runner_id(&jwt(r#"{"run_id":1}"#)), None);
        assert_eq!(bearer_runner_id(&HeaderMap::new()), None);
        let mut bad = HeaderMap::new();
        bad.insert(header::AUTHORIZATION, "Bearer not-a-jwt".parse().unwrap());
        assert_eq!(bearer_runner_id(&bad), None);
    }

    /// The test process plays the VM: it connects to a listener, and its own socket resolves to its own pid.
    #[tokio::test]
    async fn a_peer_resolves_to_its_owner_through_the_kernel() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = l.local_addr().unwrap();
        let c = tokio::net::TcpStream::connect(server).await.unwrap();
        let (_s, _) = l.accept().await.unwrap();
        let peer = c.local_addr().unwrap();
        let peers = Peers::default();
        let me = std::process::id();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let vm_of = |pid: u32| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (pid == me).then(|| "vm-x".to_string())
        };
        assert_eq!(peers.vm_for_peer(peer, server, &vm_of).as_deref(), Some("vm-x"));
        assert_eq!(peers.vm_for_peer(peer, server, &vm_of).as_deref(), Some("vm-x"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "the second answer comes from the per-connection cache");
        // A pid that maps to no VM is unknown; so is an address that is not a socket.
        assert_eq!(Peers::default().vm_for_peer(peer, server, &|_| None), None);
        assert_eq!(peers.vm_for_peer("127.0.0.1:1".parse().unwrap(), server, &vm_of), None);
        // Without scopes the pid (or an ancestor) kiln started for the VM is the fallback.
        let mut kid = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        assert_eq!(vm_of_pid(me, &[("vm-y".into(), Some(me))]).as_deref(), Some("vm-y"));
        assert_eq!(vm_of_pid(kid.id(), &[("vm-y".into(), Some(me))]).as_deref(), Some("vm-y"), "a child of the tracked pid");
        assert_eq!(vm_of_pid(kid.id(), &[("vm-y".into(), Some(u32::MAX))]), None);
        let _ = kid.kill();
        let _ = kid.wait();
        drop(c);
    }
}
