//! The first minutes after the machine (or kiln) starts: the network, DNS and tailscaled may not
//! be up yet. Nothing here fails anything; it only lets the rest of kiln say "starting: waiting
//! for the network" instead of a failure, and only for `GRACE`. A subsystem that is still not
//! working after that shows its real error.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long after `kiln serve` starts a missing network counts as "starting".
pub const GRACE: Duration = Duration::from_secs(180);
/// The same for a bare `kiln doctor`, which has no start time: seconds since the machine booted.
const BOOT_GRACE_SECS: u64 = 300;

static STARTED: OnceLock<Instant> = OnceLock::new();
static NET_UP: AtomicBool = AtomicBool::new(false);

/// Seconds since the machine booted (Linux).
fn uptime_secs() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime").ok()?.split('.').next()?.parse().ok()
}

/// Inside the grace period: `kiln serve` started less than `GRACE` ago (or, in a CLI run, the
/// machine booted less than five minutes ago).
pub fn starting() -> bool {
    match STARTED.get() {
        Some(t) => t.elapsed() < GRACE,
        None => uptime_secs().is_some_and(|u| u < BOOT_GRACE_SECS),
    }
}

/// Whether name resolution answers for `host` (an IP literal always does).
pub async fn dns_ok(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let Ok(Ok(mut a)) = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host, 443))).await else { return false };
    a.next().is_some()
}

/// Starting, and the network is not up yet: failures that only mean "not yet" read as such.
/// Needs `watch` running; a CLI run asks `dns_ok` itself.
pub fn waiting_for_network() -> bool {
    starting() && !NET_UP.load(Ordering::Relaxed)
}

/// The text of a failure that only means the network is not up yet.
pub fn waiting_msg(why: &str) -> String {
    waiting_for("the network", why)
}

/// "starting: waiting for `what` (`why`)"; a `why` that already says "waiting for ..." is not repeated.
pub fn waiting_for(what: &str, why: &str) -> String {
    if why.starts_with("waiting for") { format!("starting: {why}") } else { format!("starting: waiting for {what} ({why})") }
}

/// `kiln serve`: start the clock and keep `waiting_for_network` current for the grace period.
/// `host` is looked up on every round, so a late-configured forge is picked up.
pub fn watch(host: impl Fn() -> String + Send + 'static) {
    let _ = STARTED.set(Instant::now());
    tokio::spawn(async move {
        while starting() {
            let up = dns_ok(&host()).await;
            if up && !NET_UP.swap(true, Ordering::Relaxed) {
                tracing::info!("network is up ({} s after start)", STARTED.get().map_or(0, |t| t.elapsed().as_secs()));
            }
            NET_UP.store(up, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Seconds before retry number `fails` (1-based) of something that failed only because the
/// network is not up: quick at first, then settling at `cap`.
pub fn retry_secs(fails: u32, cap: u64) -> u64 {
    (5u64 << fails.saturating_sub(1).min(7)).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_double_up_to_the_cap() {
        assert_eq!([0, 1, 2, 3, 4, 5, 9].map(|n| retry_secs(n, 60)), [5, 5, 10, 20, 40, 60, 60]);
        assert_eq!(retry_secs(100, 30), 30);
    }

    #[tokio::test]
    async fn an_ip_literal_needs_no_dns() {
        assert!(dns_ok("192.0.2.1").await);
        assert!(!dns_ok("no-such-host.invalid").await);
    }

    #[test]
    fn the_message_says_starting() {
        assert_eq!(waiting_msg("dns error"), "starting: waiting for the network (dns error)");
        assert_eq!(waiting_msg("waiting for the network: a does not resolve"), "starting: waiting for the network: a does not resolve");
        assert_eq!(waiting_for("tailscaled", "BackendState Starting"), "starting: waiting for tailscaled (BackendState Starting)");
    }
}
