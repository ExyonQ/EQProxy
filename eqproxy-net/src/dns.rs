//! Non-blocking dynamic DNS (B-H13/B-N18/B-E15): `HOSTNAME:PORT` servers
//! are resolved in the background and re-resolved periodically — the
//! listeners serve from the first moment whatever DNS does (the lesson of
//! [Envoy #14670](https://github.com/envoyproxy/envoy/issues/14670): never
//! block startup or traffic on DNS).
//!
//! Semantics (documented, no surprises):
//!
//! - Resolution runs in its own task, started after `bind`: a hung or
//!   slow DNS never delays a listener or a request.
//! - While a name is unresolved its slots are never selected: the
//!   dataplane answers 503 (`no_available_server` metric) instead of
//!   blocking — an explicit answer, never a silent hang.
//! - Every `interval` each unique name is resolved again with a bounded
//!   attempt (`timeout`); a changed address is swapped in hot (new
//!   endpoint: the health machine and the slow-start ramp restart).
//! - A failed or empty resolution keeps the last-known address (nginx
//!   `valid=` / HAProxy `init-addr last` semantics) and counts in
//!   `dns_resolution_failures`.
//! - The first round runs immediately; `interval = 0` resolves once at
//!   startup and stops (no periodic re-resolution).
//!
//! TTL: `resolve_interval` plays the role of nginx `resolver valid=` and
//! Envoy `dns_refresh_rate` (the OS resolver caches the records; the raw
//! DNS TTL is not visible through `getaddrinfo`). A timed-out attempt is
//! dropped but its underlying OS lookup may still occupy a resolver
//! thread until the OS gives up; attempts are never overlapping per name.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use eqproxy_core::{Metrics, Shutdown};

use crate::balancer::Balancer;

/// Bounded attempt per resolution (a hung DNS cannot stall the cycle).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolver seam: [`SystemResolver`] is the production implementation
/// (`getaddrinfo` through the OS); tests inject controlled answers to
/// prove the scheduling (non-blocking startup, periodic re-resolution,
/// keep-last-known) without touching the host's resolver configuration.
pub trait Resolving: std::fmt::Debug + Send + Sync + 'static {
    /// Resolves `host:port` to its addresses. `Ok(vec![])` means the name
    /// exists but has no usable address (treated as a failed round).
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
}

/// Production resolver: the OS resolver (`tokio::net::lookup_host`).
#[derive(Debug)]
pub struct SystemResolver;

impl Resolving for SystemResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            Ok(addrs.collect())
        })
    }
}

/// Per-backend resolution settings (B-H13/B-N18/B-E15).
#[derive(Debug, Clone, Copy)]
pub struct DnsSettings {
    /// Periodic re-resolution rate; `0` = resolve once at startup.
    pub interval: Duration,
    /// Bounded attempt per resolution.
    pub timeout: Duration,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: RESOLVE_TIMEOUT,
        }
    }
}

/// Resolves the backend's names until the shutdown signal: one round
/// immediately, then one every `interval`. Runs as its own task: no
/// listener ever waits for it.
pub async fn run(
    balancer: Arc<Balancer>,
    settings: DnsSettings,
    metrics: Arc<Metrics>,
    resolver: Arc<dyn Resolving>,
    mut shutdown: Shutdown,
) {
    loop {
        round(&balancer, &settings, &metrics, resolver.as_ref()).await;
        if settings.interval.is_zero() {
            return;
        }
        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(settings.interval) => {}
        }
    }
}

/// One resolution round over the unique names, sequentially: at most one
/// in-flight attempt per name (a hung DNS cannot pile up lookups).
async fn round(
    balancer: &Balancer,
    settings: &DnsSettings,
    metrics: &Metrics,
    resolver: &dyn Resolving,
) {
    for (host, port) in balancer.name_targets() {
        let attempt =
            tokio::time::timeout(settings.timeout, resolver.resolve(host.clone(), port)).await;
        match attempt {
            Err(_) | Ok(Err(_)) => {
                // Hung or failed lookup: keep the last-known address.
                metrics
                    .dns_resolution_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(Ok(addrs)) if addrs.is_empty() => {
                // No usable address: keep the last-known one (documented).
                metrics
                    .dns_resolution_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(Ok(addrs)) => {
                metrics.dns_resolutions_ok.fetch_add(1, Ordering::Relaxed);
                let changed = balancer.apply_resolution(&host, port, &addrs);
                metrics
                    .dns_address_updates
                    .fetch_add(changed as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::balancer::{ResolvedServer, ServerAddr};

    /// What the stub resolver answers.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Answer {
        Addrs(Vec<SocketAddr>),
        Err,
        /// Hang forever (the hung-DNS case).
        Hang,
    }

    /// Stub resolver: answers the current value (test seam).
    #[derive(Debug)]
    struct Stub {
        answer: Mutex<Answer>,
        calls: Mutex<u32>,
    }

    impl Stub {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer),
                calls: Mutex::new(0),
            })
        }

        fn set(&self, answer: Answer) {
            *self.answer.lock().expect("answer lock") = answer;
        }

        fn calls(&self) -> u32 {
            *self.calls.lock().expect("calls lock")
        }
    }

    impl Resolving for Stub {
        fn resolve(
            &self,
            _host: String,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            *self.calls.lock().expect("calls lock") += 1;
            let answer = self.answer.lock().expect("answer lock").clone();
            Box::pin(async move {
                match answer {
                    Answer::Addrs(addrs) => Ok(addrs),
                    Answer::Err => Err(std::io::Error::other("stub lookup failure")),
                    Answer::Hang => std::future::pending().await,
                }
            })
        }
    }

    fn named_backend(port: u16) -> Arc<Balancer> {
        Arc::new(Balancer::new(
            vec![ResolvedServer {
                addr: ServerAddr::Name {
                    host: "api.internal".to_owned(),
                    port,
                },
                weight: 1,
                backup: false,
                priority: 0,
                maxconn: 0,
            }],
            1,
            1,
        ))
    }

    async fn eventually<F: Fn() -> bool>(what: &str, check: F) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg_attr(
        miri,
        ignore = "needs timers: miri does not support the tokio runtime clock"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn startup_resolves_immediately_then_re_resolves_at_the_interval() {
        let a: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        let b: SocketAddr = "10.0.0.2:9000".parse().expect("addr");
        let stub = Stub::new(Answer::Addrs(vec![a]));
        let balancer = named_backend(9000);
        let metrics = Arc::new(Metrics::default());
        let (stop, signal) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn(run(
            Arc::clone(&balancer),
            DnsSettings {
                interval: Duration::from_millis(50),
                timeout: Duration::from_secs(1),
            },
            Arc::clone(&metrics),
            stub.clone(),
            signal,
        ));

        // First round is immediate (no interval wait).
        eventually("first resolution", || balancer.pick() == Some(a)).await;
        assert_eq!(
            balancer.name_targets(),
            vec![("api.internal".to_owned(), 9000)]
        );

        // The periodic round picks up the new address (hot swap).
        stub.set(Answer::Addrs(vec![b]));
        eventually("re-resolution swaps the address", || {
            balancer.pick() == Some(b)
        })
        .await;
        assert_eq!(
            balancer.pick(),
            Some(b),
            "traffic follows the re-resolved address"
        );

        stop.trigger();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("resolver must stop on the signal")
            .expect("join");
        let snap = metrics.snapshot();
        assert!(snap.dns_resolutions_ok >= 2, "{snap:?}");
        assert!(snap.dns_address_updates >= 1, "{snap:?}");
    }

    #[cfg_attr(
        miri,
        ignore = "needs timers: miri does not support the tokio runtime clock"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hung_dns_fails_the_attempt_but_keeps_the_last_known_address() {
        let a: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        let stub = Stub::new(Answer::Addrs(vec![a]));
        let balancer = named_backend(9000);
        let metrics = Arc::new(Metrics::default());
        let (stop, signal) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn(run(
            Arc::clone(&balancer),
            DnsSettings {
                interval: Duration::from_millis(30),
                timeout: Duration::from_millis(100),
            },
            Arc::clone(&metrics),
            stub.clone(),
            signal,
        ));
        eventually("first resolution", || balancer.pick() == Some(a)).await;

        // DNS hangs: the round times out (bounded), the address stays.
        stub.set(Answer::Hang);
        eventually("the hung attempt is counted", || {
            metrics.snapshot().dns_resolution_failures >= 1
        })
        .await;
        assert_eq!(
            balancer.pick(),
            Some(a),
            "a hung DNS keeps the last-known address serving"
        );

        // A failing lookup behaves the same (keep-last-known).
        stub.set(Answer::Err);
        let before = metrics.snapshot().dns_resolution_failures;
        eventually("the failed attempt is counted", || {
            metrics.snapshot().dns_resolution_failures > before
        })
        .await;
        assert_eq!(
            balancer.pick(),
            Some(a),
            "a failed lookup keeps the last-known address serving"
        );

        stop.trigger();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("resolver must stop on the signal")
            .expect("join");
    }

    #[cfg_attr(
        miri,
        ignore = "needs timers: miri does not support the tokio runtime clock"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_interval_resolves_once_and_stops() {
        let a: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        let stub = Stub::new(Answer::Addrs(vec![a]));
        let balancer = named_backend(9000);
        let metrics = Arc::new(Metrics::default());
        let (stop, signal) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn(run(
            Arc::clone(&balancer),
            DnsSettings {
                interval: Duration::ZERO,
                timeout: Duration::from_secs(1),
            },
            Arc::clone(&metrics),
            stub.clone(),
            signal,
        ));
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("interval 0 resolves once and returns")
            .expect("join");
        assert_eq!(balancer.pick(), Some(a));
        assert_eq!(stub.calls(), 1, "exactly one resolution round");
        let snap = metrics.snapshot();
        assert_eq!(snap.dns_resolutions_ok, 1, "{snap:?}");
        stop.trigger();
    }
}
