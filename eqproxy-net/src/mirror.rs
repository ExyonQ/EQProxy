//! Request mirroring (B-H3; Envoy `request_mirror_policies`).
//!
//! A matched rule with `[listener.*.rules.request_mirror]` sends a **copy**
//! of the matching requests to another backend. The copy is
//! fire-and-forget: its response never reaches the client, a mirror that
//! is down/slow never delays or changes the client's answer, and the
//! mirrored request carries the same forwarded head (and body, up to a
//! budget) the primary backend received.
//!
//! Bounds (documented, never silent): the body is copied up to
//! [`BODY_BUDGET`] bytes — a larger body is **not** mirrored at all and
//! counts `mirror_skipped` — and the mirror socket is used for one request
//! and closed (no pool: a shadow backend must never consume the pool
//! capacity of the real one).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use eqproxy_core::metrics::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proxy::{BoxRead, BoxWrite, DialTimeouts, connect_backend_to};

/// Largest request body copied to the mirror backend (B-H3). Beyond it the
/// request is not mirrored (counted), never truncated.
pub const BODY_BUDGET: usize = 256 * 1024;

/// Largest response the mirror drains before closing (politeness: reading
/// the head avoids a reset on the shadow backend). Never forwarded.
const DRAIN_BUDGET: usize = 64 * 1024;

/// One request copy waiting to be sent (B-H3).
pub struct MirrorCopy {
    /// Listener name (logs).
    pub name: String,
    /// Connect timeout of the listener (the mirror uses the same budget).
    pub connect_timeout: Duration,
    /// Idle timeout: the copy is abandoned (counted) when the shadow
    /// backend stops accepting bytes or never answers.
    pub idle_timeout: Duration,
    /// The rule's mirror policy (backend + sampling).
    pub policy: Arc<crate::proxy::MirrorPolicy>,
    /// Client address (seen by the shadow backend as the peer).
    pub peer: SocketAddr,
    /// Local address of the accepted connection (PROXY v2 destination).
    pub local: SocketAddr,
    /// Forwarded head (without the trailing CRLFCRLF).
    pub head: Vec<u8>,
    /// Forwarded body bytes, already framed as sent to the primary
    /// backend (chunk framing included). Empty when the request had none.
    pub body: Vec<u8>,
    /// Shared counters.
    pub metrics: Arc<Metrics>,
}

/// Sends the copy on a detached task: the client's exchange never waits for
/// it and never observes its result.
pub fn spawn(copy: MirrorCopy) {
    tokio::spawn(async move {
        copy.run().await;
    });
}

impl MirrorCopy {
    async fn run(self) {
        let backend = Arc::clone(&self.policy.backend);
        let Some(addr) = backend.balancer.pick() else {
            // A shadow backend without a live server is a policy problem:
            // counted and logged, never a client-visible error.
            self.metrics.mirror_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "WARN [{}] mirror to {:?}: no server available (peer {})",
                self.name, backend.name, self.peer
            );
            return;
        };
        let (mut read, mut write, _opened) = match connect_backend_to(
            DialTimeouts {
                name: &self.name,
                connect: self.connect_timeout,
                idle: self.idle_timeout,
                http: true,
            },
            &backend,
            addr,
            self.peer,
            self.local,
            &self.metrics,
        )
        .await
        {
            Ok(pair) => pair,
            Err(_) => {
                self.metrics.mirror_failures.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "WARN [{}] mirror to {:?} at {addr} failed to connect (peer {})",
                    self.name, backend.name, self.peer
                );
                return;
            }
        };

        // The copy is one whole request: head, terminator, body. The write
        // half is then shut down so the shadow backend sees a complete
        // message even when the body was empty.
        let sent = self.write_request(&mut write).await;
        match sent {
            Ok(()) => {
                self.metrics
                    .requests_mirrored
                    .fetch_add(1, Ordering::Relaxed);
                // Drain (bounded) so closing the socket is a clean FIN.
                drain(&mut read, self.idle_timeout).await;
            }
            Err(why) => {
                self.metrics.mirror_failures.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "WARN [{}] mirror to {:?} at {addr} failed: {why} (peer {})",
                    self.name, backend.name, self.peer
                );
            }
        }
    }

    async fn write_request(&self, write: &mut BoxWrite) -> Result<(), String> {
        let whole = async {
            write.write_all(&self.head).await?;
            write.write_all(b"\r\n\r\n").await?;
            if !self.body.is_empty() {
                write.write_all(&self.body).await?;
            }
            write.flush().await?;
            write.shutdown().await
        };
        match tokio::time::timeout(self.idle_timeout, whole).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!("idle timeout after {:?}", self.idle_timeout)),
        }
    }
}

/// Reads (and discards) what the shadow backend answers, bounded by
/// [`DRAIN_BUDGET`] and `idle`. Never blocks the task forever.
async fn drain(read: &mut BoxRead, idle: Duration) {
    let mut buf = [0_u8; 4096];
    let mut seen = 0;
    loop {
        let read_some = tokio::time::timeout(idle, read.read(&mut buf)).await;
        match read_some {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => {
                seen += n;
                if seen >= DRAIN_BUDGET {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    #[tokio::test]
    async fn head_body_and_counter_reach_a_real_socket() {
        // A real TCP sink: the copy is only "mirrored" when the bytes are
        // actually accepted by a socket, not when a task was spawned.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sink");
        let addr = listener.local_addr().expect("addr");
        let received = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let sink_bytes = Arc::clone(&received);
        let accept = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0_u8; 8192];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink_bytes.lock().await.extend_from_slice(&buf[..n]),
                }
            }
        });

        let backend = Arc::new(crate::proxy::ResolvedBackend::single("shadow", addr));
        let counters = metrics();
        let copy = MirrorCopy {
            name: "web".to_owned(),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            policy: Arc::new(crate::proxy::MirrorPolicy::new(backend, 100)),
            peer: "127.0.0.1:1234".parse().expect("peer"),
            local: "127.0.0.1:8080".parse().expect("local"),
            head: b"GET /shadow HTTP/1.1\r\nHost: shop.example.com".to_vec(),
            body: Vec::new(),
            metrics: Arc::clone(&counters),
        };
        copy.run().await;
        assert_eq!(
            counters.requests_mirrored.load(Ordering::Relaxed),
            1,
            "a copy written to a live socket counts as mirrored"
        );
        assert_eq!(
            counters.mirror_failures.load(Ordering::Relaxed),
            0,
            "a written copy is not a failure"
        );
        let _ = tokio::time::timeout(Duration::from_secs(2), accept).await;
        let seen = String::from_utf8(received.lock().await.clone()).expect("utf8");
        assert!(
            seen.starts_with("GET /shadow HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"),
            "the shadow backend receives the whole forwarded head: {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_dead_shadow_backend_counts_a_failure_and_never_panics() {
        // Port 1 on loopback has no listener: connect fails fast.
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let backend = Arc::new(crate::proxy::ResolvedBackend::single("shadow", addr));
        let counters = metrics();
        let copy = MirrorCopy {
            name: "web".to_owned(),
            connect_timeout: Duration::from_millis(200),
            idle_timeout: Duration::from_millis(200),
            policy: Arc::new(crate::proxy::MirrorPolicy::new(backend, 100)),
            peer: "127.0.0.1:1234".parse().expect("peer"),
            local: "127.0.0.1:8080".parse().expect("local"),
            head: b"GET / HTTP/1.1\r\nHost: shop.example.com".to_vec(),
            body: Vec::new(),
            metrics: Arc::clone(&counters),
        };
        copy.run().await;
        assert_eq!(
            counters.mirror_failures.load(Ordering::Relaxed),
            1,
            "exactly the one failed copy is counted"
        );
        assert_eq!(
            counters.requests_mirrored.load(Ordering::Relaxed),
            0,
            "nothing was mirrored: the shadow backend was unreachable"
        );
    }

    #[test]
    fn sampling_uses_a_deterministic_percentage() {
        let backend = Arc::new(crate::proxy::ResolvedBackend::single(
            "shadow",
            SocketAddr::from(([127, 0, 0, 1], 9)),
        ));
        let policy = crate::proxy::MirrorPolicy::new(backend, 25);
        let hits = (0..100).filter(|_| policy.sample()).count();
        assert_eq!(hits, 25, "25% of every 100 requests, exactly");
        // One more block: the position continues, so the share stays 25%.
        let hits = (0..100).filter(|_| policy.sample()).count();
        assert_eq!(hits, 25);
        let _ = AtomicU64::new(0);
    }
}
