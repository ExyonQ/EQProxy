//! Backend keep-alive pool (A16, Phase 3 first slice).
//!
//! One idle backend connection per served exchange would burn an ephemeral
//! source port per request (measured EADDRNOTAVAIL collapse in Phase 2c).
//! The pool keeps clean backend connections alive for reuse.
//!
//! Reuse safety contract (PARITY_MATRIX A16): a connection returns to the
//! pool **only after a fully clean exchange** — request completely sent,
//! response completely forwarded, no framing error, no truncation, no
//! timeout, and the server did not signal close (`wants_close`). Anything
//! else drops the connection. A pooled connection is therefore byte-aligned
//! at a message boundary when checked out.
//!
//! Bounds: at most [`MAX_IDLE_PER_SERVER`] idle connections per server and
//! an idle expiry ([`DEFAULT_POOL_IDLE_TIMEOUT`]); excess and stale
//! connections are dropped, never queued without limit. A poisoned lock is
//! recovered (never panics), treating the pool as momentarily empty.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::BufReader;

use crate::proxy::{BoxRead, BoxWrite};

/// Idle cap per backend server: burst headroom without unbounded memory.
pub const MAX_IDLE_PER_SERVER: usize = 64;

/// How long an idle backend connection is kept. Under typical origin
/// keep-alive timeouts (60–75 s); a server-side idle close racing a checkout
/// surfaces as one explicit 502 + `connect_failures`, like a dial failure.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// One parked backend connection, byte-aligned at a message boundary.
pub struct IdleConn {
    read: BufReader<BoxRead>,
    write: BoxWrite,
    idle_since: Instant,
}

/// Per-server idle queues, shared across listeners of the same backend.
pub struct Pool {
    inner: Mutex<HashMap<SocketAddr, VecDeque<IdleConn>>>,
    max_idle_per_server: usize,
    idle_timeout: Duration,
}

impl Pool {
    /// Pool with explicit bounds (production uses the module defaults).
    #[must_use]
    pub fn new(max_idle_per_server: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_idle_per_server,
            idle_timeout,
        }
    }

    /// Production defaults: bounded and expiring.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(MAX_IDLE_PER_SERVER, DEFAULT_POOL_IDLE_TIMEOUT)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, VecDeque<IdleConn>>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Take a fresh idle connection to `addr`, or `None` (caller dials).
    /// Stale entries and entries with pending bytes are dropped, never handed
    /// out: checkout always yields a message-aligned connection or nothing.
    pub fn checkout(
        &self,
        addr: &SocketAddr,
        now: Instant,
    ) -> Option<(BufReader<BoxRead>, BoxWrite)> {
        let mut inner = self.lock();
        let queue = inner.get_mut(addr)?;
        while let Some(conn) = queue.pop_back() {
            if now.duration_since(conn.idle_since) > self.idle_timeout {
                continue;
            }
            if !conn.read.buffer().is_empty() {
                continue;
            }
            return Some((conn.read, conn.write));
        }
        None
    }

    /// Park a connection after a clean exchange. Silently drops when full,
    /// stale, or holding unread bytes (fail-closed, never miscounted).
    pub fn checkin(
        &self,
        addr: SocketAddr,
        read: BufReader<BoxRead>,
        write: BoxWrite,
        now: Instant,
    ) {
        if !read.buffer().is_empty() {
            return;
        }
        let mut inner = self.lock();
        let queue = inner.entry(addr).or_default();
        if queue.len() >= self.max_idle_per_server {
            return;
        }
        queue.push_back(IdleConn {
            read,
            write,
            idle_since: now,
        });
    }

    /// Idle connections held for `addr` (tests and diagnostics).
    #[must_use]
    pub fn idle_count(&self, addr: &SocketAddr) -> usize {
        self.lock().get(addr).map_or(0, VecDeque::len)
    }

    /// Total idle connections held (diagnostics).
    #[must_use]
    pub fn idle_total(&self) -> usize {
        self.lock().values().map(VecDeque::len).sum()
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("idle_total", &self.idle_total())
            .field("max_idle_per_server", &self.max_idle_per_server)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    fn pair() -> (BufReader<BoxRead>, BoxWrite) {
        let (a, b) = duplex(64 * 1024);
        let (ra, wa) = tokio::io::split(a);
        let (rb, wb) = tokio::io::split(b);
        // Keep the far halves alive inside the test; the pool owns one side.
        std::mem::forget((rb, wb));
        let read: BoxRead = Box::new(ra);
        let write: BoxWrite = Box::new(wa);
        (BufReader::new(read), write)
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:9000".parse().expect("addr")
    }

    #[test]
    fn roundtrip_hands_back_a_clean_connection() {
        let pool = Pool::new(4, Duration::from_secs(60));
        let now = Instant::now();
        assert!(pool.checkout(&addr(), now).is_none());
        let (read, write) = pair();
        pool.checkin(addr(), read, write, now);
        assert_eq!(pool.idle_count(&addr()), 1);
        assert!(pool.checkout(&addr(), now).is_some());
        assert_eq!(pool.idle_count(&addr()), 0);
    }

    #[test]
    fn idle_cap_drops_excess() {
        let pool = Pool::new(2, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..5 {
            let (read, write) = pair();
            pool.checkin(addr(), read, write, now);
        }
        assert_eq!(pool.idle_count(&addr()), 2);
    }

    #[test]
    fn stale_entries_are_never_handed_out() {
        let pool = Pool::new(4, Duration::from_millis(50));
        let (read, write) = pair();
        pool.checkin(addr(), read, write, Instant::now());
        std::thread::sleep(Duration::from_millis(80));
        assert!(pool.checkout(&addr(), Instant::now()).is_none());
        assert_eq!(pool.idle_count(&addr()), 0);
    }

    #[tokio::test]
    async fn connection_with_pending_bytes_is_dropped() {
        let pool = Pool::new(4, Duration::from_secs(60));
        let now = Instant::now();
        let (a, b) = duplex(64 * 1024);
        let (ra, _wa) = tokio::io::split(a);
        let (_rb, mut far_write) = tokio::io::split(b);
        // The far end (a confused origin) sends bytes the proxy never
        // framed: they land in the pooled read half's buffer.
        far_write.write_all(b"leftover").await.expect("write");
        let mut read = BufReader::new(Box::new(ra) as BoxRead);
        let buffered = tokio::io::AsyncBufReadExt::fill_buf(&mut read)
            .await
            .expect("fill");
        assert!(!buffered.is_empty(), "test setup must stage pending bytes");
        // Any write half will do: the checkin must drop it with the read half.
        let (c, _d) = duplex(8);
        let (_rc, wc) = tokio::io::split(c);
        let write: BoxWrite = Box::new(wc);
        pool.checkin(addr(), read, write, now);
        assert_eq!(
            pool.idle_count(&addr()),
            0,
            "a connection holding unread bytes must never be pooled"
        );
    }

    #[test]
    fn servers_are_keyed_independently() {
        let pool = Pool::with_defaults();
        let now = Instant::now();
        let other: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        let (read, write) = pair();
        pool.checkin(addr(), read, write, now);
        assert!(pool.checkout(&other, now).is_none());
        assert!(pool.checkout(&addr(), now).is_some());
    }
}
