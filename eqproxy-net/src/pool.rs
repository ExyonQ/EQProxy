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
//! Sizing: the idle cap per server follows the peak concurrency the balancer
//! reports when a connection is borrowed (`note_in_flight`). A burst of N
//! concurrent exchanges therefore parks up to N idle connections instead of
//! the floor of [`IDLE_FLOOR_PER_SERVER`], which is what stopped the h1 pool
//! from re-dialling every request once a workload kept more than 64
//! exchanges open (measured at 400 streams in flight: ~28 000 backend
//! connections per benchmark cell). The cap is clamped to
//! [`IDLE_CEILING_PER_SERVER`] so a pathological workload cannot pin sockets
//! without limit. An idle expiry ([`DEFAULT_POOL_IDLE_TIMEOUT`]) still
//! releases what the burst left behind; excess and stale connections are
//! dropped, never queued without limit. A poisoned lock is recovered (never
//! panics), treating the pool as momentarily empty.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::BufReader;

use crate::proxy::{BoxRead, BoxWrite};

/// Idle floor per backend server: burst headroom even when no concurrency
/// was observed (a cold workload still keeps some keep-alive headroom).
pub const IDLE_FLOOR_PER_SERVER: usize = 64;

/// Idle ceiling per backend server: the adaptive cap never grows past this,
/// so one workload cannot pin an unbounded number of sockets and file
/// descriptors. Above it the pool falls back to the pre-existing behaviour
/// (the excess is dropped on check-in and re-dialled later).
pub const IDLE_CEILING_PER_SERVER: usize = 4096;

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

/// Idle queue of one server plus the peak concurrency observed on it.
#[derive(Default)]
struct ServerPool {
    idle: VecDeque<IdleConn>,
    /// Most exchanges the balancer ever reported in flight on this server
    /// (this one included), which is what the idle cap follows.
    peak_in_flight: usize,
}

/// Per-server idle queues, shared across listeners of the same backend.
pub struct Pool {
    inner: Mutex<HashMap<SocketAddr, ServerPool>>,
    /// Idle cap when no concurrency is observed (see
    /// [`IDLE_FLOOR_PER_SERVER`]).
    floor: usize,
    /// Hard cap the adaptive sizing never exceeds ([`IDLE_CEILING_PER_SERVER`]).
    ceiling: usize,
    idle_timeout: Duration,
}

impl Pool {
    /// Pool with an explicit floor and expiry (production uses the module
    /// defaults). The ceiling stays at [`IDLE_CEILING_PER_SERVER`].
    #[must_use]
    pub fn new(max_idle_per_server: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            floor: max_idle_per_server,
            ceiling: IDLE_CEILING_PER_SERVER.max(max_idle_per_server),
            idle_timeout,
        }
    }

    /// Production defaults: adaptive, bounded and expiring.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(IDLE_FLOOR_PER_SERVER, DEFAULT_POOL_IDLE_TIMEOUT)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, ServerPool>> {
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
        let queue = &mut inner.get_mut(addr)?.idle;
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

    /// Records how many exchanges are in flight on `addr` (this one
    /// included) when a connection is borrowed, pooled or freshly dialled.
    /// The idle cap follows the peak of that number: a connection that is
    /// handed out during a burst is parked at check-in, not dropped and
    /// re-dialled by the next wave.
    pub fn note_in_flight(&self, addr: SocketAddr, in_flight: usize) {
        let mut inner = self.lock();
        let entry = inner.entry(addr).or_default();
        entry.peak_in_flight = entry.peak_in_flight.max(in_flight);
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
        let entry = inner.entry(addr).or_default();
        let cap = entry.peak_in_flight.clamp(self.floor, self.ceiling);
        if entry.idle.len() >= cap {
            return;
        }
        entry.idle.push_back(IdleConn {
            read,
            write,
            idle_since: now,
        });
    }

    /// Idle connections held for `addr` (tests and diagnostics).
    #[must_use]
    pub fn idle_count(&self, addr: &SocketAddr) -> usize {
        self.lock().get(addr).map_or(0, |pool| pool.idle.len())
    }

    /// Closes and drops every idle connection held for `addr` (v0.8,
    /// ADR-0028): the server is being taken out for a patch window, so
    /// nothing of ours may stay parked on it. The observed peak is kept —
    /// the adaptive cap must not restart from the floor after a maintenance
    /// cycle. Returns how many connections were closed; closing again is a
    /// no-op that reports zero.
    pub fn close_idle(&self, addr: &SocketAddr) -> usize {
        let mut inner = self.lock();
        inner.get_mut(addr).map_or(0, |pool| {
            let closed = pool.idle.len();
            pool.idle.clear();
            closed
        })
    }

    /// Total idle connections held (diagnostics).
    #[must_use]
    pub fn idle_total(&self) -> usize {
        self.lock().values().map(|pool| pool.idle.len()).sum()
    }

    /// Peak concurrency recorded for `addr` (tests and diagnostics).
    #[must_use]
    pub fn peak_in_flight(&self, addr: &SocketAddr) -> usize {
        self.lock().get(addr).map_or(0, |pool| pool.peak_in_flight)
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
            .field("floor", &self.floor)
            .field("ceiling", &self.ceiling)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    /// The third element holds the far halves: the test must keep them
    /// bound for its whole duration (the pool owns the other side), and
    /// drop them at its end — a `mem::forget` here is a real leak that
    /// miri reports.
    fn pair() -> (BufReader<BoxRead>, BoxWrite, (BoxRead, BoxWrite)) {
        let (a, b) = duplex(64 * 1024);
        let (ra, wa) = tokio::io::split(a);
        let (rb, wb) = tokio::io::split(b);
        let read: BoxRead = Box::new(ra);
        let write: BoxWrite = Box::new(wa);
        let far: (BoxRead, BoxWrite) = (Box::new(rb), Box::new(wb));
        (BufReader::new(read), write, far)
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:9000".parse().expect("addr")
    }

    #[test]
    fn roundtrip_hands_back_a_clean_connection() {
        let pool = Pool::new(4, Duration::from_secs(60));
        let now = Instant::now();
        assert!(pool.checkout(&addr(), now).is_none());
        let (read, write, _far) = pair();
        pool.note_in_flight(addr(), 1);
        pool.checkin(addr(), read, write, now);
        assert_eq!(pool.idle_count(&addr()), 1);
        assert!(pool.checkout(&addr(), now).is_some());
        assert_eq!(pool.idle_count(&addr()), 0);
    }

    #[test]
    fn idle_cap_drops_excess_at_the_floor() {
        let pool = Pool::new(2, Duration::from_secs(60));
        let now = Instant::now();
        pool.note_in_flight(addr(), 1);
        for _ in 0..5 {
            let (read, write, _far) = pair();
            pool.checkin(addr(), read, write, now);
        }
        assert_eq!(pool.idle_count(&addr()), 2);
    }

    /// A burst of concurrent exchanges raises the idle cap to the peak the
    /// balancer reported: the connections that served the burst stay parked
    /// and are reused, instead of being dropped and re-dialled by the next
    /// wave (the churn measured at 400 streams in flight).
    #[test]
    fn idle_cap_follows_the_peak_in_flight() {
        let pool = Pool::with_defaults();
        let now = Instant::now();
        pool.note_in_flight(addr(), 400);
        for _ in 0..400 {
            let (read, write, _far) = pair();
            pool.checkin(addr(), read, write, now);
        }
        assert_eq!(
            pool.idle_count(&addr()),
            400,
            "400 exchanges in flight must keep 400 connections, not 64"
        );
    }

    /// The adaptive cap is clamped to the ceiling: an absurd concurrency
    /// report cannot pin sockets without bound.
    #[test]
    fn idle_cap_never_exceeds_the_ceiling() {
        let pool = Pool::with_defaults();
        let now = Instant::now();
        pool.note_in_flight(addr(), IDLE_CEILING_PER_SERVER + 100);
        for _ in 0..(IDLE_CEILING_PER_SERVER + 100) {
            let (read, write, _far) = pair();
            pool.checkin(addr(), read, write, now);
        }
        assert_eq!(pool.idle_count(&addr()), IDLE_CEILING_PER_SERVER);
    }

    #[test]
    fn stale_entries_are_never_handed_out() {
        let pool = Pool::new(4, Duration::from_millis(50));
        let (read, write, _far) = pair();
        pool.note_in_flight(addr(), 1);
        pool.checkin(addr(), read, write, Instant::now());
        std::thread::sleep(Duration::from_millis(80));
        assert!(pool.checkout(&addr(), Instant::now()).is_none());
        assert_eq!(pool.idle_count(&addr()), 0);
    }

    // `#[tokio::test]` starts the tokio reactor (mio `kqueue` FFI),
    // which miri cannot execute on macOS. The test runs in every normal
    // `cargo test`; only the miri pass skips it (repo convention).
    #[cfg_attr(
        miri,
        ignore = "needs the tokio reactor (mio kqueue FFI): miri does not support foreign functions on macOS"
    )]
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
    fn close_idle_drops_what_is_parked_and_keeps_the_peak() {
        let pool = Pool::with_defaults();
        let now = Instant::now();
        pool.note_in_flight(addr(), 7);
        for _ in 0..3 {
            let (read, write, _far) = pair();
            pool.checkin(addr(), read, write, now);
        }
        assert_eq!(pool.idle_count(&addr()), 3);
        assert_eq!(pool.close_idle(&addr()), 3, "it reports what it closed");
        assert_eq!(pool.idle_count(&addr()), 0);
        assert_eq!(
            pool.peak_in_flight(&addr()),
            7,
            "the adaptive cap keeps the peak: no cliff after a patch window"
        );
        assert_eq!(
            pool.close_idle(&addr()),
            0,
            "closing again is a no-op that reports zero"
        );
        // Another server's parked connections are untouched.
        let other: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        let (read, write, _far) = pair();
        pool.note_in_flight(other, 1);
        pool.checkin(other, read, write, now);
        pool.close_idle(&addr());
        assert_eq!(pool.idle_count(&other), 1);
    }

    #[test]
    fn servers_are_keyed_independently() {
        let pool = Pool::with_defaults();
        let now = Instant::now();
        let other: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        let (read, write, _far) = pair();
        pool.note_in_flight(addr(), 1);
        pool.checkin(addr(), read, write, now);
        assert!(pool.checkout(&other, now).is_none());
        assert!(pool.checkout(&addr(), now).is_some());
    }
}
