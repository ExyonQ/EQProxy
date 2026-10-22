//! TCP proxy: accept, connect to the backend and pump bytes with timeouts.
//!
//! Semantics (documented and tested):
//! - `maxconn` per listener: when full, the connection is **refused** (close
//!   immediately + counter); there are never unbounded queues (SPEC §7.3).
//! - `connect_timeout`: maximum to establish the backend connection
//!   (includes the TLS handshake to it).
//! - `idle_timeout`: per direction; with no bytes in that direction during
//!   the window, it closes with EOF towards its peer and `idle_timeouts`
//!   counts it.
//! - Graceful shutdown: stops accepting, live connections finish within
//!   `grace`; on expiry the process exits and the rest are closed.
//! - Hot reload (S-CFG-01): `serve_with_reloads` swaps the listeners of a
//!   validated config while serving. Fail-closed (bind before mutate),
//!   established connections drain with the config they were accepted
//!   with and the counters never reset (PP-03).
//! - `bind` is "all or nothing": when a listener cannot open, the
//!   others close and an error returns (resource preparation before
//!   activation, SPEC §7.2).
//!
//! Phase 2b: TLS termination (A11, handshake in the client phase), TLS to
//! backends (A12), weighted RR balancing (B1/B7) with TCP health checks
//! (B11) and PROXY protocol v1 send (A9). With no servers available:
//! HTTP → 503, TCP → close (counted in `no_available_server`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use eqproxy_core::{Metrics, Shutdown, ShutdownHandle};

use crate::backend_h2;
use crate::balancer::{ActiveGuard, Balance, Balancer, ResolvedServer};
use crate::dns::{self, DnsSettings, Resolving, SystemResolver};
use crate::health::{self, HealthCheck};
use crate::http1;
use crate::http2;
use crate::pool::Pool;
use crate::proxy_proto::{self, ProxyProtocolMode};
use crate::tls::{self, ClientTls};

/// Per-direction buffer (SPEC §7.3: 16 KiB).
pub const READ_BUF: usize = 16 * 1024;

/// Reader of an already-split stream half (TCP or TLS).
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
/// Writer of an already-split stream half (TCP or TLS).
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Whole client stream before it is split (TCP or TLS): HTTP/2 needs one
/// object that both reads and writes, HTTP/1.1 works on split halves.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// Proxy mode of a listener (A1 `Tcp`, A2 `Http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// TCP tunnel without interpretation.
    #[default]
    Tcp,
    /// HTTP/1.1 proxy with strict framing.
    Http,
}

/// Resolved backend: servers, balancing, TLS and PROXY protocol.
///
/// Shared across listeners referencing the same backend (a single
/// [`Balancer`] and a single health machine per backend).
#[derive(Debug)]
pub struct ResolvedBackend {
    pub name: String,
    pub servers: Vec<ResolvedServer>,
    pub proxy_protocol: ProxyProtocolMode,
    pub tls: Option<ClientTls>,
    pub health_check: Option<HealthCheck>,
    pub balancer: Arc<Balancer>,
    /// Per-backend keep-alive pool (A16), shared across listeners.
    pub pool: Pool,
    /// Bounded wait queue when no server is up (B-H7). `None` = reject now.
    pub queue: Option<WaitQueue>,
    /// Connect-phase retry policy (B-H7).
    pub retries: RetryPolicy,
    /// Session affinity (B-H8/B-N13/B-I8).
    pub affinity: Option<ResolvedAffinity>,
    /// DNS re-resolution settings (B-H13/B-N18/B-E15) for
    /// `HOSTNAME:PORT` servers.
    pub dns: DnsSettings,
}

impl ResolvedBackend {
    /// Single-server backend with default settings (compat 0.1.0).
    #[must_use]
    pub fn single(name: impl Into<String>, server: impl Into<crate::ServerAddr>) -> Self {
        Self::new(
            name,
            vec![ResolvedServer {
                addr: server.into(),
                weight: 1,
            }],
            3,
            2,
        )
    }

    /// Backend with weighted servers and `fall`/`rise` thresholds (B11).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        servers: Vec<ResolvedServer>,
        fall: u32,
        rise: u32,
    ) -> Self {
        Self {
            name: name.into(),
            balancer: Arc::new(Balancer::new(servers.clone(), fall, rise)),
            servers,
            proxy_protocol: ProxyProtocolMode::None,
            tls: None,
            health_check: None,
            pool: Pool::with_defaults(),
            queue: None,
            retries: RetryPolicy::default(),
            affinity: None,
            dns: DnsSettings::default(),
        }
    }

    /// Balancing algorithm and slow start (B-H5/B-N12/B-E6 + B14):
    /// `leastconn` picks by `active / effective weight`, and after every
    /// transition to operational the effective weight ramps linearly from
    /// ~0 to `weight` over `slow_start` (dynamic weighting).
    #[must_use]
    pub fn with_balance(mut self, algorithm: Balance, slow_start: Duration) -> Self {
        let (fall, rise) = self.balancer.thresholds();
        self.balancer = Arc::new(Balancer::with_options(
            self.servers.clone(),
            fall,
            rise,
            algorithm,
            slow_start,
        ));
        self
    }

    /// Session affinity (B-H8/B-N13/B-I8).
    #[must_use]
    pub fn with_affinity(mut self, affinity: ResolvedAffinity) -> Self {
        self.affinity = Some(affinity);
        self
    }

    /// PROXY protocol v1 send to the servers (A9).
    #[must_use]
    pub fn with_proxy_protocol(mut self, mode: ProxyProtocolMode) -> Self {
        self.proxy_protocol = mode;
        self
    }

    /// TLS to the servers (A12).
    #[must_use]
    pub fn with_tls(mut self, tls: ClientTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Active TCP health check (B11).
    #[must_use]
    pub fn with_health_check(mut self, check: HealthCheck) -> Self {
        self.health_check = Some(check);
        self
    }

    /// DNS re-resolution rate (B-H13/B-N18/B-E15): `Duration::ZERO`
    /// resolves `HOSTNAME:PORT` servers once at startup; anything higher
    /// re-resolves them periodically in the background.
    #[must_use]
    pub fn with_resolve_interval(mut self, interval: Duration) -> Self {
        self.dns.interval = interval;
        self
    }

    /// Bounded attempt per resolution (a hung DNS cannot stall the
    /// cycle; default [`crate::dns::RESOLVE_TIMEOUT`]).
    #[must_use]
    pub fn with_resolve_timeout(mut self, timeout: Duration) -> Self {
        self.dns.timeout = timeout;
        self
    }

    /// Bounded wait queue when no server is up (B-H7).
    #[must_use]
    pub fn with_queue(mut self, settings: QueueSettings) -> Self {
        self.queue = Some(WaitQueue::new(settings));
        self
    }

    /// Connect-phase retry policy (B-H7).
    #[must_use]
    pub fn with_retries(mut self, retries: RetryPolicy) -> Self {
        self.retries = retries;
        self
    }
}

/// Rewrite applied to the forwarded request (v0.6 slice 2).
#[derive(Debug, Clone)]
pub struct ResolvedRewrite {
    /// The rule's matched `path_prefix`: what `path_prefix_rewrite` replaces.
    pub matched_prefix: String,
    /// Literal replacement for the matched prefix (`""` strips it).
    pub path_prefix_rewrite: Option<String>,
    /// Exact upstream `Host` value.
    pub host_rewrite: Option<String>,
}

/// CORS policy of a matched rule (B-I10): preflight `OPTIONS` answered
/// locally, CORS headers on every response of the rule.
#[derive(Debug, Clone)]
pub struct ResolvedCors {
    /// Exact allowed origin.
    pub allow_origin: String,
    /// `Access-Control-Allow-Methods`.
    pub allow_methods: String,
    /// `Access-Control-Allow-Headers` (omitted when `None`).
    pub allow_headers: Option<String>,
    /// `Access-Control-Expose-Headers` (omitted when `None`).
    pub expose_headers: Option<String>,
    /// Preflight cache time (omitted when zero).
    pub max_age: Duration,
    /// `Access-Control-Allow-Credentials: true`.
    pub allow_credentials: bool,
}

/// Authentication of a matched rule (B-N9/B-I9): HTTP Basic against
/// htpasswd users checked locally first, then the external subrequest
/// (`auth-url`; nginx `auth_request`). Fail closed everywhere.
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    /// External auth subrequest target (`http://HOST[:PORT][/PATH]`).
    pub url: Option<eqproxy_core::auth::AuthUrl>,
    /// htpasswd-format users (`type = "basic"`).
    pub basic: Option<Arc<eqproxy_core::auth::BasicUsers>>,
    /// `WWW-Authenticate` realm (default `"EQProxy"`).
    pub realm: String,
}

/// Session affinity of a backend (B-H8/B-N13/B-I8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityMode {
    /// Sticky cookie inserted by the proxy (HAProxy `cookie insert`).
    Cookie,
    /// Hash of the client IP (nginx `ip_hash`).
    Source,
}

/// Resolved session affinity: how a client is pinned to its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAffinity {
    pub mode: AffinityMode,
    /// Cookie name (Cookie mode only).
    pub cookie: String,
}

/// Token-bucket rate limiter (B-N8/B-I7/B-E16), shared by the requests
/// of one rule: `burst` tokens of capacity, refilled `rate` per `per`
/// window. Buckets are per client IP and in-memory only — no network in
/// the hot path (Q6); over the limit the caller rejects explicitly.
/// `ponytail:` plain map + lazy prune by idleness (60s) at 64k tracked
/// IPs — a real LRU if per-IP limits ever need more.
#[derive(Debug)]
pub struct RateLimiter {
    rate: u32,
    per: Duration,
    burst: u32,
    per_second: f64,
    capacity: f64,
    buckets: std::sync::Mutex<HashMap<IpAddr, TokenBucket>>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: tokio::time::Instant,
}

const MAX_TRACKED_BUCKETS: usize = 65_536;
const BUCKET_IDLE_PRUNE: Duration = Duration::from_secs(60);

impl RateLimiter {
    /// `rate` tokens per `per` window, `burst` capacity.
    pub fn new(rate: u32, per: Duration, burst: u32) -> Self {
        Self {
            rate,
            per,
            burst,
            per_second: f64::from(rate) / per.as_secs_f64(),
            capacity: f64::from(burst),
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Consumes one token for `ip`; `false` = over the limit (429).
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let now = tokio::time::Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        if buckets.len() >= MAX_TRACKED_BUCKETS {
            buckets.retain(|_, bucket| now.duration_since(bucket.last) < BUCKET_IDLE_PRUNE);
        }
        let bucket = buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// One-line summary for `config explain`.
    pub fn describe(&self) -> String {
        format!(
            "rate limit {}/{}s burst {}",
            self.rate,
            self.per.as_secs(),
            self.burst
        )
    }
}

/// Mirror policy of a matched rule (B-H3; Envoy
/// `request_mirror_policies`): a copy of the request goes to another
/// backend, fire-and-forget — its response never reaches the client and
/// a mirror failure never changes the client's answer.
#[derive(Debug)]
pub struct MirrorPolicy {
    /// Backend that receives the copy.
    pub backend: Arc<ResolvedBackend>,
    /// Percentage of the matching requests (1..=100).
    pub percentage: u32,
    /// Sampling position. Deterministic: every block of 100 requests
    /// mirrors exactly `percentage` of them (tests and operations are
    /// reproducible; Envoy samples randomly — documented difference).
    counter: AtomicU64,
}

impl MirrorPolicy {
    /// Builds the policy for a backend and a percentage (1..=100).
    #[must_use]
    pub fn new(backend: Arc<ResolvedBackend>, percentage: u32) -> Self {
        Self {
            backend,
            percentage,
            counter: AtomicU64::new(0),
        }
    }

    /// `true` when this request must be mirrored.
    #[must_use]
    pub fn sample(&self) -> bool {
        let position = self.counter.fetch_add(1, Ordering::Relaxed);
        (position % 100) < u64::from(self.percentage)
    }

    /// One-line summary for `config explain`.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("mirror {}% -> {}", self.percentage, self.backend.name)
    }
}

/// Header actions of a matched rule (B-N4/B-I4/B-E17): request-side
/// `set`/`add`/`del` plus `response` additions. Values are templates
/// (`$remote_addr`, `$host`, `$scheme`), rendered per request.
#[derive(Debug, Clone, Default)]
pub struct ResolvedHeaders {
    /// Replace (or insert) these request headers.
    pub set: Vec<(String, String)>,
    /// Append these request headers, keeping the client's values.
    pub add: Vec<(String, String)>,
    /// Remove these request headers before forwarding.
    pub del: Vec<String>,
    /// Append these headers to the response the client sees.
    pub response: Vec<(String, String)>,
    /// CORS policy of the rule (B-I10).
    pub cors: Option<ResolvedCors>,
    /// Rate limit of the rule (B-N8/B-I7/B-E16), whatever the action.
    pub rate_limit: Option<Arc<RateLimiter>>,
    /// Authentication of the rule (B-N9/B-I9), whatever the action.
    pub auth: Option<ResolvedAuth>,
    /// Mirror policy of the rule (B-H3), forwarding actions only.
    pub mirror: Option<Arc<MirrorPolicy>>,
}

impl<'a> RouteDecision<'a> {
    /// The matched rule's rate limiter (B-N8), whatever the action.
    pub fn rate_limiter(&self) -> Option<&Arc<RateLimiter>> {
        match self {
            RouteDecision::Proxy { headers, .. }
            | RouteDecision::Redirect { headers, .. }
            | RouteDecision::Direct { headers, .. } => headers
                .as_ref()
                .and_then(|actions| actions.rate_limit.as_ref()),
        }
    }

    /// The matched rule's mirror policy (B-H3), when it has one.
    pub fn mirror(&self) -> Option<&Arc<MirrorPolicy>> {
        match self {
            RouteDecision::Proxy { headers, .. }
            | RouteDecision::Redirect { headers, .. }
            | RouteDecision::Direct { headers, .. } => {
                headers.and_then(|actions| actions.mirror.as_ref())
            }
        }
    }

    /// The matched rule's authentication gate (B-N9), whatever the action.
    pub fn auth(&self) -> Option<&ResolvedAuth> {
        match self {
            RouteDecision::Proxy { headers, .. }
            | RouteDecision::Redirect { headers, .. }
            | RouteDecision::Direct { headers, .. } => {
                headers.as_ref().and_then(|actions| actions.auth.as_ref())
            }
        }
    }
}

/// Request key of a hash policy (B-H3; Envoy `hash_policy` keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashKey {
    /// Client IP (`connection_properties.source_ip`).
    Source,
    /// Request path, query excluded.
    Path,
    /// Host header, lowercased and port-free.
    Host,
    /// Cookie value by name (RFC 6265 parsing).
    Cookie(String),
    /// First value of a request header by name.
    Header(String),
}

/// Hash policy of a split (B-H3; Envoy `hash_policy` + `RING_HASH`): the
/// target is chosen by a hash of the request key instead of the weighted
/// rotation, so the same key keeps its target while targets come and go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashPolicy {
    /// Key extracted from the request.
    pub key: HashKey,
}

impl HashPolicy {
    /// Parses a `hash_policy.key` string (B-H3): `source`, `path`, `host`,
    /// `cookie:NAME` or `header:NAME`. The config gate validates the
    /// same grammar (`eqproxy-config`), so a failure here means the two
    /// halves disagree — an error, never a silent fallback.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let key = raw.trim();
        let kind = match key {
            "source" => HashKey::Source,
            "path" => HashKey::Path,
            "host" => HashKey::Host,
            _ => match key.split_once(':') {
                Some((kind, name)) if kind == "cookie" || kind == "header" => {
                    let name = name.trim();
                    if name.is_empty() {
                        return Err(format!("{kind}: needs a name after the colon"));
                    }
                    if kind == "cookie" {
                        HashKey::Cookie(name.to_owned())
                    } else {
                        HashKey::Header(name.to_owned())
                    }
                }
                _ => {
                    return Err(format!(
                        "unknown key {key:?}: expected source, path, host, cookie:NAME or header:NAME"
                    ));
                }
            },
        };
        Ok(Self { key: kind })
    }

    /// The key of this request; `None` when the request does not carry it
    /// (absent cookie/header) — the caller falls back to the rotation.
    #[must_use]
    pub fn key_for(&self, facts: &eqproxy_core::rules::RequestFacts<'_>) -> Option<String> {
        match &self.key {
            HashKey::Source => Some(facts.peer.to_string()),
            HashKey::Path => Some(facts.path.to_owned()),
            HashKey::Host => Some(eqproxy_core::rules::host_key(facts.host)),
            HashKey::Cookie(name) => {
                eqproxy_core::rules::cookie_value(facts.headers, name).map(str::to_owned)
            }
            HashKey::Header(name) => facts
                .headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone()),
        }
    }

    /// One-line summary for `config explain`.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.key {
            HashKey::Source => "hash source".to_owned(),
            HashKey::Path => "hash path".to_owned(),
            HashKey::Host => "hash host".to_owned(),
            HashKey::Cookie(name) => format!("hash cookie:{name}"),
            HashKey::Header(name) => format!("hash header:{name}"),
        }
    }
}

/// One weighted target of a [`SplitTargets`] (B-I11).
#[derive(Debug, Clone)]
pub struct SplitTarget {
    /// Backend receiving this share of the requests.
    pub backend: Arc<ResolvedBackend>,
    /// Share weight (0 = disabled; the config gate requires one > 0).
    pub weight: u32,
}

/// Weighted traffic split across backends (B-I11; Envoy
/// `weighted_clusters`, ingress-nginx `canary-weight`).
///
/// Selection is **smooth weighted round-robin** over the targets
/// (nginx's algorithm): deterministic per request order, weights
/// describe exact shares in rotation (3:1 = 3 of every 4 requests),
/// and a `weight = 0` target is never picked (canary rollback without
/// touching the rest). Invariant: at least one target has weight > 0
/// (the config gate rejects an all-zero split; `pick` then serves the
/// first target by construction, never a panic).
#[derive(Debug)]
pub struct SplitTargets {
    targets: Vec<SplitTarget>,
    /// Per-target current weight (SWRR state; same shape as the
    /// balancer's, one lock per pick — no state in the request itself).
    current: std::sync::Mutex<Vec<i64>>,
}

impl SplitTargets {
    /// Builds the split (target order preserved = tie-break order).
    #[must_use]
    pub fn new(targets: Vec<SplitTarget>) -> Self {
        let current = std::sync::Mutex::new(vec![0_i64; targets.len()]);
        Self { targets, current }
    }

    /// Picks the backend for one request (smooth WRR).
    #[must_use]
    pub fn pick(&self) -> &Arc<ResolvedBackend> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert_eq!(current.len(), self.targets.len());
        let mut total: i64 = 0;
        for (i, target) in self.targets.iter().enumerate() {
            current[i] += i64::from(target.weight);
            total += i64::from(target.weight);
        }
        let chosen = current
            .iter()
            .enumerate()
            .max_by_key(|(i, weight)| (*weight, std::cmp::Reverse(*i)))
            .map_or(0, |(i, _)| i);
        current[chosen] -= total;
        &self.targets[chosen].backend
    }

    /// Picks the backend for one request **by key** (B-H3, Envoy
    /// `hash_policy`): weighted rendezvous hashing (HRW) over the active
    /// targets.
    ///
    /// Properties (documented, pinned by tests): deterministic (the same
    /// key always lands on the same target while the set is unchanged),
    /// weighted (`weight` sets the share of keys), and consistent
    /// (removing or disabling one target only remaps the keys it owned —
    /// the other keys keep their target). No state: nothing to reset.
    ///
    /// `None` when no target is active; the caller falls back to the plain
    /// rotation (the config gate rejects an all-zero split anyway, so this
    /// is the panic-free shape of an impossible state, never an index).
    #[must_use]
    pub fn pick_hashed(&self, key: &str) -> Option<&Arc<ResolvedBackend>> {
        let mut best: Option<(f64, &Arc<ResolvedBackend>)> = None;
        for target in &self.targets {
            if target.weight == 0 {
                continue;
            }
            // FNV-1a alone leaves too much of the top 53 bits untouched by
            // short keys that differ only in their last characters, so the
            // 64-bit result is passed through the splitmix64 finalizer
            // before taking bits: without it every key of a run landed on
            // the same target (caught by the distribution test).
            let hash = mix64(fnv1a(&target.backend.name, key));
            // 53 random-ish bits → (0, 1); weighted rendezvous score
            // `weight / -ln(u)` keeps the share proportional to weight.
            let u = ((hash >> 11) as f64 + 0.5) / (1_u64 << 53) as f64;
            // `u` is at least 2^-53, so `-ln(u)` is at least ~36 and the
            // division can never be zero: the guard is the explicit proof
            // of that, not a behavioural change.
            let spread = -u.ln();
            // `u` is finite and positive, so the spread is finite and
            // positive too; anything else (NaN) skips the target instead of
            // poisoning the comparison.
            if spread.is_nan() || spread <= 0.0 {
                continue;
            }
            let score = f64::from(target.weight) / spread;
            if best.as_ref().is_none_or(|(best, _)| score > *best) {
                best = Some((score, &target.backend));
            }
        }
        best.map(|(_, backend)| backend)
    }

    /// The configured targets (explain and `all_backends`).
    #[must_use]
    pub fn targets(&self) -> &[SplitTarget] {
        &self.targets
    }
}

/// splitmix64 finalizer: full avalanche of a 64-bit value (the cheap
/// mixing step of the same-named PRNG).
const fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// FNV-1a over `(target, key)`: stable across processes and runs (a
/// sticky key must survive restarts), cheap, and independent of the
/// Rust std hasher's per-process seed. Not cryptographic: keys are never
/// adversarial input for a hash-flooding attack here (one target list of
/// bounded size) — a hostile client could still aim a key at a target,
/// exactly like Envoy's ring hash; the gate is the key being the client's
/// own data.
fn fnv1a(target: &str, key: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in target
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .chain(key.as_bytes().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Action of a matched routing rule (v0.6 slice 2): route to a backend
/// (optionally rewriting the request), split across backends (B-I11),
/// or answer locally.
#[derive(Debug, Clone)]
pub enum RouteAction {
    /// Proxy the request to this backend.
    Backend {
        backend: Arc<ResolvedBackend>,
        rewrite: Option<ResolvedRewrite>,
    },
    /// Proxy to the weighted target the split picks this request (B-I11);
    /// with a hash policy the pick is keyed instead of rotated (B-H3).
    Split {
        targets: Arc<SplitTargets>,
        rewrite: Option<ResolvedRewrite>,
        hash: Option<HashPolicy>,
    },
    /// Answer locally: 3xx + `Location` (template rendered per request).
    Redirect { status: u16, location: String },
    /// Answer locally: the configured response, no backend contacted.
    Direct {
        status: u16,
        content_type: String,
        body: String,
    },
}

/// Borrowed view of one routing decision (v0.6 slice 2).
#[derive(Debug)]
pub enum RouteDecision<'a> {
    /// Proxy to this backend, optionally rewriting the forwarded head.
    Proxy {
        backend: &'a Arc<ResolvedBackend>,
        rewrite: Option<&'a ResolvedRewrite>,
        headers: Option<&'a ResolvedHeaders>,
    },
    /// Serve a local 3xx with a `Location` template.
    Redirect {
        status: u16,
        location: &'a str,
        headers: Option<&'a ResolvedHeaders>,
    },
    /// Serve a local response.
    Direct {
        status: u16,
        content_type: &'a str,
        body: &'a str,
        headers: Option<&'a ResolvedHeaders>,
    },
}

/// One compiled routing rule with its action (v0.6, B-H4).
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Compiled match conditions (ordered evaluation, first match wins).
    pub rule: eqproxy_core::rules::Rule,
    /// What a matching request triggers.
    pub action: RouteAction,
    /// Header actions of the matched rule (B-N4/B-I4/B-E17).
    pub headers: Option<ResolvedHeaders>,
}

/// Resolved listener (already-validated config: parsed addresses, sound refs).
///
/// `#[non_exhaustive]`: adding fields is not a breaking change for
/// consumers (ADR-0004 semver policy). Built with [`Self::new`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResolvedListener {
    pub name: String,
    pub listen: SocketAddr,
    pub backend_name: String,
    /// Default backend (servers + balancing + TLS + PROXY): the fallback
    /// when no rule matches (and the only backend in `tcp` mode).
    pub backend: Arc<ResolvedBackend>,
    /// Ordered routing rules (`http` only, B-H3/B-H4): first match wins.
    pub routes: Vec<ResolvedRoute>,
    pub mode: ProxyMode,
    pub maxconn: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Client phase (`http` only): request head. Also covers the
    /// client TLS handshake (A11).
    pub client_header_timeout: Duration,
    /// Server phase (`http` only): response head.
    pub server_header_timeout: Duration,
    /// Total duration cap for one forwarded exchange (`http` only;
    /// `ZERO` disables): `max_stream_duration` (B-H11/B-E12).
    pub max_stream_duration: Duration,
    /// TLS termination at this listener (A11). `None` = plain TCP.
    pub server_tls: Option<tls::ServerTls>,
    /// PROXY v1 reception with origin allowlist (B-H9/B-E10): strict
    /// front door — every connection must come from an allowlisted
    /// origin and carry a valid PROXY v1 line.
    pub proxy_receive: Option<eqproxy_core::expectation::IpAllowlist>,
    /// `X-Forwarded-For`/`X-Real-IP` handling (B-N4).
    pub forwarded_headers: ForwardedMode,
    /// Custom response for the "no server available" class (C9).
    pub local_response: Option<LocalResponse>,
    /// Data maps in force (C10/PP-02): what `map` rule conditions
    /// consult; the file watchers swap their data in hot.
    pub maps: Arc<eqproxy_core::maps::MapRegistry>,
}

impl ResolvedListener {
    /// Builds a listener with a single-server backend (compat 0.1.0).
    /// Use [`Self::with_backend`] for balancing/TLS/PROXY and
    /// [`Self::with_server_tls`] for TLS termination.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        listen: SocketAddr,
        backend_name: impl Into<String>,
        server: impl Into<crate::ServerAddr>,
        mode: ProxyMode,
        maxconn: u32,
        connect_timeout: Duration,
        idle_timeout: Duration,
        client_header_timeout: Duration,
        server_header_timeout: Duration,
    ) -> Self {
        let backend_name = backend_name.into();
        Self {
            name: name.into(),
            listen,
            backend: Arc::new(ResolvedBackend::single(backend_name.clone(), server.into())),
            routes: Vec::new(),
            backend_name,
            mode,
            maxconn,
            connect_timeout,
            idle_timeout,
            client_header_timeout,
            server_header_timeout,
            max_stream_duration: Duration::ZERO,
            server_tls: None,
            proxy_receive: None,
            forwarded_headers: ForwardedMode::Off,
            local_response: None,
            maps: Arc::new(eqproxy_core::maps::MapRegistry::new()),
        }
    }

    /// Replaces the backend with a full one (multi-server, TLS, PROXY, …).
    #[must_use]
    pub fn with_backend(mut self, backend: Arc<ResolvedBackend>) -> Self {
        self.backend_name = backend.name.clone();
        self.backend = backend;
        self
    }

    /// Installs the ordered routing rules (`http` only, B-H3/B-H4).
    #[must_use]
    pub fn with_routes(mut self, routes: Vec<ResolvedRoute>) -> Self {
        self.routes = routes;
        self
    }

    /// Decision for one request: first matching rule wins, the default
    /// backend is the fallback (per-request: keep-alive connections may
    /// route each exchange differently).
    #[must_use]
    pub fn decide(&self, facts: &eqproxy_core::rules::RequestFacts<'_>) -> RouteDecision<'_> {
        self.routes
            .iter()
            .find(|route| route.rule.matches(facts))
            .map_or(
                RouteDecision::Proxy {
                    backend: &self.backend,
                    rewrite: None,
                    headers: None,
                },
                |route| {
                    let headers = route.headers.as_ref();
                    match &route.action {
                        RouteAction::Backend { backend, rewrite } => RouteDecision::Proxy {
                            backend,
                            rewrite: rewrite.as_ref(),
                            headers,
                        },
                        RouteAction::Split {
                            targets,
                            rewrite,
                            hash,
                        } => {
                            // B-H3: with a hash policy the target follows
                            // the request key; a request without the key
                            // falls back to the weighted rotation.
                            let backend = hash
                                .as_ref()
                                .and_then(|policy| policy.key_for(facts))
                                .and_then(|key| targets.pick_hashed(&key))
                                .unwrap_or_else(|| targets.pick());
                            RouteDecision::Proxy {
                                backend,
                                rewrite: rewrite.as_ref(),
                                headers,
                            }
                        }
                        RouteAction::Redirect { status, location } => RouteDecision::Redirect {
                            status: *status,
                            location,
                            headers,
                        },
                        RouteAction::Direct {
                            status,
                            content_type,
                            body,
                        } => RouteDecision::Direct {
                            status: *status,
                            content_type,
                            body,
                            headers,
                        },
                    }
                },
            )
    }

    /// Every distinct backend this listener can route to (default +
    /// rule actions of the forwarding kind: `use_backend` and `split`).
    pub fn all_backends(&self) -> impl Iterator<Item = &Arc<ResolvedBackend>> {
        std::iter::once(&self.backend).chain(self.routes.iter().flat_map(|route| {
            let mut backends: Vec<&Arc<ResolvedBackend>> = Vec::new();
            match &route.action {
                RouteAction::Backend { backend, .. } => backends.push(backend),
                RouteAction::Split { targets, .. } => {
                    backends.extend(targets.targets().iter().map(|t| &t.backend));
                }
                RouteAction::Redirect { .. } | RouteAction::Direct { .. } => {}
            }
            backends
        }))
    }

    /// Enables TLS termination on the listener (A11).
    #[must_use]
    pub fn with_server_tls(mut self, server_tls: tls::ServerTls) -> Self {
        self.server_tls = Some(server_tls);
        self
    }

    /// PROXY v1 reception with origin allowlist (B-H9/B-E10).
    #[must_use]
    pub fn with_proxy_receive(mut self, allowlist: eqproxy_core::expectation::IpAllowlist) -> Self {
        self.proxy_receive = Some(allowlist);
        self
    }

    /// `X-Forwarded-For`/`X-Real-IP` handling (B-N4).
    #[must_use]
    pub fn with_forwarded_headers(mut self, mode: ForwardedMode) -> Self {
        self.forwarded_headers = mode;
        self
    }

    /// Total duration cap for one forwarded exchange (`ZERO` disables).
    #[must_use]
    pub fn with_max_stream_duration(mut self, max_stream_duration: Duration) -> Self {
        self.max_stream_duration = max_stream_duration;
        self
    }

    /// Custom "no server available" response (C9).
    #[must_use]
    pub fn with_local_response(mut self, local: LocalResponse) -> Self {
        self.local_response = Some(local);
        self
    }

    /// Data maps consulted by `map` rule conditions (C10/PP-02).
    #[must_use]
    pub fn with_maps(mut self, maps: Arc<eqproxy_core::maps::MapRegistry>) -> Self {
        self.maps = maps;
        self
    }
}

/// Dataplane activation error (startup or hot swap).
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not listen on {addr} (listener \"{name}\"): {source}")]
    Bind {
        name: String,
        addr: SocketAddr,
        source: io::Error,
    },
    #[error("listener \"{name}\" uses {addr}, already used by another listener")]
    DuplicateListener { name: String, addr: SocketAddr },
}

/// Why the stream to the backend could not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    /// All servers are down or drained (HTTP → 503, TCP → close).
    NoServer,
    /// The chosen server refused the connection/handshake (HTTP → 502).
    Connect,
    /// The bounded backend queue is full (B-H7): explicit rejection
    /// (HTTP → 503, TCP → close; counted in `queue_full`).
    QueueFull,
    /// The bounded backend queue wait expired (B-H7; HTTP → 503).
    QueueTimeout,
}

/// Bounded wait queue settings (B-H7): wait for a server when none is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSettings {
    /// Maximum waiters (`MAX_QUEUE` budget); admission is capped.
    pub maxqueue: u32,
    /// Maximum wait in the queue.
    pub timeout: Duration,
}

/// Bounded wait queue (B-H7): never more than `maxqueue` waiters, never
/// unbounded waits (SPEC §7.3). Full queue = explicit rejection.
#[derive(Debug)]
pub struct WaitQueue {
    /// Settings (rendered in `config plan`).
    pub settings: QueueSettings,
    slots: Arc<tokio::sync::Semaphore>,
}

impl WaitQueue {
    #[must_use]
    pub fn new(settings: QueueSettings) -> Self {
        Self {
            settings,
            slots: Arc::new(tokio::sync::Semaphore::new(settings.maxqueue as usize)),
        }
    }

    /// Admission for one waiter; `None` when the queue is full.
    fn enter(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }
}

/// Connect-phase retry policy (B-H7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryPolicy {
    /// Extra dials after the first failure (0 = disabled; max 5).
    pub max: u32,
    /// Non-idempotent exchanges may retry (explicit opt-in).
    pub non_idempotent: bool,
}

impl RetryPolicy {
    /// Is a redial allowed for this exchange?
    ///
    /// Documented rule (B-H7): only idempotent exchanges unless
    /// `non_idempotent` opts in. v0.5 retries cover connect-phase
    /// failures only (nothing was sent to any backend yet).
    #[must_use]
    pub fn allows(self, idempotent: bool) -> bool {
        self.max > 0 && (idempotent || self.non_idempotent)
    }
}

/// What the caller knows about the exchange for retry safety (B-H7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryContext {
    /// The exchange is safe to replay (idempotent request).
    pub idempotent: bool,
}

impl RetryContext {
    /// Idempotent exchange (RFC 9110 method).
    #[must_use]
    pub const fn idempotent() -> Self {
        Self { idempotent: true }
    }

    /// Non-idempotent exchange (or protocol without replay safety).
    #[must_use]
    pub const fn non_idempotent() -> Self {
        Self { idempotent: false }
    }
}

/// `X-Forwarded-For`/`X-Real-IP` handling (B-N4 first step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedMode {
    /// No forwarded headers (default; explicit opt-in).
    #[default]
    Off,
    /// Append the client address to `X-Forwarded-For` (creating it when
    /// absent); `X-Real-IP` only when absent.
    Append,
    /// Replace `X-Forwarded-For` and `X-Real-IP` with the client address.
    Replace,
}

/// Custom response for the "no server available" class (C9 minimal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    /// Status code (400-599).
    pub status: u16,
    /// Content-Type of the body.
    pub content_type: String,
    /// Response body (bounded by config validation).
    pub body: String,
}

/// Current configuration of one listener, shared between its accept loop
/// (read per accept) and the hot swap (write). Established connections
/// keep the `ResolvedListener` they were accepted with (drain).
type SharedCfg = Arc<RwLock<Arc<ResolvedListener>>>;

/// The config in force right now (poison-recovered lock).
fn current_cfg(shared: &SharedCfg) -> Arc<ResolvedListener> {
    Arc::clone(
        &shared
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// One live listener: socket + accept loop + the config that new
/// connections see. Dropping it stops the accept loop (RAII).
struct Entry {
    /// Config address (swap key together with the name; `:0` keeps its
    /// resolved ephemeral socket across reloads).
    listen: SocketAddr,
    /// Real bound address (after `:0` resolution).
    local: SocketAddr,
    cfg: SharedCfg,
    stop: ShutdownHandle,
    task: JoinHandle<()>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.stop.trigger();
    }
}

/// What a hot swap changed (logged; rendering unit-tested).
/// A rebind (same name, new address) counts as removed + added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapSummary {
    /// Kept socket (same name and address): only the config changed.
    pub kept: usize,
    /// Listeners started.
    pub added: usize,
    /// Listeners stopped.
    pub removed: usize,
}

impl std::fmt::Display for SwapSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "listeners kept={} added={} removed={}",
            self.kept, self.added, self.removed
        )
    }
}

/// Dataplane with all sockets open and their accept loops running.
pub struct BoundProxy {
    entries: Vec<Entry>,
    metrics: Arc<Metrics>,
    /// Background tasks: active health checks (B11) and the DNS
    /// resolver (B-H13/B-N18/B-E15), restarted together on reload.
    bg_tasks: JoinSet<()>,
    bg_stop: ShutdownHandle,
    /// DNS resolver seam: [`SystemResolver`] in production, injectable
    /// in tests (never the request path: resolution is always async).
    resolver: Arc<dyn Resolving>,
}

impl std::fmt::Debug for BoundProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundProxy")
            .field("listeners", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Opens all listeners and starts their accept loops. Fails whole when
/// any one cannot open (SPEC §7.2): the already-opened ones close and an
/// error returns — never partially started.
pub async fn bind(
    listeners: Vec<ResolvedListener>,
    metrics: Arc<Metrics>,
) -> Result<BoundProxy, ProxyError> {
    let mut entries = Vec::with_capacity(listeners.len());
    for cfg in listeners {
        let name = cfg.name.clone();
        let addr = cfg.listen;
        // On error `entries` drops: its Drop impls stop the loops opened
        // so far (all-or-nothing).
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ProxyError::Bind { name, addr, source })?;
        entries.push(make_entry(cfg, listener, Arc::clone(&metrics)));
    }
    let (bg_stop, _bg_shutdown) = eqproxy_core::shutdown::channel();
    let mut proxy = BoundProxy {
        entries,
        metrics,
        bg_tasks: JoinSet::new(),
        bg_stop,
        resolver: Arc::new(SystemResolver),
    };
    proxy.spawn_background();
    Ok(proxy)
}

impl BoundProxy {
    /// Replaces the DNS resolver (B-H13 test seam): call before
    /// [`serve`](Self::serve). Production keeps [`SystemResolver`].
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolving>) -> Self {
        self.resolver = resolver;
        self.spawn_background();
        self
    }
}

/// One entry: socket + shared config + its accept loop task.
fn make_entry(cfg: ResolvedListener, listener: TcpListener, metrics: Arc<Metrics>) -> Entry {
    let listen = cfg.listen;
    let local = listener.local_addr().unwrap_or(listen);
    let name = cfg.name.clone();
    let listener = Arc::new(listener);
    let shared: SharedCfg = Arc::new(RwLock::new(Arc::new(cfg)));
    let (stop, shutdown) = eqproxy_core::shutdown::channel();
    let task = tokio::spawn(accept_loop(
        Arc::clone(&listener),
        Arc::clone(&shared),
        name,
        metrics,
        shutdown,
    ));
    Entry {
        listen,
        local,
        cfg: shared,
        stop,
        task,
    }
}

impl BoundProxy {
    /// Real addresses after bind (port 0 resolves an ephemeral one).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.entries
            .iter()
            .map(|e| (current_cfg(&e.cfg).name.clone(), e.local))
            .collect()
    }

    /// Hot swap (S-CFG-01): applies a new listener set while serving.
    ///
    /// Matching is by listener name (unique in the config):
    /// - same name + same address → the socket is **kept** (no rejection
    ///   window): only the config of new connections changes;
    /// - same name + different address → stop + rebind;
    /// - new name → start; missing name → stop.
    ///
    /// Fail-closed (SPEC §7.2): every needed address is bound **before**
    /// anything mutates, so a rejected swap leaves the running config
    /// untouched. Established connections drain with the config they
    /// were accepted with. Known edge: renaming a listener while keeping
    /// its exact address is rejected (the socket is still held); keep the
    /// name to keep the socket.
    pub async fn apply(
        &mut self,
        listeners: Vec<ResolvedListener>,
    ) -> Result<SwapSummary, ProxyError> {
        if let Some((name, addr)) = find_duplicate_addr(&listeners) {
            return Err(ProxyError::DuplicateListener { name, addr });
        }

        // Phase 1 — prepare resources: bind what we do not hold yet.
        // `None` = the socket is kept. On failure nothing has mutated.
        let mut prepared: Vec<(ResolvedListener, Option<TcpListener>)> = Vec::new();
        for cfg in listeners {
            let kept = self
                .entries
                .iter()
                .any(|e| e.listen == cfg.listen && current_cfg(&e.cfg).name == cfg.name);
            if kept {
                prepared.push((cfg, None));
                continue;
            }
            let name = cfg.name.clone();
            let addr = cfg.listen;
            match TcpListener::bind(addr).await {
                Ok(listener) => prepared.push((cfg, Some(listener))),
                Err(source) => return Err(ProxyError::Bind { name, addr, source }),
            }
        }

        // Phase 2 — commit: only infallible steps from here on.
        let mut summary = SwapSummary {
            kept: 0,
            added: 0,
            removed: 0,
        };
        // Stop what is not kept (the Drop impl stops the accept loop).
        self.entries.retain(|e| {
            let kept = prepared.iter().any(|(cfg, fresh)| {
                fresh.is_none() && cfg.listen == e.listen && cfg.name == current_cfg(&e.cfg).name
            });
            if kept {
                true
            } else {
                summary.removed += 1;
                false
            }
        });
        for (cfg, fresh) in prepared {
            let name = cfg.name.clone();
            match fresh {
                None => {
                    // Kept socket: swap the config new connections see.
                    let entry = self
                        .entries
                        .iter_mut()
                        .find(|e| e.listen == cfg.listen && current_cfg(&e.cfg).name == name)
                        .expect("kept entry present (phase 1 matched it)");
                    *entry
                        .cfg
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(cfg);
                    summary.kept += 1;
                }
                Some(listener) => {
                    self.entries
                        .push(make_entry(cfg, listener, Arc::clone(&self.metrics)));
                    summary.added += 1;
                }
            }
        }
        self.spawn_background();
        Ok(summary)
    }

    /// (Re)starts the background tasks for the current config, one per
    /// unique backend (same [`Balancer`] Arc across listeners): the
    /// active health checks (B11) and the non-blocking DNS resolver
    /// (B-H13/B-N18/B-E15, only for `HOSTNAME:PORT` servers). Both run
    /// after `bind`: no listener ever waits for health or DNS.
    fn spawn_background(&mut self) {
        self.bg_stop.trigger();
        self.bg_tasks.abort_all();
        let (stop, shutdown) = eqproxy_core::shutdown::channel();
        self.bg_stop = stop;
        let mut seen: Vec<Arc<Balancer>> = Vec::new();
        for entry in &self.entries {
            let cfg = current_cfg(&entry.cfg);
            // Every backend the listener can route to (default + rule
            // targets): a rule-referenced backend keeps its checks.
            for backend in cfg.all_backends() {
                let balancer = Arc::clone(&backend.balancer);
                if seen.iter().any(|s| Arc::ptr_eq(s, &balancer)) {
                    continue;
                }
                seen.push(Arc::clone(&balancer));
                if let Some(check) = backend.health_check.clone() {
                    self.bg_tasks.spawn(health::run(
                        Arc::clone(&balancer),
                        check,
                        shutdown.clone(),
                    ));
                }
                if !balancer.name_targets().is_empty() {
                    self.bg_tasks.spawn(dns::run(
                        balancer,
                        backend.dns,
                        Arc::clone(&self.metrics),
                        Arc::clone(&self.resolver),
                        shutdown.clone(),
                    ));
                }
            }
        }
        // Hot map file watchers (C10/PP-02): one per unique map with a
        // file source and a reload window. Restarted with the config
        // generation, like health checks and DNS (a swap rebuilds the
        // registry, so the new maps get their own watchers).
        let mut seen_maps: Vec<Arc<eqproxy_core::maps::HotMap>> = Vec::new();
        for entry in &self.entries {
            let cfg = current_cfg(&entry.cfg);
            for map in cfg.maps.iter() {
                if map.file().is_none() || map.reload_interval().is_zero() {
                    continue;
                }
                if seen_maps.iter().any(|seen| Arc::ptr_eq(seen, map)) {
                    continue;
                }
                seen_maps.push(Arc::clone(map));
                self.bg_tasks.spawn(crate::maps::run(
                    Arc::clone(map),
                    Arc::clone(&self.metrics),
                    shutdown.clone(),
                ));
            }
        }
    }

    /// Serves until the shutdown signal; then drains until `grace`.
    pub async fn serve(self, shutdown: Shutdown, grace: Duration) -> Result<(), ProxyError> {
        // No reload source: the channel stays silent for the whole life
        // of the dataplane.
        let (_reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
        self.serve_with_reloads(shutdown, grace, reload_rx).await
    }

    /// Serves until the shutdown signal, applying the validated config
    /// swaps that arrive through `reloads` (S-CFG-01). A rejected swap
    /// keeps serving the running config; a closed channel only disables
    /// the reloads.
    pub async fn serve_with_reloads(
        mut self,
        mut shutdown: Shutdown,
        grace: Duration,
        mut reloads: tokio::sync::mpsc::Receiver<Vec<ResolvedListener>>,
    ) -> Result<(), ProxyError> {
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                // `Some(..)`: when the channel closes, this branch is
                // disabled and only shutdown is left.
                Some(listeners) = reloads.recv() => {
                    // The swap latency is measured (PP-04/05), not assumed.
                    let started = std::time::Instant::now();
                    match self.apply(listeners).await {
                        Ok(summary) => {
                            let elapsed = started.elapsed();
                            self.metrics.config_reloads.fetch_add(1, Ordering::Relaxed);
                            self.metrics.config_reload_duration_us.store(
                                u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
                                Ordering::Relaxed,
                            );
                            eprintln!("INFO config reload applied: {summary} in {elapsed:?}");
                        }
                        Err(err) => {
                            self.metrics.config_reload_failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!("ERROR config reload rejected: {err}");
                        }
                    }
                }
            }
        }

        // Accept loops return instantly on the triggered signal.
        for entry in &self.entries {
            entry.stop.trigger();
        }
        self.bg_stop.trigger();
        let _ = tokio::time::timeout(grace, async {
            for entry in &mut self.entries {
                let _ = (&mut entry.task).await;
            }
        })
        .await;
        for entry in &mut self.entries {
            entry.task.abort();
        }
        self.bg_tasks.abort_all();

        // Draining: live connections may finish within the window.
        let deadline = tokio::time::Instant::now() + grace;
        while self.metrics.connections_active.load(Ordering::Acquire) > 0 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

/// First duplicate explicit listen address (two listeners sharing one
/// address can never both bind; startup fails the same way). Port 0 is
/// exempt: each resolves its own ephemeral port. Pure (unit-tested).
fn find_duplicate_addr(listeners: &[ResolvedListener]) -> Option<(String, SocketAddr)> {
    let mut seen: Vec<SocketAddr> = Vec::new();
    for cfg in listeners {
        if cfg.listen.port() == 0 {
            continue;
        }
        if seen.contains(&cfg.listen) {
            return Some((cfg.name.clone(), cfg.listen));
        }
        seen.push(cfg.listen);
    }
    None
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    shared: SharedCfg,
    name: String,
    metrics: Arc<Metrics>,
    mut shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        // Transient error (EMFILE, etc.): log and continue,
                        // with a small breather to avoid saturating the CPU.
                        eprintln!("ERROR [{name}] accept failed: {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // Config in force at accept time (S-CFG-01): established
                // connections keep it until they drain.
                let cfg = Arc::clone(&current_cfg(&shared));
                if !metrics.try_acquire_connection(cfg.maxconn) {
                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    // Explicit refusal: immediate close, no queue.
                    drop(socket);
                    continue;
                }
                metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
                let task_metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    handle_connection(socket, peer, cfg, task_metrics).await;
                });
            }
        }
    }
}

/// RAII guard: releases the connection slot no matter what.
struct ConnectionGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.release_connection();
    }
}

/// Picks a server honoring active health state (B11) and excluding servers
/// that already failed this exchange (B-H7: `pick_except`).
///
/// Pure selection: `NoServer` when everything is down/drained or already
/// tried. Counting `no_available_server` is the caller's job (once per
/// rejected exchange, never per queue poll).
fn select_server<'a>(
    backend: &'a ResolvedBackend,
    exclude: &[SocketAddr],
    preferred: Option<SocketAddr>,
) -> Result<(SocketAddr, ActiveGuard<'a>), OutboundError> {
    // `preferred = None` is the plain pick (roundrobin / leastconn); with
    // affinity the pin wins and falls forward past down/excluded servers
    // (B-H8). The pick holds one in-flight slot (B-H5 leastconn), taken
    // atomically with the selection and released with the guard.
    backend
        .balancer
        .pick_pinned_tracked(preferred, exclude)
        .ok_or(OutboundError::NoServer)
}

/// Stable-enough hash of the client IP for source affinity (B-N13).
fn affinity_hash(ip: IpAddr) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.finish() as usize
}

/// Passive health (B12/B-N10): a connect-phase failure feeds the balancer's
/// fall counter (same threshold as the active checker), so a dead server is
/// not hammered in a loop. **Opt-in + safe-restart rule:** only when the
/// backend sets `passive = true` AND an active checker exists that can bring
/// the server back (its `rise` transition clears the mark) — without a
/// checker a passive DOWN would be permanent.
fn report_passive(backend: &ResolvedBackend, addr: SocketAddr) {
    if backend
        .health_check
        .as_ref()
        .is_some_and(|check| check.passive)
    {
        backend.balancer.report_fail(addr);
    }
}

/// Connects to the balancer-chosen backend: TCP + optional TLS (A12) +
/// optional PROXY v1 header (A9), with B-H7 retry/queue semantics.
///
/// Retry rule: connect-phase failures only (nothing was sent to any backend
/// yet), idempotent exchanges unless the explicit opt-in; the failed server
/// is excluded from redials. With no server up: bounded wait in the backend
/// queue (or explicit rejection when configured/off).
///
/// `use_pool` enables A16 reuse (HTTP keep-alive); the pool checkout runs
/// on the very pick that would be dialed — a separate pick would steal the
/// round-robin turn of another server and silently starve it.
///
/// Retry safety (B-H7), the affinity pin (B-H8) and pool reuse (A16) are
/// per-exchange and travel together in [`DialOpts`].
struct DialOpts<'a> {
    ctx: RetryContext,
    affinity_cookie: Option<&'a str>,
    use_pool: bool,
}

async fn dial_with_retries<'a>(
    cfg: &ResolvedListener,
    backend: &'a ResolvedBackend,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
    opts: DialOpts<'_>,
) -> Result<(BackendConn, ActiveGuard<'a>), OutboundError> {
    // Affinity (B-H8/B-N13/B-I8): the preferred server of this exchange,
    // from the request's affinity cookie (cookie mode) or the client IP
    // hash (source mode). Both fall forward past down servers.
    let preferred = match backend.affinity.as_ref().map(|affinity| affinity.mode) {
        // The token/hash maps to a **stable slot index** (B-H13: a DNS
        // re-resolution must not reshuffle affinity); an unresolved slot
        // simply has no preferred address and falls forward.
        Some(AffinityMode::Cookie) => opts
            .affinity_cookie
            .and_then(|token| token.parse::<usize>().ok())
            .and_then(|idx| backend.balancer.addr_of_slot(idx)),
        Some(AffinityMode::Source) => {
            let count = backend.balancer.slot_count();
            (count > 0)
                .then(|| {
                    backend
                        .balancer
                        .addr_of_slot(affinity_hash(peer.ip()) % count)
                })
                .flatten()
        }
        None => None,
    };
    let max_attempts = if backend.retries.allows(opts.ctx.idempotent) {
        backend.retries.max
    } else {
        0
    };
    let mut tried: Vec<SocketAddr> = Vec::new();
    loop {
        // --- Server selection (B11 active state; B-H7 exclusion) ---
        // The pick holds one in-flight slot (B-H5); it is released with
        // the guard when the attempt fails and travels with the
        // connection on success.
        let (addr, active) = match select_server(backend, &tried, preferred) {
            Ok(picked) => picked,
            Err(OutboundError::NoServer) if !tried.is_empty() => {
                // Every candidate already failed this exchange: the class is
                // "the chosen server failed" (HTTP → 502), not "nothing up".
                return Err(OutboundError::Connect);
            }
            Err(OutboundError::NoServer) => {
                // Nothing up/drained now: bounded queue (B-H7) or reject.
                let Some(queue) = &backend.queue else {
                    metrics.no_available_server.fetch_add(1, Ordering::Relaxed);
                    return Err(OutboundError::NoServer);
                };
                let Some(_permit) = queue.enter() else {
                    metrics.queue_full.fetch_add(1, Ordering::Relaxed);
                    return Err(OutboundError::QueueFull);
                };
                let deadline = tokio::time::Instant::now() + queue.settings.timeout;
                let result = tokio::time::timeout_at(deadline, async {
                    loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if let Ok(picked) = select_server(backend, &[], preferred) {
                            return picked;
                        }
                    }
                })
                .await;
                match result {
                    Ok(picked) => picked,
                    Err(_) => {
                        metrics.queue_timeout.fetch_add(1, Ordering::Relaxed);
                        return Err(OutboundError::QueueTimeout);
                    }
                }
            }
            Err(err) => return Err(err),
        };

        // --- Pool reuse first (A16), first attempt only ---
        if opts.use_pool
            && tried.is_empty()
            && let Some((read, write)) = backend.pool.checkout(&addr, Instant::now())
        {
            metrics
                .backend_connections_reused
                .fetch_add(1, Ordering::Relaxed);
            return Ok((
                BackendConn {
                    addr,
                    read,
                    write,
                    reused: true,
                },
                active,
            ));
        }

        // --- Dial the chosen server ---
        match connect_backend_to(
            DialTimeouts {
                name: &cfg.name,
                connect: cfg.connect_timeout,
                idle: cfg.idle_timeout,
            },
            backend,
            addr,
            peer,
            local,
            metrics,
        )
        .await
        {
            Ok((read, write)) => {
                metrics
                    .backend_connections_opened
                    .fetch_add(1, Ordering::Relaxed);
                return Ok((
                    BackendConn {
                        addr,
                        read: BufReader::new(read),
                        write,
                        reused: false,
                    },
                    active,
                ));
            }
            Err(OutboundError::Connect) => {
                tried.push(addr);
                // Passive mark (when safe to restart) + exclusion.
                report_passive(backend, addr);
                if tried.len() as u32 > max_attempts {
                    // Retry budget spent: final error.
                    return Err(OutboundError::Connect);
                }
                metrics.retry_attempts.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => return Err(err),
        }
    }
}

/// Connects to the balancer-chosen backend (TCP/TLS + PROXY send).
pub async fn connect_backend<'a>(
    cfg: &'a ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<(BoxRead, BoxWrite, ActiveGuard<'a>), OutboundError> {
    // TCP has no replay-safety knowledge: conservative non-idempotent,
    // and no pooling (streams have no message boundaries). TCP has no
    // routing rules: always the default backend.
    let (conn, active) = dial_with_retries(
        cfg,
        &cfg.backend,
        peer,
        local,
        metrics,
        DialOpts {
            ctx: RetryContext::non_idempotent(),
            affinity_cookie: None,
            use_pool: false,
        },
    )
    .await?;
    Ok((Box::new(conn.read), conn.write, active))
}

/// Stream to the backend with its origin: reused from the pool (A16) or
/// freshly dialed. `reused` feeds `backend_connections_reused`.
pub struct BackendConn {
    /// Balancer-chosen server (pool key).
    pub addr: SocketAddr,
    /// Read half (ready for `read_head`: message-aligned).
    pub read: BufReader<BoxRead>,
    /// Write half.
    pub write: BoxWrite,
    /// `true` when from the pool (no dial, handshake or PROXY again).
    pub reused: bool,
}

/// Reuses an idle pool connection or dials a new one to the
/// balancer-chosen server, with B-H7 retry/queue semantics.
///
/// `ctx` decides retry safety (idempotent unless explicit opt-in).
pub async fn checkout_or_connect<'a>(
    cfg: &ResolvedListener,
    backend: &'a ResolvedBackend,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
    ctx: RetryContext,
    affinity_cookie: Option<&str>,
) -> Result<(BackendConn, ActiveGuard<'a>), OutboundError> {
    // Pool checkout runs on the very pick that would be dialed (inside
    // `dial_with_retries`): one request, one pick, one connection (B-H7).
    // The in-flight slot (B-H5) travels with the connection and is
    // released when the caller's guard drops at exchange end.
    dial_with_retries(
        cfg,
        backend,
        peer,
        local,
        metrics,
        DialOpts {
            ctx,
            affinity_cookie,
            use_pool: true,
        },
    )
    .await
}

/// Name and timeouts of one dial attempt, kept together so the signature of
/// [`connect_backend_to`] stays readable.
#[derive(Clone, Copy)]
pub(crate) struct DialTimeouts<'a> {
    /// Listener (or mirror) name used in the log lines.
    pub name: &'a str,
    /// Maximum for TCP connect, TLS handshake and h2 handshake alike.
    pub connect: Duration,
    /// Per-operation inactivity bound of the h2 backend bridge.
    pub idle: Duration,
}

/// Variant of [`connect_backend`] against an already-chosen server (the pool
/// needs the address before deciding between reuse and dial).
///
/// The PROXY v1 header (A9) is written once per connection: pool-reused
/// connections already carry it from their first use.
pub(crate) async fn connect_backend_to(
    timeouts: DialTimeouts<'_>,
    backend: &ResolvedBackend,
    addr: SocketAddr,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<(BoxRead, BoxWrite), OutboundError> {
    let DialTimeouts {
        name,
        connect: connect_timeout,
        idle,
    } = timeouts;
    let socket = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(err)) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!("ERROR [{name}] could not connect to {addr} (peer {peer}): {err}");
            return Err(OutboundError::Connect);
        }
        Err(_elapsed) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{name}] connect timeout to {addr} (peer {peer}) after {connect_timeout:?}"
            );
            return Err(OutboundError::Connect);
        }
    };
    let _ = socket.set_nodelay(true);

    if let Some(client_tls) = &backend.tls {
        let server_name = tls::server_name_for(client_tls, addr);
        let handshake = tokio::time::timeout(
            connect_timeout,
            client_tls.connector.connect(server_name, socket),
        );
        let mut stream = match handshake.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!("ERROR [{name}] failed TLS handshake to {addr} (peer {peer}): {err}");

                return Err(OutboundError::Connect);
            }
            Err(_elapsed) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{name}] TLS handshake timeout to {addr} (peer {peer}) after {connect_timeout:?}"
                );
                return Err(OutboundError::Connect);
            }
        };
        let proxy_header = match backend.proxy_protocol {
            ProxyProtocolMode::None => Ok(()),
            ProxyProtocolMode::V1 => proxy_proto::write_v1(&mut stream, peer, local).await,
            ProxyProtocolMode::V2 => proxy_proto::write_v2(&mut stream, peer, local).await,
        };
        if proxy_header.is_err() {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            return Err(OutboundError::Connect);
        }
        // HTTP/2 to the backend (B-H1): whatever ALPN the handshake agreed.
        // A `h2` result is served as a real h2 session; anything else (none,
        // `http/1.1`) keeps the h1 byte stream.
        if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            return match backend_h2::bridge(stream, name, connect_timeout, idle).await {
                Ok(pair) => Ok(pair),
                Err(err) => {
                    metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "ERROR [{name}] failed HTTP/2 session to {addr} (peer {peer}): {err}"
                    );
                    Err(OutboundError::Connect)
                }
            };
        }
        let (read, write) = tokio::io::split(stream);
        Ok((Box::new(read), Box::new(write)))
    } else {
        let mut socket = socket;
        let proxy_header = match backend.proxy_protocol {
            ProxyProtocolMode::None => Ok(()),
            ProxyProtocolMode::V1 => proxy_proto::write_v1(&mut socket, peer, local).await,
            ProxyProtocolMode::V2 => proxy_proto::write_v2(&mut socket, peer, local).await,
        };
        if proxy_header.is_err() {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            return Err(OutboundError::Connect);
        }
        let (read, write) = socket.into_split();
        Ok((Box::new(read), Box::new(write)))
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ResolvedListener>,
    metrics: Arc<Metrics>,
) {
    let _guard = ConnectionGuard {
        metrics: Arc::clone(&metrics),
    };
    let _ = client.set_nodelay(true);
    let local = client.local_addr().unwrap_or(cfg.listen);

    // PROXY v1 reception (B-H9/B-E10): strict front door — only
    // allowlisted origins, only valid lines, always bounded. The claimed
    // address becomes the peer for XFF, logs and PROXY send.
    let peer = if let Some(allowlist) = &cfg.proxy_receive {
        match proxy_proto::read_proxy_header(
            &mut client,
            peer,
            allowlist,
            cfg.client_header_timeout,
        )
        .await
        {
            Ok(claimed) => claimed,
            Err(err) => {
                match err {
                    proxy_proto::ProxyReceiveError::Denied => {
                        metrics
                            .proxy_protocol_denied
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] PROXY header from non-allowlisted origin {peer}: connection rejected",
                            cfg.name
                        );
                    }
                    proxy_proto::ProxyReceiveError::Invalid => {
                        metrics
                            .proxy_protocol_invalid
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] invalid PROXY header from {peer}: connection rejected",
                            cfg.name
                        );
                    }
                    proxy_proto::ProxyReceiveError::Timeout => {
                        metrics
                            .proxy_protocol_invalid
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] PROXY header from {peer} timed out after {:?}: connection rejected",
                            cfg.name, cfg.client_header_timeout
                        );
                    }
                }
                return;
            }
        }
    } else {
        peer
    };

    // TLS termination (A11): the handshake lives in the client phase. What
    // the listener speaks afterwards is the negotiated ALPN; a plaintext
    // listener cannot negotiate anything, so it looks for the h2c
    // connection preface instead (RFC 9113 §3.4).
    let (io, negotiated_h2): (Box<dyn IoStream>, bool) = if let Some(server_tls) = &cfg.server_tls {
        let handshake = tokio::time::timeout(
            cfg.client_header_timeout,
            server_tls.acceptor.accept(client),
        );
        let stream = match handshake.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] failed client TLS handshake (peer {peer}): {err}",
                    cfg.name
                );
                return;
            }
            Err(_elapsed) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] client TLS handshake timeout (peer {peer}) after {:?}",
                    cfg.name, cfg.client_header_timeout
                );
                return;
            }
        };
        // A TCP tunnel relays bytes: an `h2` ALPN hint there is the
        // client's choice for what the *backend* speaks, never a reason to
        // parse the stream here.
        let negotiated_h2 =
            cfg.mode == ProxyMode::Http && stream.get_ref().1.alpn_protocol() == Some(b"h2");
        (Box::new(stream), negotiated_h2)
    } else if cfg.mode == ProxyMode::Http {
        let negotiated_h2 = http2::is_h2c(&client, cfg.client_header_timeout).await;
        (Box::new(client), negotiated_h2)
    } else {
        // TCP mode dials the backend immediately: no sniffing, no delay.
        (Box::new(client), false)
    };

    if cfg.mode == ProxyMode::Http {
        if negotiated_h2 {
            http2::serve_h2(io, peer, local, Arc::clone(&cfg), Arc::clone(&metrics)).await;
            return;
        }
        let (client_read, client_write) = tokio::io::split(io);
        http1::serve_http(client_read, client_write, peer, local, &cfg, metrics).await;
        return;
    }
    let (client_read, client_write) = tokio::io::split(io);
    let client_read: BoxRead = Box::new(client_read);
    let client_write: BoxWrite = Box::new(client_write);

    match connect_backend(&cfg, peer, local, &metrics).await {
        Ok((server_read, server_write, _active)) => {
            // `_active` (B-H5) holds the in-flight slot across the whole
            // relay: a TCP stream counts as one load unit until EOF.
            pump(
                (client_read, client_write),
                (server_read, server_write),
                cfg.idle_timeout,
                &metrics,
            )
            .await;
        }
        Err(OutboundError::NoServer | OutboundError::QueueFull | OutboundError::QueueTimeout) => {
            // TCP mode has no response channel: explicit close (logged).
            eprintln!(
                "ERROR [{}] no servers available (peer {peer}): connection closed",
                cfg.name
            );
        }
        Err(OutboundError::Connect) => {}
    }
}

/// Independent bidirectional pump per direction.
async fn pump(
    client: (BoxRead, BoxWrite),
    server: (BoxRead, BoxWrite),
    idle: Duration,
    metrics: &Metrics,
) {
    let (client_read, client_write) = client;
    let (server_read, server_write) = server;

    let c2b = copy_dir(
        client_read,
        server_write,
        idle,
        &metrics.bytes_client_to_backend,
        &metrics.idle_timeouts,
    );
    let b2c = copy_dir(
        server_read,
        client_write,
        idle,
        &metrics.bytes_backend_to_client,
        &metrics.idle_timeouts,
    );
    // join!: each direction has its own timeout, so the set finishes in
    // bounded time even when a peer is silent.
    let (c2b_result, b2c_result) = tokio::join!(c2b, b2c);
    for result in [c2b_result, b2c_result] {
        // The inactivity timeout is already counted and closed in copy_dir;
        // real I/O errors are logged for diagnosis.
        if let Err(err) = result
            && err.kind() != io::ErrorKind::TimedOut
        {
            eprintln!("ERROR in the TCP tunnel: {err}");
        }
    }
}

/// Copies `reader → writer` with a per-read inactivity timeout.
///
/// On EOF (or timeout) the writer gets `shutdown()` to propagate the
/// half-close towards the peer. Returns `TimedOut` when the timeout expired.
async fn copy_dir<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        let read = match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_elapsed) => {
                idle_counter.fetch_add(1, Ordering::Relaxed);
                let _ = writer.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "inactivity timeout in one tunnel direction",
                ));
            }
            Ok(result) => result,
        };
        match read {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(n) => {
                writer.write_all(&buf[..n]).await?;
                total += n as u64;
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(err) => {
                let _ = writer.shutdown().await;
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::AsyncWriteExt;

    /// Runs a future on a single-thread runtime **without IO driver**
    /// (mio/kqueue): tests only use timers and in-memory duplex, so they
    /// also run under miri, which does not emulate that OS FFI.
    fn sin_driver_io<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(fut)
    }

    #[test]
    fn copy_dir_moves_bytes_and_propagates_eof() {
        sin_driver_io(async {
            let (mut client, server) = tokio::io::duplex(64);
            let bytes = Arc::new(AtomicU64::new(0));
            let idles = Arc::new(AtomicU64::new(0));
            let task_bytes = Arc::clone(&bytes);
            let task_idles = Arc::clone(&idles);

            let copier = tokio::spawn(async move {
                copy_dir(
                    server,
                    tokio::io::sink(),
                    Duration::from_secs(5),
                    &task_bytes,
                    &task_idles,
                )
                .await
            });
            client.write_all(b"hello").await.expect("write");
            drop(client); // EOF
            let copied = tokio::time::timeout(Duration::from_secs(2), copier)
                .await
                .expect("the copier must finish")
                .expect("join")
                .expect("no error on EOF");
            assert_eq!(copied, 5);
            assert_eq!(bytes.load(Ordering::Relaxed), 5);
            assert_eq!(idles.load(Ordering::Relaxed), 0);
        })
    }

    #[test]
    fn copy_dir_times_out_when_reader_is_silent() {
        sin_driver_io(async {
            let (_client, server) = tokio::io::duplex(64);
            let bytes = AtomicU64::new(0);
            let idles = AtomicU64::new(0);
            let result = copy_dir(
                server,
                tokio::io::sink(),
                Duration::from_millis(50),
                &bytes,
                &idles,
            )
            .await;
            let err = result.expect_err("must expire on inactivity");
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert_eq!(idles.load(Ordering::Relaxed), 1);
        })
    }

    // --- B-I11: weighted traffic split (smooth WRR across targets) ---

    fn split_backend(name: &str) -> Arc<ResolvedBackend> {
        Arc::new(ResolvedBackend::single(
            name,
            "127.0.0.1:9000"
                .parse::<std::net::SocketAddr>()
                .expect("server addr"),
        ))
    }

    fn split(weights: &[(&str, u32)]) -> SplitTargets {
        SplitTargets::new(
            weights
                .iter()
                .map(|(name, weight)| SplitTarget {
                    backend: split_backend(name),
                    weight: *weight,
                })
                .collect(),
        )
    }

    #[test]
    fn split_shares_requests_by_exact_weight() {
        let targets = split(&[("stable", 3), ("canary", 1)]);
        let mut counts = std::collections::BTreeMap::new();
        for _ in 0..8 {
            let picked = targets.pick().name.clone();
            *counts.entry(picked).or_insert(0usize) += 1;
        }
        assert_eq!(
            counts.get("stable"),
            Some(&6),
            "3:1 over 8 = 6:2: {counts:?}"
        );
        assert_eq!(counts.get("canary"), Some(&2), "{counts:?}");
    }

    #[test]
    fn split_zero_weight_targets_are_never_picked() {
        let targets = split(&[("off", 0), ("live", 2), ("also-off", 0)]);
        for _ in 0..20 {
            assert_eq!(targets.pick().name, "live");
        }
    }

    #[test]
    fn split_smoothly_interleaves_instead_of_bursting() {
        let targets = split(&[("a", 3), ("b", 1)]);
        let order: Vec<String> = (0..4).map(|_| targets.pick().name.clone()).collect();
        // Smooth WRR: the minority target lands inside the window, not
        // in a burst at the end of it (nginx's algorithm).
        assert_eq!(order, ["a", "a", "b", "a"], "order: {order:?}");
    }

    // --- B-H3: hash policy keys and weighted rendezvous selection ---

    #[test]
    fn hash_policy_parses_the_documented_keys_and_rejects_the_rest() {
        for (raw, expected) in [
            ("source", HashKey::Source),
            ("path", HashKey::Path),
            ("  host  ", HashKey::Host),
            ("cookie:session", HashKey::Cookie("session".to_owned())),
            ("header:X-User", HashKey::Header("X-User".to_owned())),
        ] {
            assert_eq!(
                HashPolicy::parse(raw).expect("parses").key,
                expected,
                "{raw:?}"
            );
        }
        for raw in ["iphash", "cookie:", "header:", "cookie", ""] {
            assert!(
                HashPolicy::parse(raw).is_err(),
                "{raw:?} must be rejected, not silently ignored"
            );
        }
    }

    #[test]
    fn hashed_pick_is_sticky_weighted_and_consistent_under_removal() {
        let three = split(&[("a", 1), ("b", 1), ("c", 1)]);
        let mut mapping = std::collections::BTreeMap::new();
        for i in 0..300 {
            let key = format!("key-{i}");
            let first = three
                .pick_hashed(&key)
                .expect("an active target")
                .name
                .clone();
            // Deterministic: the same key always lands on the same target.
            for _ in 0..3 {
                assert_eq!(
                    three.pick_hashed(&key).expect("an active target").name,
                    first,
                    "key {key}"
                );
            }
            mapping.insert(key, first);
        }
        let mut counts = std::collections::BTreeMap::new();
        for name in mapping.values() {
            *counts.entry(name.clone()).or_insert(0usize) += 1;
        }
        for name in ["a", "b", "c"] {
            let share = counts.get(name).copied().unwrap_or(0);
            assert!(
                (60..140).contains(&share),
                "equal weights must give each target ~100 of 300 keys: {counts:?}"
            );
        }

        // Consistent removal: dropping one target only moves its keys.
        let two = split(&[("a", 1), ("b", 1)]);
        for (key, was) in &mapping {
            let now = two.pick_hashed(key).expect("an active target").name.clone();
            if was != "c" {
                assert_eq!(&now, was, "key {key} moved although its target stayed");
            }
        }

        // Weights set the share of keys, not the identity of a key.
        let weighted = split(&[("a", 9), ("b", 1)]);
        let a_share = (0..300)
            .filter(|i| {
                weighted
                    .pick_hashed(&format!("key-{i}"))
                    .expect("an active target")
                    .name
                    == "a"
            })
            .count();
        assert!(
            (200..300).contains(&a_share),
            "9:1 must send most keys to `a` but not all, got {a_share} of 300"
        );
    }

    #[test]
    fn swap_summary_renders_the_three_counts() {
        let summary = SwapSummary {
            kept: 1,
            added: 2,
            removed: 3,
        };
        assert_eq!(summary.to_string(), "listeners kept=1 added=2 removed=3");
    }

    /// Builds a listener without sockets (pure: miri-safe).
    fn listener(name: &str, listen: &str) -> ResolvedListener {
        ResolvedListener::new(
            name,
            listen.parse().expect("listen"),
            "backend",
            "127.0.0.1:9000".parse::<SocketAddr>().expect("server"),
            ProxyMode::Tcp,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn duplicate_explicit_addresses_are_detected_and_port_zero_is_exempt() {
        let a = listener("a", "127.0.0.1:8080");
        let b = listener("b", "127.0.0.1:8080");
        let z1 = listener("z1", "127.0.0.1:0");
        let z2 = listener("z2", "127.0.0.1:0");
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("addr");

        assert_eq!(
            find_duplicate_addr(&[a.clone(), b.clone()]),
            Some(("b".to_owned(), addr))
        );
        // Two ephemeral listeners are legal: each gets its own port.
        assert_eq!(find_duplicate_addr(&[z1, z2]), None);
        assert_eq!(find_duplicate_addr(&[a]), None);
        assert_eq!(find_duplicate_addr(&[]), None);
    }
}
