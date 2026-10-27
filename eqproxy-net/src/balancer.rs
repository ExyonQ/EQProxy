//! Load balancing (B1/B7 round-robin; B-H5/B-N12/B-E6 least-connections)
//! with per-server health state and slow-start ramping (B14).
//!
//! Algorithms:
//!
//! - `roundrobin`: *smooth weighted round-robin* (deterministic; ties follow
//!   configuration order).
//! - `leastconn`: weighted least-connections (HAProxy `leastconn`, nginx
//!   `least_conn`, Envoy `LEAST_REQUEST`): the server with the smallest
//!   `active / effective_weight` ratio wins; ties keep the SWRR smoothing.
//!
//! **Dynamic weighting (B14 slow start):** the weight used at pick time is
//! not the configured one but the *effective weight* = `weight` scaled by
//! the slow-start ramp. Whenever a server becomes operational (startup or
//! recovery after `rise` successes) its effective weight ramps linearly
//! from ~0 to `weight` over the `slow_start` window, so a cold or recovered
//! server is not hammered with full traffic immediately.
//!
//! A server with `weight = 0` is never selected (drained) but keeps being
//! probed by health checks (B11).
//!
//! Health state: `fall`/`rise` machine — `fall` consecutive failures drop
//! the server, `rise` consecutive successes raise it. Servers start
//! operational (like HAProxy before the first check); with no health check
//! configured they stay operational forever.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Administration state of one backend server (v0.8, ADR-0018, ADR-0028).
///
/// `Drain` removes the server from **new** selections immediately while the
/// exchanges already in flight finish on it; `Maintenance` does the same and
/// additionally closes the server's idle pooled sockets at the transition,
/// so nothing of ours stays parked on a box taken out for a patch window;
/// `Ready` puts it back. The health machine (B11) is a separate axis: a
/// removed server keeps being probed and keeps its `up`/`down` state, so an
/// operator can see both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerMode {
    /// Serving new exchanges.
    #[default]
    Ready,
    /// Administratively removed: no new exchanges, in-flight ones finish.
    Drain,
    /// Removed for a patch window (ADR-0028): like `Drain`, and the server's
    /// idle pooled connections are closed at the transition instead of
    /// ageing out on their own timer.
    Maintenance,
}

impl ServerMode {
    /// Wire/JSON name (the only accepted spellings; the reference's `maint`
    /// is not an alias).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Drain => "drain",
            Self::Maintenance => "maintenance",
        }
    }

    /// Parses the wire name exactly (no aliases: a typo must not remove a
    /// server).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ready" => Some(Self::Ready),
            "drain" => Some(Self::Drain),
            "maintenance" => Some(Self::Maintenance),
            _ => None,
        }
    }
}

/// Administration state per `(backend, configured target)`, shared by every
/// [`Balancer`] of that backend **and by the ones built by a SIGHUP reload**:
/// a drain survives a config swap instead of silently returning the server to
/// rotation. Keyed by the configured target (`HOSTNAME:PORT` or `IP:PORT`),
/// never by the resolved address, so a DNS change does not lose the state.
#[derive(Debug, Default)]
pub struct ServerModes {
    inner: Mutex<HashMap<String, HashMap<String, ServerMode>>>,
}

impl ServerModes {
    /// Empty registry (every server starts `ready`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// State of one server (`Ready` when it was never touched).
    #[must_use]
    pub fn get(&self, backend: &str, target: &str) -> ServerMode {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .get(backend)
            .and_then(|servers| servers.get(target))
            .copied()
            .unwrap_or_default()
    }

    /// Sets the state and returns the previous one (idempotent by design:
    /// declaring the same state twice is not an error).
    pub fn set(&self, backend: &str, target: &str, mode: ServerMode) -> ServerMode {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .entry(backend.to_owned())
            .or_default()
            .insert(target.to_owned(), mode)
            .unwrap_or_default()
    }
}

/// Live view of one server slot, as the admin plane reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerView {
    /// Configured target, exactly as written (`HOSTNAME:PORT` or `IP:PORT`).
    pub target: String,
    /// Address currently in use (`None` while a name is unresolved).
    pub addr: Option<SocketAddr>,
    pub weight: u32,
    /// Backup class (B8): selected only when no primary is eligible.
    pub backup: bool,
    /// Failover order among backups (EQProxy extension): higher first, ties
    /// by configuration order. Always `0` on a primary.
    pub priority: u32,
    /// Health machine (B11), independent of [`mode`](Self::mode).
    pub up: bool,
    /// Exchanges in flight on this slot.
    pub active: u32,
    /// Administrative state (ADR-0018).
    pub mode: ServerMode,
    /// `true` when the slot is administratively removed (`drain` or
    /// `maintenance`) and nothing is in flight on it any more: the drain has
    /// finished (H3) or the maintenance window is open (ADR-0028). A removed
    /// but idle slot reports `true` as well — there was nothing to wait for.
    pub drained: bool,
}

/// Balancing algorithm of a backend (B-H5/B-N12/B-E6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Balance {
    /// Smooth weighted round-robin (B1 + B7).
    #[default]
    RoundRobin,
    /// Weighted least-connections (B-H5/B-N12/B-E6): `active / effective
    /// weight` picks, ties smoothed by SWRR.
    LeastConn,
}

impl Balance {
    /// Report name, shared by the status JSON, the metrics detail labels and
    /// the panel: one spelling for one algorithm.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::LeastConn => "least_conn",
        }
    }
}

/// Effective weights live in milli-units so a slow-start ramp can be
/// fractional without floats (1 configured weight = 1000 milli-units).
const SCALE: i64 = 1000;

/// Where a backend server lives: a literal address or a hostname that
/// the DNS resolver (B-H13/B-N18/B-E15) keeps up to date in the
/// background — listeners never block on DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAddr {
    /// Literal `IP:PORT`: no DNS involved.
    Ip(SocketAddr),
    /// `HOSTNAME:PORT`: resolved non-blockingly, re-resolved periodically.
    Name { host: String, port: u16 },
}

impl From<SocketAddr> for ServerAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl std::fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Name { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// A resolved backend server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServer {
    pub addr: ServerAddr,
    pub weight: u32,
    /// Backup class (B8): never selected while any primary is eligible.
    pub backup: bool,
    /// Failover order among backups (EQProxy extension, 0..=255): higher
    /// serves first; only the first operational rung is used at a time.
    pub priority: u32,
}

#[derive(Debug, Clone)]
struct ServerState {
    /// Target as configured: the key of the administration state, stable
    /// across DNS re-resolutions (ADR-0018).
    target: String,
    /// Current resolved address. `None` = name still unresolved (B-H13):
    /// the slot is never selected and the caller answers 503 with the
    /// `no_available_server` metric until DNS lands.
    addr: Option<SocketAddr>,
    weight: u32,
    /// Backup class (B8), copied from [`ResolvedServer`] at construction.
    backup: bool,
    /// Failover order among backups (EQProxy extension), copied too.
    priority: u32,
    up: bool,
    current_weight: i64,
    consecutive_fails: u32,
    consecutive_rises: u32,
    /// Exchanges in flight on this server (the leastconn load metric).
    active: u32,
    /// When the server last became operational: slow-start ramp base.
    up_since: Instant,
}

/// Load balancer with shared health state (per backend).
#[derive(Debug)]
pub struct Balancer {
    /// Backend name: one half of the administration-state key (ADR-0018).
    backend: String,
    fall: u32,
    rise: u32,
    algorithm: Balance,
    slow_start: Duration,
    /// Balance across the whole backup tier (`option allbackups`, B8): every
    /// eligible backup is a candidate instead of one rung at a time.
    all_backups: bool,
    state: Mutex<Vec<ServerState>>,
    targets: Vec<ServerAddr>,
    /// Shared administration state; `None` in unit constructions that do not
    /// use the admin plane (every server is then `ready`).
    modes: Option<Arc<ServerModes>>,
    /// Drain episodes of this backend whose **last in-flight exchange** ended
    /// after the drain was declared (H3). Incremented once per episode, when
    /// the count reaches zero on a drained slot; a drain declared on an idle
    /// slot has no exchange to wait for and is reported by
    /// [`ServerView::drained`] instead of an event.
    drains_completed: AtomicU64,
}

/// RAII in-flight slot (B-H5 leastconn): one held per exchange, released
/// on drop — an early return or an error cannot leak load. Keyed by slot
/// index: a DNS re-resolution may change a server's address under a
/// running exchange.
pub struct ActiveGuard<'a> {
    balancer: &'a Balancer,
    idx: usize,
}

impl ActiveGuard<'_> {
    /// Exchanges the balancer currently counts on the guarded server, this
    /// one included. The keep-alive pool sizes its idle cap from it, so a
    /// burst of N exchanges keeps N connections instead of re-dialling all
    /// but the floor.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.balancer
            .state()
            .get(self.idx)
            .map_or(1, |server| server.active)
    }

    /// Administration state of the guarded slot at this instant (ADR-0028):
    /// the completion path refuses to park a connection to a `maintenance`
    /// slot, so the pool holds nothing of a server taken out for a patch
    /// window — check-in would otherwise re-park it after the transition.
    #[must_use]
    pub fn mode(&self) -> ServerMode {
        let state = self.balancer.state();
        state
            .get(self.idx)
            .map_or(ServerMode::Ready, |server| self.balancer.mode_of(server))
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        // The last exchange of a removed slot ends here: that is the exact
        // moment the drain finishes (H3) and the maintenance window opens
        // (ADR-0028), so the event is recorded at the source instead of
        // being polled later. The lock is released before the log line so
        // no I/O happens while holding the server table.
        let mut state = self.balancer.state();
        let finished = match state.get_mut(self.idx) {
            Some(server) => {
                server.active = server.active.saturating_sub(1);
                let mode = self.balancer.mode_of(server);
                (server.active == 0 && mode != ServerMode::Ready)
                    .then(|| (mode, server.target.clone()))
            }
            None => None,
        };
        drop(state);
        match finished {
            Some((ServerMode::Drain, target)) => {
                let count = self
                    .balancer
                    .drains_completed
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                eprintln!(
                    "INFO server drained: backend={} target={} active=0 events={count}",
                    self.balancer.backend, target
                );
            }
            Some((ServerMode::Maintenance, target)) => {
                // One-shot: the drain counter backs a published metric and is
                // not extended to maintenance (ADR-0028). The `drained` flag
                // in status plus this line are the window's signal.
                eprintln!(
                    "INFO server ready for maintenance: backend={} target={} active=0",
                    self.balancer.backend, target
                );
            }
            _ => {}
        }
    }
}

impl Balancer {
    /// Creates the balancer for `servers` (in configuration order) with the
    /// `roundrobin` algorithm and no slow start. `fall` and `rise` are the
    /// health-machine thresholds (B11).
    #[must_use]
    pub fn new(servers: Vec<ResolvedServer>, fall: u32, rise: u32) -> Self {
        Self::with_options(servers, fall, rise, Balance::RoundRobin, Duration::ZERO)
    }

    /// Creates the balancer with its algorithm (B-H5/B-N12/B-E6) and slow
    /// start window (B14; [`Duration::ZERO`] disables the ramp).
    #[must_use]
    pub fn with_options(
        servers: Vec<ResolvedServer>,
        fall: u32,
        rise: u32,
        algorithm: Balance,
        slow_start: Duration,
    ) -> Self {
        let now = Instant::now();
        let targets: Vec<ServerAddr> = servers.iter().map(|s| s.addr.clone()).collect();
        let state = servers
            .into_iter()
            .map(|s| ServerState {
                target: s.addr.to_string(),
                // Names start unresolved (B-H13): the resolver task fills
                // them in; a literal is usable immediately.
                addr: match &s.addr {
                    ServerAddr::Ip(ip) => Some(*ip),
                    ServerAddr::Name { .. } => None,
                },
                weight: s.weight,
                backup: s.backup,
                priority: s.priority,
                up: true,
                current_weight: 0,
                consecutive_fails: 0,
                consecutive_rises: 0,
                active: 0,
                up_since: now,
            })
            .collect::<Vec<ServerState>>();
        Self {
            backend: String::new(),
            fall: fall.max(1),
            rise: rise.max(1),
            algorithm,
            slow_start,
            all_backups: false,
            state: Mutex::new(state),
            targets,
            modes: None,
            drains_completed: AtomicU64::new(0),
        }
    }

    /// Drain episodes of this backend that finished while it had exchanges in
    /// flight (H3). Monotonic for the life of the balancer; a SIGHUP rebuild
    /// starts a fresh balancer, exactly like the rest of its live state.
    #[must_use]
    pub fn drains_completed(&self) -> u64 {
        self.drains_completed.load(Ordering::Relaxed)
    }

    /// Binds the balancer to the shared administration state (ADR-0018): the
    /// backend name and the registry a `drain` is written to. Must be called
    /// before the balancer serves traffic (the CLI sets it while resolving).
    #[must_use]
    pub fn with_modes(mut self, backend: impl Into<String>, modes: Arc<ServerModes>) -> Self {
        self.backend = backend.into();
        self.modes = Some(modes);
        self
    }

    /// Slow-start window (B14), needed when a builder rebuilds the balancer.
    #[must_use]
    pub fn slow_start(&self) -> Duration {
        self.slow_start
    }

    /// Balances across every eligible backup (`option allbackups`, B8)
    /// instead of one rung at a time. Set while building, before the
    /// balancer serves traffic.
    #[must_use]
    pub fn with_all_backups(mut self, all_backups: bool) -> Self {
        self.all_backups = all_backups;
        self
    }

    /// Whether the whole backup tier balances at once (`option allbackups`,
    /// B8); needed when a builder rebuilds the balancer.
    #[must_use]
    pub fn all_backups(&self) -> bool {
        self.all_backups
    }

    /// Administrative state of a slot (ADR-0018).
    fn mode_of(&self, server: &ServerState) -> ServerMode {
        self.modes.as_ref().map_or(ServerMode::Ready, |modes| {
            modes.get(&self.backend, &server.target)
        })
    }

    /// Every slot as the admin plane reports it: configured target, current
    /// address, weight, health, in-flight exchanges and administration state.
    #[must_use]
    pub fn servers_view(&self) -> Vec<ServerView> {
        let state = self.state();
        state
            .iter()
            .map(|server| {
                let mode = self.mode_of(server);
                ServerView {
                    target: server.target.clone(),
                    addr: server.addr,
                    weight: server.weight,
                    backup: server.backup,
                    priority: server.priority,
                    up: server.up,
                    active: server.active,
                    mode,
                    drained: mode != ServerMode::Ready && server.active == 0,
                }
            })
            .collect()
    }

    /// Shared state; a poisoned lock (a previous panic on another thread)
    /// recovers with the state intact instead of propagating the panic.
    fn state(&self) -> MutexGuard<'_, Vec<ServerState>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Resolved server addresses (configuration order). Unresolved name
    /// slots are not included: they cannot be connected to (B-H13).
    #[must_use]
    pub fn resolved_servers(&self) -> Vec<SocketAddr> {
        self.state().iter().filter_map(|s| s.addr).collect()
    }

    /// Number of server slots (resolved or not). Slot indexes are stable
    /// across DNS re-resolutions: affinity tokens use them.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.state().len()
    }

    /// Stable slot index of the server currently at `addr`.
    #[must_use]
    pub fn slot_of(&self, addr: SocketAddr) -> Option<usize> {
        self.state().iter().position(|s| s.addr == Some(addr))
    }

    /// Current address of a stable slot index (`None` = unresolved).
    #[must_use]
    pub fn addr_of_slot(&self, idx: usize) -> Option<SocketAddr> {
        self.state().get(idx).and_then(|s| s.addr)
    }

    /// Unique `HOSTNAME:PORT` targets to resolve (B-H13/B-N18/B-E15).
    #[must_use]
    pub fn name_targets(&self) -> Vec<(String, u16)> {
        let mut names: Vec<(String, u16)> = Vec::new();
        for target in &self.targets {
            if let ServerAddr::Name { host, port } = target
                && !names.contains(&(host.clone(), *port))
            {
                names.push((host.clone(), *port));
            }
        }
        names
    }

    /// Applies one resolution round (B-H13/B-N18/B-E15): every
    /// `HOSTNAME:PORT` slot matching `host`/`port` gets the **first**
    /// resolved address (nginx `server name:port` semantics; multi-A
    /// expansion is a declared gap). An empty result keeps the
    /// last-known address (nginx `valid=` / HAProxy `init-addr last`
    /// semantics). A **changed** address resets the health machine and
    /// the slow-start ramp: the endpoint is new and cold. Returns how
    /// many slots changed address.
    pub fn apply_resolution(&self, host: &str, port: u16, addrs: &[SocketAddr]) -> usize {
        let Some(&new) = addrs.first() else {
            return 0;
        };
        let mut state = self.state();
        let mut changed = 0;
        for (idx, target) in self.targets.iter().enumerate() {
            if !matches!(target, ServerAddr::Name { host: h, port: p } if *p == port && h == host) {
                continue;
            }
            let Some(server) = state.get_mut(idx) else {
                continue;
            };
            if server.addr != Some(new) {
                server.addr = Some(new);
                server.consecutive_fails = 0;
                server.consecutive_rises = 0;
                server.up = true;
                server.current_weight = 0;
                server.up_since = Instant::now();
                changed += 1;
            }
        }
        changed
    }

    /// Balancing algorithm (B-H5/B-N12/B-E6).
    #[must_use]
    pub fn algorithm(&self) -> Balance {
        self.algorithm
    }

    /// Health-machine thresholds (`fall`, `rise`; B11).
    #[must_use]
    pub fn thresholds(&self) -> (u32, u32) {
        (self.fall, self.rise)
    }

    /// Effective weight of `addr` at this instant, in milli-units
    /// (B14: configured weight × slow-start ramp; 0 = not selectable).
    #[must_use]
    pub fn effective_weight(&self, addr: SocketAddr) -> i64 {
        let state = self.state();
        state
            .iter()
            .position(|s| s.addr == Some(addr))
            .and_then(|idx| state.get(idx))
            .map_or(0, |server| self.eff_weight(server, Instant::now()))
    }

    /// Exchanges currently in flight on `addr` (B-H5 leastconn metric).
    #[must_use]
    pub fn active_count(&self, addr: SocketAddr) -> u32 {
        let state = self.state();
        state
            .iter()
            .position(|s| s.addr == Some(addr))
            .and_then(|idx| state.get(idx))
            .map_or(0, |server| server.active)
    }

    /// Selects the next operational server, or `None` when all are down
    /// (or all with `weight = 0`). Pure selection: no in-flight slot.
    #[must_use]
    pub fn pick(&self) -> Option<SocketAddr> {
        self.pick_except(&[])
    }

    /// Like [`pick`](Self::pick) but skipping `exclude`: a connect-phase
    /// retry picks another server than the one that just failed (B-H7).
    /// Pure selection: no in-flight slot.
    #[must_use]
    pub fn pick_except(&self, exclude: &[SocketAddr]) -> Option<SocketAddr> {
        let mut state = self.state();
        let idx = self.select(&mut state, None, exclude)?;
        state[idx].addr
    }

    /// [`pick`](Self::pick) holding one in-flight slot on the chosen
    /// server. The slot is taken under the same lock as the pick (no
    /// pick/lease race) and released when the guard drops (B-H5).
    #[must_use]
    pub fn pick_tracked(&self, exclude: &[SocketAddr]) -> Option<(SocketAddr, ActiveGuard<'_>)> {
        let mut state = self.state();
        let idx = self.select(&mut state, None, exclude)?;
        state[idx].active = state[idx].active.saturating_add(1);
        let addr = state[idx].addr?;
        Some((
            addr,
            ActiveGuard {
                balancer: self,
                idx,
            },
        ))
    }

    /// Affinity (B-H8/B-N13/B-I8): serve `preferred` when it is eligible;
    /// otherwise the next eligible server in configuration order after it
    /// (nginx `ip_hash` fallback), else nothing. `preferred = None` is the
    /// plain [`pick_except`](Self::pick_except). Pure selection.
    #[must_use]
    pub fn pick_pinned(
        &self,
        preferred: Option<SocketAddr>,
        exclude: &[SocketAddr],
    ) -> Option<SocketAddr> {
        let mut state = self.state();
        let idx = self.select(&mut state, preferred, exclude)?;
        state[idx].addr
    }

    /// [`pick_pinned`](Self::pick_pinned) holding one in-flight slot on the
    /// chosen server (B-H5), released when the guard drops.
    #[must_use]
    pub fn pick_pinned_tracked(
        &self,
        preferred: Option<SocketAddr>,
        exclude: &[SocketAddr],
    ) -> Option<(SocketAddr, ActiveGuard<'_>)> {
        let mut state = self.state();
        let idx = self.select(&mut state, preferred, exclude)?;
        state[idx].active = state[idx].active.saturating_add(1);
        let addr = state[idx].addr?;
        Some((
            addr,
            ActiveGuard {
                balancer: self,
                idx,
            },
        ))
    }

    /// Core selection: affinity first (B-H8), then the configured
    /// algorithm over the eligible servers (up, not drained, not excluded).
    ///
    /// Backup servers (B8) form a second tier: whenever at least one primary
    /// is eligible, only primaries are considered; backups are selected only
    /// when the primary tier is empty (down, drained, weight 0, unresolved or
    /// excluded by a retry). Inside the backup tier there are two declared
    /// modes:
    ///
    /// - the reference default: one **ladder**, rungs ordered by `priority`
    ///   (higher first), then configuration order, and only the first
    ///   operational rung serves — "only the first operational backup server
    ///   is used" (HAProxy 3.4 `backup`);
    /// - `option allbackups` ([`Self::with_all_backups`]): every eligible
    ///   backup is a candidate, so the algorithm and the weights spread load
    ///   across them — the reference states there is no priority order among
    ///   the backups then.
    ///
    /// A backend whose servers are all backups follows the same mode.
    fn select(
        &self,
        state: &mut [ServerState],
        preferred: Option<SocketAddr>,
        exclude: &[SocketAddr],
    ) -> Option<usize> {
        let eligible = |idx: usize, state: &[ServerState]| {
            // Unresolved name slots (B-H13) are never selectable, a drained
            // one leaves rotation without touching its health (ADR-0018).
            state[idx].addr.is_some()
                && state[idx].up
                && state[idx].weight > 0
                && self.mode_of(&state[idx]) == ServerMode::Ready
                && !state[idx].addr.is_some_and(|a| exclude.contains(&a))
        };
        // B8: one tier at a time. Primaries are the top tier; when none is
        // eligible the backup tier serves. With `option allbackups` every
        // eligible backup is a candidate (the algorithm and the weights
        // spread across them); otherwise the ladder serves its first
        // operational rung, ordered by `priority` (higher first) and then
        // configuration order.
        let has_primary = state
            .iter()
            .enumerate()
            .any(|(idx, server)| !server.backup && eligible(idx, state));
        let active_backup = if has_primary || self.all_backups {
            None
        } else {
            state
                .iter()
                .enumerate()
                .filter(|(idx, server)| server.backup && eligible(*idx, state))
                .min_by_key(|(idx, server)| (std::cmp::Reverse(server.priority), *idx))
                .map(|(idx, _)| idx)
        };
        let available = |idx: usize, state: &[ServerState]| {
            eligible(idx, state)
                && if has_primary {
                    !state[idx].backup
                } else if self.all_backups {
                    state[idx].backup
                } else {
                    Some(idx) == active_backup
                }
        };
        // Affinity pin (B-H8/B-N13/B-I8): preferred when eligible, else
        // the next eligible in configuration order after it (ip_hash
        // fallback). Affinity never consults load or weights.
        if let Some(start) =
            preferred.and_then(|addr| state.iter().position(|s| s.addr == Some(addr)))
        {
            return (0..state.len()).find_map(|offset| {
                let idx = (start + offset) % state.len();
                available(idx, state).then_some(idx)
            });
        }
        let mut candidates: Vec<usize> = (0..state.len())
            .filter(|&idx| available(idx, state))
            .collect();
        let first = *candidates.first()?;
        let now = Instant::now();
        if self.algorithm == Balance::LeastConn {
            // Weighted least-connections (nginx `least_conn` semantics):
            // keep only the servers with the smallest
            // `active / effective_weight` ratio (cross-multiplied).
            let mut best = first;
            for &idx in &candidates {
                let (server, winner) = (&state[idx], &state[best]);
                let load = i64::from(server.active) * self.eff_weight(winner, now);
                let best_load = i64::from(winner.active) * self.eff_weight(server, now);
                if load < best_load {
                    best = idx;
                }
            }
            candidates.retain(|&idx| {
                let (server, winner) = (&state[idx], &state[best]);
                i64::from(server.active) * self.eff_weight(winner, now)
                    == i64::from(winner.active) * self.eff_weight(server, now)
            });
        }
        // Smooth weighted round-robin among the candidates (B1/B7):
        // deterministic, ties follow configuration order.
        let mut total: i64 = 0;
        let mut chosen: Option<usize> = None;
        let mut best_weight: i64 = 0;
        for &idx in &candidates {
            let eff = self.eff_weight(&state[idx], now);
            let server = &mut state[idx];
            server.current_weight += eff;
            total += eff;
            if chosen.is_none_or(|_| server.current_weight > best_weight) {
                chosen = Some(idx);
                best_weight = server.current_weight;
            }
        }
        let chosen = chosen?;
        state[chosen].current_weight -= total;
        Some(chosen)
    }

    /// Effective weight in milli-units (B14 dynamic weighting): the
    /// configured weight scaled by the slow-start ramp. A server that is
    /// operational always keeps at least 1 milli-unit (never a black hole).
    fn eff_weight(&self, server: &ServerState, now: Instant) -> i64 {
        if server.weight == 0 {
            return 0;
        }
        let full = i64::from(server.weight) * SCALE;
        if self.slow_start.is_zero() {
            return full;
        }
        let elapsed = now.saturating_duration_since(server.up_since);
        if elapsed >= self.slow_start {
            return full;
        }
        let ramped = full.saturating_mul(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
            / i64::try_from(self.slow_start.as_millis())
                .unwrap_or(1)
                .max(1);
        ramped.clamp(1, full)
    }

    /// Records a successful health check (`rise` machine).
    pub fn report_ok(&self, addr: SocketAddr) {
        self.report(addr, true);
    }

    /// Records a failed health check (`fall` machine).
    pub fn report_fail(&self, addr: SocketAddr) {
        self.report(addr, false);
    }

    fn report(&self, addr: SocketAddr, ok: bool) {
        let mut state = self.state();
        if let Some(idx) = state.iter().position(|s| s.addr == Some(addr))
            && let Some(server) = state.get_mut(idx)
        {
            if ok {
                server.consecutive_fails = 0;
                server.consecutive_rises = server.consecutive_rises.saturating_add(1);
                if !server.up && server.consecutive_rises >= self.rise {
                    server.up = true;
                    server.current_weight = 0;
                    // B14: the slow-start ramp restarts on every transition
                    // into operational (recovery, and startup in `new`).
                    server.up_since = Instant::now();
                }
            } else {
                server.consecutive_rises = 0;
                server.consecutive_fails = server.consecutive_fails.saturating_add(1);
                if server.up && server.consecutive_fails >= self.fall {
                    server.up = false;
                    server.current_weight = 0;
                }
            }
        }
    }

    /// Is the server operational?
    #[must_use]
    pub fn is_up(&self, addr: SocketAddr) -> bool {
        let state = self.state();
        state
            .iter()
            .position(|s| s.addr == Some(addr))
            .and_then(|idx| state.get(idx))
            .is_some_and(|server| server.up)
    }

    /// Number of operational and resolved servers.
    #[must_use]
    pub fn up_count(&self) -> usize {
        self.state()
            .iter()
            .filter(|s| s.up && s.addr.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn server(port: u16, weight: u32) -> ResolvedServer {
        ResolvedServer {
            addr: ServerAddr::Ip(ip(port)),
            weight,
            backup: false,
            priority: 0,
        }
    }

    fn backup(port: u16, weight: u32) -> ResolvedServer {
        backup_with(port, weight, 0)
    }

    fn backup_with(port: u16, weight: u32, priority: u32) -> ResolvedServer {
        ResolvedServer {
            addr: ServerAddr::Ip(ip(port)),
            weight,
            backup: true,
            priority,
        }
    }

    fn named(host: &str, port: u16, weight: u32) -> ResolvedServer {
        ResolvedServer {
            backup: false,
            priority: 0,
            addr: ServerAddr::Name {
                host: host.to_owned(),
                port,
            },
            weight,
        }
    }

    #[test]
    fn pick_rotates_deterministically_with_equal_weights() {
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1), server(3, 1)], 3, 2);
        let picks: Vec<u16> = (0..6)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        assert_eq!(
            picks,
            vec![1, 2, 3, 1, 2, 3],
            "fixed rotation in config order"
        );
    }
    #[test]
    fn pick_respects_weights_over_full_cycles() {
        let balancer = Balancer::new(vec![server(1, 1), server(2, 3)], 3, 2);
        let picks: Vec<u16> = (0..8)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        assert_eq!(
            picks.len(),
            8,
            "with operational servers there is always a pick"
        );
        let a = picks.iter().filter(|port| **port == 1).count();
        let b = picks.iter().filter(|port| **port == 2).count();
        assert_eq!((a, b), (2, 6), "1:3 ratio over two full cycles");
    }

    #[test]
    fn drained_server_is_never_picked_but_others_are() {
        let balancer = Balancer::new(vec![server(1, 0), server(2, 1)], 3, 2);
        for _ in 0..4 {
            assert_eq!(balancer.pick().map(|a| a.port()), Some(2));
        }
        assert_eq!(balancer.up_count(), 2, "weight=0 stays operational");
    }

    #[test]
    fn pick_except_skips_excluded_servers() {
        let a: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
        let b: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
        let balancer = Balancer::new(
            vec![
                ResolvedServer {
                    addr: a.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: b.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
            ],
            3,
            2,
        );
        assert_eq!(balancer.pick_except(&[a]), Some(b), "a is excluded");
        assert_eq!(balancer.pick_except(&[a]), Some(b), "still b");
        assert_eq!(
            balancer.pick_except(&[a, b]),
            None,
            "with every server excluded there is no candidate"
        );
        assert!(balancer.pick_except(&[]).is_some(), "no exclusion works");
    }

    #[test]
    fn pick_returns_none_when_all_servers_are_down_or_drained() {
        let balancer = Balancer::new(vec![server(1, 1)], 1, 1);
        balancer.report_fail(ip(1));
        assert!(!balancer.is_up(ip(1)));
        assert!(balancer.pick().is_none());

        let drained = Balancer::new(vec![server(2, 0)], 1, 1);
        assert!(drained.pick().is_none());
    }

    #[test]
    fn fall_and_rise_thresholds_gate_transitions() {
        let addr = ip(1);
        let balancer = Balancer::new(vec![server(1, 1)], 2, 2);

        balancer.report_fail(addr);
        assert!(balancer.is_up(addr), "1 failure with fall=2 does not drop");
        balancer.report_fail(addr);
        assert!(!balancer.is_up(addr), "2 failures with fall=2 drop");

        // A success followed by a failure resets the rise count.
        balancer.report_ok(addr);
        assert!(
            !balancer.is_up(addr),
            "1 success with rise=2 does not raise"
        );
        balancer.report_fail(addr);
        assert!(!balancer.is_up(addr));
        balancer.report_ok(addr);
        balancer.report_ok(addr);
        assert!(balancer.is_up(addr), "2 successes with rise=2 raise");
    }

    // ------------------------------------------- B-H5: least-connections ---

    #[test]
    fn leastconn_prefers_the_server_with_the_fewest_active_exchanges() {
        let a = ip(1);
        let b = ip(2);
        let balancer = Balancer::with_options(
            vec![server(1, 1), server(2, 1)],
            3,
            2,
            Balance::LeastConn,
            Duration::ZERO,
        );
        let held = balancer.pick_tracked(&[]).expect("pick").1;
        assert_eq!(balancer.active_count(a), 1, "the held exchange is on A");
        for _ in 0..5 {
            let (addr, _guard) = balancer.pick_tracked(&[]).expect("pick");
            assert_eq!(addr, b, "A is loaded; every new pick goes to B");
        }
        drop(held);
        assert_eq!(balancer.active_count(a), 0, "the slot is released on drop");
    }

    #[test]
    fn leastconn_weights_share_load_by_conns_over_weight() {
        // Weighted least-connections: with weights 2:1 and all responses
        // held, 6 in-flight exchanges split 4:2 whatever the tie order.
        let balancer = Balancer::with_options(
            vec![server(1, 2), server(2, 1)],
            3,
            2,
            Balance::LeastConn,
            Duration::ZERO,
        );
        let mut held = Vec::new();
        for _ in 0..6 {
            held.push(balancer.pick_tracked(&[]).expect("pick"));
        }
        let a = balancer.active_count(ip(1));
        let b = balancer.active_count(ip(2));
        assert_eq!((a, b), (4, 2), "in-flight split follows the 2:1 weights");
        drop(held);
    }

    #[test]
    fn leastconn_ties_rotate_smoothly() {
        let balancer = Balancer::with_options(
            vec![server(1, 1), server(2, 1)],
            3,
            2,
            Balance::LeastConn,
            Duration::ZERO,
        );
        let picks: Vec<u16> = (0..4)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        assert_eq!(picks, vec![1, 2, 1, 2], "zero load ties fall to SWRR");
    }

    // ------------------------------------------------ B14: slow start ------

    #[test]
    fn slow_start_ramps_the_recovered_server_up() {
        let a = ip(1);
        let b = ip(2);
        let balancer = Balancer::with_options(
            vec![server(1, 1), server(2, 1)],
            3,
            2,
            Balance::RoundRobin,
            Duration::from_secs(3600),
        );
        // A has been operational for a long window (full weight); B just
        // recovered (fresh ramp).
        {
            let mut state = balancer.state();
            state[0].up_since = Instant::now() - Duration::from_secs(7200);
        }
        balancer.report_fail(b);
        balancer.report_ok(b);
        assert!(balancer.is_up(b));
        let eff_a = balancer.effective_weight(a);
        let eff_b = balancer.effective_weight(b);
        assert!(
            eff_b < eff_a / 100,
            "the fresh ramp must be a tiny fraction: eff_a={eff_a} eff_b={eff_b}"
        );
        for _ in 0..10 {
            assert_eq!(
                balancer.pick().map(|addr| addr.port()),
                Some(1),
                "all early traffic goes to the fully ramped server"
            );
        }
        // Once the ramp is over the weights are equal again.
        {
            let mut state = balancer.state();
            state[1].up_since = Instant::now() - Duration::from_secs(7200);
        }
        assert_eq!(balancer.effective_weight(b), eff_a, "ramp complete");
        let picks: Vec<u16> = (0..4)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        let a_picks = picks.iter().filter(|port| **port == 1).count();
        let b_picks = picks.iter().filter(|port| **port == 2).count();
        assert_eq!(
            (a_picks, b_picks),
            (2, 2),
            "full weights restore the 1:1 split (got {picks:?})"
        );
    }

    #[test]
    fn slow_start_zero_keeps_full_weights_after_recovery() {
        let a = ip(1);
        let b = ip(2);
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1);
        balancer.report_fail(b);
        balancer.report_ok(b);
        assert_eq!(
            (balancer.effective_weight(a), balancer.effective_weight(b)),
            (SCALE, SCALE),
            "without slow start a recovered server is immediately full"
        );
    }

    #[test]
    fn tracked_picks_take_and_release_the_slot() {
        let a = ip(1);
        let balancer = Balancer::new(vec![server(1, 1)], 1, 1);
        let (addr, guard) = balancer.pick_tracked(&[]).expect("pick");
        assert_eq!(addr, a);
        assert_eq!(balancer.active_count(a), 1);
        drop(guard);
        assert_eq!(balancer.active_count(a), 0);
    }

    // --------------------------------------- B-H13: dynamic DNS slots ---

    #[test]
    fn named_servers_start_unresolved_and_pick_nothing() {
        let balancer = Balancer::new(vec![named("api.internal", 9000, 1)], 1, 1);
        assert_eq!(
            balancer.pick(),
            None,
            "an unresolved name is never selected (the caller answers 503)"
        );
        assert_eq!(balancer.resolved_servers(), Vec::<SocketAddr>::new());
        assert_eq!(balancer.up_count(), 0, "unresolved is not operational");
        assert_eq!(
            balancer.name_targets(),
            vec![("api.internal".to_owned(), 9000)]
        );

        let addr: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        assert_eq!(
            balancer.apply_resolution("api.internal", 9000, &[addr]),
            1,
            "one slot resolved"
        );
        assert_eq!(balancer.pick(), Some(addr), "the resolved name serves");
        assert_eq!(balancer.resolved_servers(), vec![addr]);
    }

    #[test]
    fn re_resolution_swaps_the_address_and_resets_health() {
        let balancer = Balancer::new(vec![named("api.internal", 9000, 1)], 1, 1);
        let old: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        let new: SocketAddr = "10.0.0.2:9000".parse().expect("addr");
        balancer.apply_resolution("api.internal", 9000, &[old]);
        balancer.report_fail(old);
        assert!(!balancer.is_up(old), "fall = 1 drops the old endpoint");
        assert_eq!(balancer.pick(), None);

        assert_eq!(balancer.apply_resolution("api.internal", 9000, &[new]), 1);
        assert!(
            balancer.is_up(new),
            "a changed address is a new endpoint: operational and cold"
        );
        assert_eq!(
            balancer.pick(),
            Some(new),
            "traffic moves to the new address"
        );
        assert_eq!(
            balancer.effective_weight(new),
            SCALE,
            "no slow start configured: full weight"
        );
    }

    #[test]
    fn empty_or_repeated_resolutions_keep_the_last_known_state() {
        let balancer = Balancer::new(vec![named("api.internal", 9000, 1)], 1, 1);
        let addr: SocketAddr = "10.0.0.1:9000".parse().expect("addr");
        balancer.apply_resolution("api.internal", 9000, &[addr]);
        balancer.report_fail(addr);

        // Empty answer: keep the last-known address (and its health).
        assert_eq!(balancer.apply_resolution("api.internal", 9000, &[]), 0);
        assert_eq!(balancer.resolved_servers(), vec![addr]);
        assert!(!balancer.is_up(addr), "health state is untouched");

        // Same answer again: no change, no reset.
        assert_eq!(balancer.apply_resolution("api.internal", 9000, &[addr]), 0);
        assert!(!balancer.is_up(addr));
        assert_eq!(
            balancer.apply_resolution("other.internal", 9000, &[addr]),
            0,
            "only slots with this exact name match"
        );
    }

    #[test]
    fn unresolved_slots_never_shadow_resolved_ones() {
        let balancer = Balancer::new(vec![named("cold.internal", 9000, 1), server(1, 1)], 1, 1);
        for _ in 0..4 {
            assert_eq!(
                balancer.pick(),
                Some(ip(1)),
                "the literal server takes all the traffic while the name is unresolved"
            );
        }
    }

    #[test]
    fn pinned_tracked_picks_honor_affinity_and_hold_a_slot() {
        let b = ip(2);
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1);
        let (addr, guard) = balancer.pick_pinned_tracked(Some(b), &[]).expect("pick");
        assert_eq!(addr, b, "the pin wins over load");
        assert_eq!(balancer.active_count(b), 1);
        drop(guard);
        assert_eq!(balancer.active_count(b), 0);
    }

    // ------------------------------------ ADR-0018: admin server state ---

    #[test]
    fn drain_removes_a_server_from_new_picks_and_ready_returns_it() {
        let modes = Arc::new(ServerModes::new());
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        for _ in 0..6 {
            assert_eq!(
                balancer.pick().map(|addr| addr.port()),
                Some(2),
                "the drained slot never wins a pick"
            );
        }
        assert!(
            balancer.is_up(ip(1)),
            "drain is an admin decision, not a health failure"
        );
        assert_eq!(balancer.up_count(), 2, "both servers stay operational");

        // Idempotent declaration, then back to rotation.
        assert_eq!(
            modes.set("api", "127.0.0.1:1", ServerMode::Drain),
            ServerMode::Drain
        );
        assert_eq!(
            modes.set("api", "127.0.0.1:1", ServerMode::Ready),
            ServerMode::Drain
        );
        let picks: Vec<u16> = (0..4)
            .filter_map(|_| balancer.pick())
            .map(|addr| addr.port())
            .collect();
        assert_eq!(picks, vec![1, 2, 1, 2], "ready restores the rotation");
    }

    #[test]
    fn all_drained_means_no_candidate() {
        let modes = Arc::new(ServerModes::new());
        let balancer =
            Balancer::new(vec![server(1, 1)], 1, 1).with_modes("api", Arc::clone(&modes));
        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        assert_eq!(
            balancer.pick(),
            None,
            "the caller answers 503 when every server is drained"
        );
    }

    #[test]
    fn modes_are_per_backend_and_survive_a_rebuilt_balancer() {
        let modes = Arc::new(ServerModes::new());
        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        // Same target in another backend is untouched.
        assert_eq!(modes.get("other", "127.0.0.1:1"), ServerMode::Ready);
        // A reload builds a new balancer with the same registry: the drain
        // is still in force.
        let rebuilt = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        assert_eq!(
            rebuilt.pick().map(|addr| addr.port()),
            Some(2),
            "state outlives the Balancer it was declared on"
        );
        assert_eq!(
            ServerMode::parse("drain"),
            Some(ServerMode::Drain),
            "wire name"
        );
        assert_eq!(
            ServerMode::parse("maintenance"),
            Some(ServerMode::Maintenance),
            "wire name"
        );
        assert_eq!(ServerMode::parse("maint"), None, "no aliases");
    }

    #[test]
    fn servers_view_reports_target_health_mode_and_in_flight() {
        let modes = Arc::new(ServerModes::new());
        let balancer = Balancer::new(vec![server(9000, 1), server(9001, 2)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        modes.set("api", "127.0.0.1:9001", ServerMode::Drain);
        let guard = balancer.pick_tracked(&[]).expect("pick").1;
        let view = balancer.servers_view();
        assert_eq!(view.len(), 2);
        assert_eq!(view[0].target, "127.0.0.1:9000");
        assert_eq!(view[0].addr, Some(ip(9000)));
        assert_eq!(view[0].weight, 1);
        assert!(view[0].up);
        assert_eq!(view[0].mode, ServerMode::Ready);
        assert_eq!(view[0].active, 1, "the held slot is visible");
        assert!(!view[0].drained, "a ready slot is never drained");
        assert_eq!(view[1].mode, ServerMode::Drain);
        assert_eq!(view[1].active, 0);
        assert!(
            view[1].drained,
            "a drained slot with nothing in flight has finished draining"
        );
        assert_eq!(view[1].weight, 2);
        drop(guard);
        assert_eq!(
            balancer.servers_view()[0].active,
            0,
            "the slot is released on drop"
        );
    }

    #[test]
    fn drain_completion_is_counted_when_the_last_exchange_finishes() {
        let modes = Arc::new(ServerModes::new());
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        let (_, first) = balancer
            .pick_pinned_tracked(Some(ip(1)), &[])
            .expect("first");
        let (_, second) = balancer
            .pick_pinned_tracked(Some(ip(1)), &[])
            .expect("second");
        // An exchange finishing on a ready slot is not a drain event.
        drop(first);
        assert_eq!(balancer.drains_completed(), 0);

        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        let view = balancer
            .servers_view()
            .into_iter()
            .find(|server| server.target == "127.0.0.1:1")
            .expect("slot");
        assert_eq!(view.active, 1, "the second exchange is still in flight");
        assert!(
            !view.drained,
            "a drain with work in flight has not finished (H3)"
        );

        drop(second);
        assert_eq!(
            balancer.drains_completed(),
            1,
            "the exchange that ends the drain is the event, exactly once"
        );
        let view = balancer
            .servers_view()
            .into_iter()
            .find(|server| server.target == "127.0.0.1:1")
            .expect("slot");
        assert_eq!(view.active, 0);
        assert!(view.drained);
        // No drained exchange is left to finish: nothing more is counted.
        assert_eq!(balancer.drains_completed(), 1);
    }

    #[test]
    fn drain_of_an_idle_slot_reports_finished_without_an_event() {
        let modes = Arc::new(ServerModes::new());
        let balancer =
            Balancer::new(vec![server(1, 1)], 1, 1).with_modes("api", Arc::clone(&modes));
        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        let view = balancer.servers_view().remove(0);
        assert!(view.drained, "there was nothing to wait for");
        assert_eq!(
            balancer.drains_completed(),
            0,
            "no exchange ended after the drain was declared"
        );
    }

    #[test]
    fn maintenance_removes_the_slot_like_a_drain_does() {
        let modes = Arc::new(ServerModes::new());
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        modes.set("api", "127.0.0.1:1", ServerMode::Maintenance);
        for _ in 0..6 {
            assert_eq!(
                balancer.pick().map(|addr| addr.port()),
                Some(2),
                "a maintenance slot takes no new exchange"
            );
        }
        let view = balancer.servers_view().remove(0);
        assert_eq!(view.mode, ServerMode::Maintenance);
        assert!(
            view.drained,
            "a maintenance slot with nothing in flight is already finished"
        );
        assert!(view.up, "the health axis is deliberately untouched");
        // Restoring it puts it back in rotation.
        modes.set("api", "127.0.0.1:1", ServerMode::Ready);
        assert!(
            (0..6).any(|_| balancer.pick().map(|addr| addr.port()) == Some(1)),
            "ready puts the slot back"
        );
    }

    #[test]
    fn the_guard_reports_the_mode_of_its_own_slot() {
        let modes = Arc::new(ServerModes::new());
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        let (_, guard) = balancer
            .pick_pinned_tracked(Some(ip(1)), &[])
            .expect("pick");
        assert_eq!(guard.mode(), ServerMode::Ready, "a fresh slot is ready");
        modes.set("api", "127.0.0.1:2", ServerMode::Maintenance);
        assert_eq!(
            guard.mode(),
            ServerMode::Ready,
            "another slot's state is not this guard's"
        );
        modes.set("api", "127.0.0.1:1", ServerMode::Maintenance);
        assert_eq!(
            guard.mode(),
            ServerMode::Maintenance,
            "the declaration is seen by the guard holding the exchange"
        );
    }

    #[test]
    fn maintenance_completion_is_not_a_drain_completion() {
        let modes = Arc::new(ServerModes::new());
        let balancer =
            Balancer::new(vec![server(1, 1)], 1, 1).with_modes("api", Arc::clone(&modes));
        let (_, guard) = balancer
            .pick_pinned_tracked(Some(ip(1)), &[])
            .expect("pick");
        modes.set("api", "127.0.0.1:1", ServerMode::Maintenance);
        let view = balancer.servers_view().remove(0);
        assert_eq!(view.active, 1, "the exchange is still in flight");
        assert!(!view.drained, "the window is not open yet");
        drop(guard);
        let view = balancer.servers_view().remove(0);
        assert!(view.drained, "the window opens when the last exchange ends");
        assert_eq!(
            balancer.drains_completed(),
            0,
            "the drain counter is drain-only (ADR-0028)"
        );
    }

    #[test]
    fn backup_is_never_selected_while_a_primary_is_eligible() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 1)], 1, 1);
        for _ in 0..12 {
            assert_eq!(
                balancer.pick(),
                Some(ip(1)),
                "a healthy primary owns every selection"
            );
        }
        let view = balancer
            .servers_view()
            .into_iter()
            .find(|server| server.target == "127.0.0.1:2")
            .expect("backup slot");
        assert!(view.backup, "the live view says which slot is a backup");
        assert!(view.up, "a backup keeps being health-checked");
    }

    #[test]
    fn backup_takes_over_when_every_primary_is_down_and_returns_on_recovery() {
        let balancer = Balancer::new(vec![server(1, 1), server(2, 1), backup(3, 1)], 1, 1);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..6 {
            seen.insert(balancer.pick().expect("primary eligible").port());
        }
        assert_eq!(seen, std::collections::BTreeSet::from([1, 2]));

        balancer.report_fail(ip(1));
        balancer.report_fail(ip(2));
        for _ in 0..4 {
            assert_eq!(
                balancer.pick(),
                Some(ip(3)),
                "with no primary eligible the backup takes every selection"
            );
        }

        balancer.report_ok(ip(2));
        assert_eq!(
            balancer.pick(),
            Some(ip(2)),
            "the first recovered primary takes the tier back"
        );
        assert_eq!(balancer.pick(), Some(ip(2)));
    }

    #[test]
    fn weight_zero_and_drained_primaries_leave_the_backup_in_rotation() {
        let zero_weight = Balancer::new(vec![server(1, 0), backup(2, 1)], 1, 1);
        assert_eq!(
            zero_weight.pick(),
            Some(ip(2)),
            "weight 0 is not an eligible primary"
        );

        let modes = Arc::new(ServerModes::new());
        let drained = Balancer::new(vec![server(1, 1), backup(2, 1)], 1, 1)
            .with_modes("api", Arc::clone(&modes));
        assert_eq!(drained.pick(), Some(ip(1)));
        modes.set("api", "127.0.0.1:1", ServerMode::Drain);
        assert_eq!(
            drained.pick(),
            Some(ip(2)),
            "a drained primary releases the tier to the backup"
        );
        modes.set("api", "127.0.0.1:1", ServerMode::Ready);
        assert_eq!(
            drained.pick(),
            Some(ip(1)),
            "undrain puts the primary back in front of the backup"
        );
    }

    #[test]
    fn a_retry_that_excludes_the_primary_uses_the_backup() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 1)], 1, 1);
        assert_eq!(
            balancer.pick_except(&[ip(1)]),
            Some(ip(2)),
            "a retry that already tried the primary may reach the backup"
        );
    }

    #[test]
    fn affinity_never_pins_to_a_backup_while_a_primary_is_up() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 1)], 1, 1);
        assert_eq!(
            balancer.pick_pinned(Some(ip(2)), &[]),
            Some(ip(1)),
            "a sticky key aimed at a backup is served by the eligible primary"
        );
        balancer.report_fail(ip(1));
        assert_eq!(
            balancer.pick_pinned(Some(ip(2)), &[]),
            Some(ip(2)),
            "with the primary down the pinned backup serves"
        );
    }

    #[test]
    fn a_backend_of_only_backups_serves_the_first_operational_rung() {
        let balancer = Balancer::new(vec![backup(1, 1), backup(2, 1)], 1, 1);
        for _ in 0..6 {
            assert_eq!(
                balancer.pick(),
                Some(ip(1)),
                "the reference uses only the first operational backup"
            );
        }
        balancer.report_fail(ip(1));
        assert_eq!(balancer.pick(), Some(ip(2)), "the next rung takes over");
        balancer.report_ok(ip(1));
        assert_eq!(
            balancer.pick(),
            Some(ip(1)),
            "the first rung takes the tier back when it recovers"
        );
    }

    #[test]
    fn priority_orders_the_backup_ladder() {
        let balancer = Balancer::new(
            vec![
                server(1, 1),
                backup_with(2, 1, 5),
                backup_with(3, 1, 10),
                backup_with(4, 1, 5),
            ],
            1,
            1,
        );
        balancer.report_fail(ip(1));
        for _ in 0..6 {
            assert_eq!(
                balancer.pick(),
                Some(ip(3)),
                "the highest priority rung owns the backup tier"
            );
        }
        balancer.report_fail(ip(3));
        for _ in 0..4 {
            assert_eq!(
                balancer.pick(),
                Some(ip(2)),
                "ties follow configuration order and only the first rung serves"
            );
        }
        balancer.report_ok(ip(3));
        assert_eq!(
            balancer.pick(),
            Some(ip(3)),
            "a recovered higher rung takes the traffic back"
        );
        balancer.report_ok(ip(1));
        assert_eq!(
            balancer.pick(),
            Some(ip(1)),
            "a primary always outranks the whole backup ladder"
        );
    }

    #[test]
    fn a_retry_that_excludes_the_top_rung_uses_the_next_backup() {
        let balancer = Balancer::new(
            vec![server(1, 1), backup_with(2, 1, 5), backup_with(3, 1, 10)],
            1,
            1,
        );
        balancer.report_fail(ip(1));
        assert_eq!(
            balancer.pick_except(&[ip(3)]),
            Some(ip(2)),
            "a retry that already tried the top rung serves the next one"
        );
        assert_eq!(
            balancer.pick_except(&[ip(3), ip(2)]),
            None,
            "no rung is reused after it was tried"
        );
    }

    #[test]
    fn affinity_lands_on_the_active_backup_rung() {
        let balancer = Balancer::new(vec![backup_with(1, 1, 5), backup_with(2, 1, 10)], 1, 1);
        assert_eq!(
            balancer.pick_pinned(Some(ip(1)), &[]),
            Some(ip(2)),
            "a sticky key aimed at a lower rung is served by the active one"
        );
        assert_eq!(balancer.pick_pinned(Some(ip(2)), &[]), Some(ip(2)));
    }

    #[test]
    fn least_conn_uses_only_the_highest_priority_backup() {
        let balancer = Balancer::with_options(
            vec![server(1, 1), backup_with(2, 1, 5), backup_with(3, 1, 10)],
            1,
            1,
            Balance::LeastConn,
            Duration::ZERO,
        );
        balancer.report_fail(ip(1));
        for _ in 0..6 {
            assert_eq!(
                balancer.pick(),
                Some(ip(3)),
                "leastconn never reaches below the active rung"
            );
        }
    }

    #[test]
    fn least_conn_never_uses_the_backup_while_a_primary_is_eligible() {
        let balancer = Balancer::with_options(
            vec![server(1, 1), backup(2, 1)],
            1,
            1,
            Balance::LeastConn,
            Duration::ZERO,
        );
        let (addr, guard) = balancer.pick_tracked(&[]).expect("primary");
        assert_eq!(addr, ip(1));
        assert_eq!(
            balancer.pick(),
            Some(ip(1)),
            "the backup stays out even when the primary carries load"
        );
        drop(guard);
    }

    #[test]
    fn all_backups_balances_the_whole_tier_by_weight() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 2), backup(3, 1)], 1, 1)
            .with_all_backups(true);
        for _ in 0..4 {
            assert_eq!(
                balancer.pick(),
                Some(ip(1)),
                "a primary still outranks the whole backup pool"
            );
        }
        balancer.report_fail(ip(1));
        let picks: Vec<u16> = (0..9)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        let high = picks.iter().filter(|port| **port == 2).count();
        let low = picks.iter().filter(|port| **port == 3).count();
        assert_eq!(
            (high, low),
            (6, 3),
            "2:1 weights spread load inside the backup pool: {picks:?}"
        );
    }

    #[test]
    fn all_backups_drops_the_priority_ladder() {
        let balancer = Balancer::with_options(
            vec![backup_with(1, 1, 10), backup_with(2, 1, 5)],
            1,
            1,
            Balance::RoundRobin,
            Duration::ZERO,
        )
        .with_all_backups(true);
        let picks: Vec<u16> = (0..6)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        assert_eq!(
            picks,
            vec![1, 2, 1, 2, 1, 2],
            "the reference says there is no priority order between the backups anymore"
        );
    }

    #[test]
    fn all_backups_keeps_a_dead_member_out_and_a_retry_skips_the_one_it_tried() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 1), backup(3, 1)], 1, 1)
            .with_all_backups(true);
        balancer.report_fail(ip(1));
        balancer.report_fail(ip(2));
        for _ in 0..4 {
            assert_eq!(
                balancer.pick(),
                Some(ip(3)),
                "a dead pool member leaves rotation, the rest still serves"
            );
        }
        balancer.report_ok(ip(2));
        assert_eq!(
            balancer.pick_except(&[ip(2)]),
            Some(ip(3)),
            "a retry that already tried a pool member reaches the other one"
        );
        let picks: Vec<u16> = (0..4)
            .filter_map(|_| balancer.pick())
            .map(|a| a.port())
            .collect();
        assert!(
            picks.contains(&2) && picks.contains(&3),
            "a recovered pool member takes its share back: {picks:?}"
        );
    }

    #[test]
    fn all_backups_with_every_member_unusable_is_still_none() {
        let zero_weight = Balancer::new(vec![server(1, 1), backup(2, 0), backup(3, 0)], 1, 1)
            .with_all_backups(true);
        zero_weight.report_fail(ip(1));
        assert_eq!(
            zero_weight.pick(),
            None,
            "weight 0 leaves the pool with no candidate"
        );
        let down = Balancer::new(vec![server(1, 1), backup(2, 1), backup(3, 1)], 1, 1)
            .with_all_backups(true);
        down.report_fail(ip(1));
        down.report_fail(ip(2));
        down.report_fail(ip(3));
        assert_eq!(down.pick(), None, "an all-down pool answers 503 upstream");
    }

    #[test]
    fn least_conn_spreads_inside_the_backup_pool() {
        let balancer = Balancer::with_options(
            vec![server(1, 1), backup(2, 1), backup(3, 1)],
            1,
            1,
            Balance::LeastConn,
            Duration::ZERO,
        )
        .with_all_backups(true);
        balancer.report_fail(ip(1));
        let (first, guard_a) = balancer.pick_tracked(&[]).expect("pool member");
        let (second, guard_b) = balancer.pick_tracked(&[]).expect("pool member");
        assert_ne!(
            first, second,
            "leastconn takes the pool member with the fewest in-flight exchanges"
        );
        drop(guard_a);
        drop(guard_b);
    }

    #[test]
    fn affinity_pins_inside_the_backup_pool() {
        let balancer = Balancer::new(vec![backup(1, 1), backup(2, 1)], 1, 1).with_all_backups(true);
        assert_eq!(
            balancer.pick_pinned(Some(ip(1)), &[]),
            Some(ip(1)),
            "a sticky key keeps its pool member while that member is eligible"
        );
        assert_eq!(balancer.pick_pinned(Some(ip(2)), &[]), Some(ip(2)));
        balancer.report_fail(ip(1));
        assert_eq!(
            balancer.pick_pinned(Some(ip(1)), &[]),
            Some(ip(2)),
            "a sticky key aimed at a dead member falls to the next one in configuration order"
        );
    }

    #[test]
    fn all_servers_down_is_still_none() {
        let balancer = Balancer::new(vec![server(1, 1), backup(2, 1)], 1, 1);
        balancer.report_fail(ip(1));
        balancer.report_fail(ip(2));
        assert_eq!(balancer.pick(), None);
    }
}
