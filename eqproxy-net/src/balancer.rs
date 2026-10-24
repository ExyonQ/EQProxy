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

use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

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
}

#[derive(Debug, Clone)]
struct ServerState {
    /// Current resolved address. `None` = name still unresolved (B-H13):
    /// the slot is never selected and the caller answers 503 with the
    /// `no_available_server` metric until DNS lands.
    addr: Option<SocketAddr>,
    weight: u32,
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
    fall: u32,
    rise: u32,
    algorithm: Balance,
    slow_start: Duration,
    state: Mutex<Vec<ServerState>>,
    targets: Vec<ServerAddr>,
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
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.balancer.state();
        if let Some(server) = state.get_mut(self.idx) {
            server.active = server.active.saturating_sub(1);
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
                // Names start unresolved (B-H13): the resolver task fills
                // them in; a literal is usable immediately.
                addr: match &s.addr {
                    ServerAddr::Ip(ip) => Some(*ip),
                    ServerAddr::Name { .. } => None,
                },
                weight: s.weight,
                up: true,
                current_weight: 0,
                consecutive_fails: 0,
                consecutive_rises: 0,
                active: 0,
                up_since: now,
            })
            .collect::<Vec<ServerState>>();
        Self {
            fall: fall.max(1),
            rise: rise.max(1),
            algorithm,
            slow_start,
            state: Mutex::new(state),
            targets,
        }
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
    fn select(
        &self,
        state: &mut [ServerState],
        preferred: Option<SocketAddr>,
        exclude: &[SocketAddr],
    ) -> Option<usize> {
        let eligible = |idx: usize, state: &[ServerState]| {
            // Unresolved name slots (B-H13) are never selectable.
            state[idx].addr.is_some()
                && state[idx].up
                && state[idx].weight > 0
                && !state[idx].addr.is_some_and(|a| exclude.contains(&a))
        };
        // Affinity pin (B-H8/B-N13/B-I8): preferred when eligible, else
        // the next eligible in configuration order after it (ip_hash
        // fallback). Affinity never consults load or weights.
        if let Some(start) =
            preferred.and_then(|addr| state.iter().position(|s| s.addr == Some(addr)))
        {
            return (0..state.len()).find_map(|offset| {
                let idx = (start + offset) % state.len();
                eligible(idx, state).then_some(idx)
            });
        }
        let mut candidates: Vec<usize> = (0..state.len())
            .filter(|&idx| eligible(idx, state))
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
        }
    }

    fn named(host: &str, port: u16, weight: u32) -> ResolvedServer {
        ResolvedServer {
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
                },
                ResolvedServer {
                    addr: b.into(),
                    weight: 1,
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
}
