//! Weighted round-robin balancing (B1/B7) with per-server health state.
//!
//! Algorithm: *smooth weighted round-robin* (deterministic; ties follow
//! configuration order). A server with `weight = 0` is never selected
//! (drained) but keeps being probed by health checks (B11).
//!
//! Health state: `fall`/`rise` machine — `fall` consecutive failures drop
//! the server, `rise` consecutive successes raise it. Servers start
//! operational (like HAProxy before the first check); with no health check
//! configured they stay operational forever.

use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};

/// A resolved backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedServer {
    pub addr: SocketAddr,
    pub weight: u32,
}

#[derive(Debug, Clone, Copy)]
struct ServerState {
    weight: u32,
    up: bool,
    current_weight: i64,
    consecutive_fails: u32,
    consecutive_rises: u32,
}

/// Weighted round-robin with shared health state (per backend).
#[derive(Debug)]
pub struct Balancer {
    fall: u32,
    rise: u32,
    state: Mutex<Vec<ServerState>>,
    addrs: Vec<SocketAddr>,
}

impl Balancer {
    /// Creates the balancer for `servers` (in configuration order). `fall` and
    /// `rise` are the health-machine thresholds (B11).
    #[must_use]
    pub fn new(servers: Vec<ResolvedServer>, fall: u32, rise: u32) -> Self {
        let addrs: Vec<SocketAddr> = servers.iter().map(|s| s.addr).collect();
        let state = servers
            .into_iter()
            .map(|s| ServerState {
                weight: s.weight,
                up: true,
                current_weight: 0,
                consecutive_fails: 0,
                consecutive_rises: 0,
            })
            .collect();
        Self {
            fall: fall.max(1),
            rise: rise.max(1),
            state: Mutex::new(state),
            addrs,
        }
    }

    /// Shared state; a poisoned lock (a previous panic on another thread)
    /// recovers with the state intact instead of propagating the panic.
    fn state(&self) -> MutexGuard<'_, Vec<ServerState>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Server addresses (configuration order).
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Selects the next operational server, or `None` when all are down
    /// (or all with `weight = 0`).
    #[must_use]
    pub fn pick(&self) -> Option<SocketAddr> {
        let mut state = self.state();
        let mut total: i64 = 0;
        let mut best: Option<usize> = None;
        let mut best_weight: i64 = 0;
        for (idx, server) in state.iter_mut().enumerate() {
            if !server.up || server.weight == 0 {
                continue;
            }
            let weight = i64::from(server.weight);
            server.current_weight += weight;
            total += weight;
            if best.is_none_or(|_| server.current_weight > best_weight) {
                best = Some(idx);
                best_weight = server.current_weight;
            }
        }
        let chosen = best?;
        if let Some(server) = state.get_mut(chosen) {
            server.current_weight -= total;
        }
        self.addrs.get(chosen).copied()
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
        if let Some(idx) = self.addrs.iter().position(|a| *a == addr)
            && let Some(server) = state.get_mut(idx)
        {
            if ok {
                server.consecutive_fails = 0;
                server.consecutive_rises = server.consecutive_rises.saturating_add(1);
                if !server.up && server.consecutive_rises >= self.rise {
                    server.up = true;
                    server.current_weight = 0;
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
        self.addrs
            .iter()
            .position(|a| *a == addr)
            .and_then(|idx| state.get(idx))
            .is_some_and(|server| server.up)
    }

    /// Number of operational servers.
    #[must_use]
    pub fn up_count(&self) -> usize {
        self.state().iter().filter(|s| s.up).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(port: u16, weight: u32) -> ResolvedServer {
        ResolvedServer {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
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
    fn pick_returns_none_when_all_servers_are_down_or_drained() {
        let balancer = Balancer::new(vec![server(1, 1)], 1, 1);
        balancer.report_fail(server(1, 1).addr);
        assert!(!balancer.is_up(server(1, 1).addr));
        assert!(balancer.pick().is_none());

        let drained = Balancer::new(vec![server(2, 0)], 1, 1);
        assert!(drained.pick().is_none());
    }

    #[test]
    fn fall_and_rise_thresholds_gate_transitions() {
        let addr = server(1, 1).addr;
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
}
