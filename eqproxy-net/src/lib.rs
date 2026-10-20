//! EQProxy dataplane: TCP/HTTP proxy with TLS, balancing, health checks and
//! limits. Streaming, cancellation and graceful shutdown.
//!
//! Phase 1: TCP passthrough with timeouts and limits. Phase 2a: strict HTTP/1.1.
//! Phase 2b: TLS (A11/A12/A14), weighted RR balancing (B1/B7), TCP health
//! checks (B11) and PROXY protocol v1 send (A9). 100 % safe Rust code.

#![forbid(unsafe_code)]

pub mod auth;
pub mod balancer;
pub mod health;
pub mod http1;
pub mod maps;
pub mod pool;
pub mod proxy;
pub mod proxy_proto;
pub mod tls;

pub mod dns;

pub use auth::{AuthOutcome, DenyResponse, check_basic};
pub use balancer::{ActiveGuard, Balance, Balancer, ResolvedServer, ServerAddr};
pub use dns::{DnsSettings, Resolving, SystemResolver};
pub use health::HealthCheck;
pub use pool::{DEFAULT_POOL_IDLE_TIMEOUT, MAX_IDLE_PER_SERVER, Pool};
pub use proxy::{
    AffinityMode, BoundProxy, OutboundError, ProxyError, ProxyMode, READ_BUF, RateLimiter,
    ResolvedAffinity, ResolvedAuth, ResolvedBackend, ResolvedCors, ResolvedHeaders,
    ResolvedListener, ResolvedRewrite, ResolvedRoute, RouteAction, RouteDecision, SplitTarget,
    SplitTargets, SwapSummary, bind, connect_backend,
};
pub use proxy_proto::ProxyProtocolMode;
