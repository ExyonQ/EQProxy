//! EQProxy dataplane: TCP/HTTP proxy with TLS, balancing, health checks and
//! limits. Streaming, cancellation and graceful shutdown.
//!
//! Phase 1: TCP passthrough with timeouts and limits. Phase 2a: strict HTTP/1.1.
//! Phase 2b: TLS (A11/A12/A14), weighted RR balancing (B1/B7), TCP health
//! checks (B11) and PROXY protocol v1 send (A9). 100 % safe Rust code.

#![forbid(unsafe_code)]

pub mod balancer;
pub mod health;
pub mod http1;
pub mod pool;
pub mod proxy;
pub mod proxy_proto;
pub mod tls;

pub use balancer::{Balancer, ResolvedServer};
pub use health::HealthCheck;
pub use pool::{DEFAULT_POOL_IDLE_TIMEOUT, MAX_IDLE_PER_SERVER, Pool};
pub use proxy::{
    BoundProxy, OutboundError, ProxyError, ProxyMode, READ_BUF, ResolvedBackend, ResolvedListener,
    ResolvedRewrite, ResolvedRoute, RouteAction, RouteDecision, SwapSummary, bind, connect_backend,
};
pub use proxy_proto::ProxyProtocolMode;
