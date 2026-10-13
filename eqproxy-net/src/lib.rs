//! Dataplane de EQProxy: proxy TCP/HTTP con TLS, balanceo, health checks y
//! límites. Streaming, cancelación y apagado gradual.
//!
//! Fase 1: TCP passthrough con timeouts y límites. Fase 2a: HTTP/1.1 estricto.
//! Fase 2b: TLS (A11/A12/A14), balanceo RR ponderado (B1/B7), health checks TCP
//! (B11) y envío de PROXY protocol v1 (A9). Código 100 % safe Rust.

#![forbid(unsafe_code)]

pub mod balancer;
pub mod health;
pub mod http1;
pub mod proxy;
pub mod proxy_proto;
pub mod tls;

pub use balancer::{Balancer, ResolvedServer};
pub use health::HealthCheck;
pub use proxy::{
    BoundProxy, OutboundError, ProxyError, ProxyMode, READ_BUF, ResolvedBackend, ResolvedListener,
    bind, connect_backend,
};
pub use proxy_proto::ProxyProtocolMode;
