//! Dataplane de EQProxy: proxy TCP real con límites, timeouts por fase,
//! rechazo explícito al agotar recursos y apagado gradual.
//!
//! Fase 1 del roadmap: TCP passthrough con semántica de streaming y
//! cancelación. Código 100 % safe Rust.

#![forbid(unsafe_code)]

pub mod proxy;

pub use proxy::{BoundProxy, ProxyError, READ_BUF, ResolvedListener, bind};
