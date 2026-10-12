//! Tipos compartidos de EQProxy: contadores del dataplane y apagado gradual.
//!
//! Código 100 % safe Rust (`#![forbid(unsafe_code)]`, decisión de proyecto).

#![forbid(unsafe_code)]

pub mod metrics;
pub mod shutdown;

pub use metrics::{Metrics, MetricsSnapshot};
pub use shutdown::{Shutdown, ShutdownHandle};
