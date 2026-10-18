//! Shared EQProxy types: dataplane counters and graceful shutdown.
//!
//! 100 % safe Rust code (`#![forbid(unsafe_code)]`, project decision).

#![forbid(unsafe_code)]

pub mod expectation;
pub mod metrics;
pub mod rules;
pub mod shutdown;

pub use expectation::{IpAllowlist, IpBlock, StatusExpectation};
pub use metrics::{Metrics, MetricsSnapshot};
pub use rules::{HeaderSpec, RequestFacts, Rule, RuleError, RuleSpec};
pub use shutdown::{Shutdown, ShutdownHandle};
