//! Shared EQProxy types: dataplane counters and graceful shutdown.
//!
//! 100 % safe Rust code (`#![forbid(unsafe_code)]`, project decision).

#![forbid(unsafe_code)]

pub mod auth;
pub mod expectation;
pub mod maps;
pub mod metrics;
pub mod rules;
pub mod shutdown;

pub use auth::{AuthUrl, BasicUsers, apr1_verify, basic_credentials, parse_auth_url};
pub use expectation::{IpAllowlist, IpBlock, StatusExpectation};
pub use maps::{HotMap, MapData, MapError, MapKey, MapRegistry};
pub use metrics::{Metrics, MetricsSnapshot};
pub use rules::{
    CookieSpec, HeaderSpec, MapConditionSpec, RequestFacts, Rule, RuleError, RuleSpec,
};
pub use shutdown::{Shutdown, ShutdownHandle};
