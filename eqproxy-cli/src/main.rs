//! EQProxy CLI.
//!
//! Implemented: `run`, `config validate/explain/diff/plan/apply/rollback`
//! and `doctor`. The rest **fail explicitly** with exit code 2
//! (never fake success).

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use clap::{Parser, Subcommand};

use eqproxy_config::error::ConfigError;
use eqproxy_config::schema::Config;
use eqproxy_config::validate::{self, CheckResult};
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::health::HealthCheck;
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    ProxyMode, ProxyProtocolMode, ResolvedBackend, ResolvedListener, ResolvedServer, bind,
};

#[derive(Parser)]
#[command(
    name = "eqproxy",
    version,
    about = "ExyonQ Proxy (EQProxy): reverse proxy and load balancer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the dataplane with the given configuration
    Run {
        /// TOML configuration file
        #[arg(short, long)]
        config: PathBuf,
        /// Metrics report interval (suffixes: ms, s, m, h)
        #[arg(long, default_value = "30s")]
        metrics_interval: String,
    },
    /// Configuration commands
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Environment diagnostics (Phase 3): config gate, listener bind
    /// probes and the FD budget. With no `--config`, environment only.
    Doctor {
        /// TOML configuration file to check readiness for
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Validates the configuration: errors with file, line, field, cause and example
    Validate {
        /// TOML configuration file
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Simulates one routing decision without side effects (Phase 3, SPEC §8)
    Explain {
        #[arg(short, long)]
        config: PathBuf,
        /// Listener to explain (required when the config defines several)
        #[arg(long)]
        listener: Option<String>,
        /// Simulated request method
        #[arg(long, default_value = "GET")]
        method: String,
        /// Simulated request host
        #[arg(long, default_value = "-")]
        host: String,
        /// Simulated request path
        #[arg(long, default_value = "/")]
        path: String,
    },
    /// Compares two configurations (Phase 3): exit 0 with the report on
    /// stdout (verdict line first); exit 1 when either side fails to load
    /// or validate, with the errors on stderr
    Diff {
        /// Baseline configuration file
        left: PathBuf,
        /// Candidate configuration file
        right: PathBuf,
    },
    /// Shows the change plan without applying it (Phase 3)
    Plan {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Applies a candidate configuration to the local versioned state (Phase 3,
    /// offline: validate + resolve gate, backup, atomic swap; no running
    /// process is touched)
    Apply {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Restores the most recent backup into current (Phase 3, offline)
    Rollback,
    /// Reference-proxy to EQProxy configuration converter (Phase 8)
    Import {
        /// Source file (reference-proxy configuration)
        #[arg(long)]
        input: PathBuf,
        /// Destination file (eqproxy.toml)
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run {
            config,
            metrics_interval,
        } => run(config, metrics_interval).await,
        Command::Config { command } => config_command(command),
        Command::Doctor { config } => doctor(config.as_deref()),
    };
    ExitCode::from(code)
}

fn config_command(command: ConfigCommand) -> u8 {
    match command {
        ConfigCommand::Validate { config } => validate(&config),
        ConfigCommand::Explain {
            config,
            listener,
            method,
            host,
            path,
        } => explain(&config, listener.as_deref(), &method, &host, &path),
        ConfigCommand::Diff { left, right } => diff(&left, &right),
        ConfigCommand::Plan { config } => plan(&config),
        ConfigCommand::Apply { config } => apply(&config),
        ConfigCommand::Rollback => rollback(),
        ConfigCommand::Import { .. } => not_implemented("config import", "Phase 8"),
    }
}

/// Explicit failure for unimplemented functionality: never fakes success.
fn not_implemented(feature: &str, phase: &str) -> u8 {
    eprintln!("error: \"{feature}\" is not implemented yet (planned for {phase})");
    2
}

/// Reads, parses and validates. The parse error already carries line, field and example.
fn load_and_check(path: &Path) -> Result<(Config, CheckResult), ConfigError> {
    let source = read_config_source(path)?;
    parse_and_check(&source, path)
}

/// Reads the raw config text (single read: `/dev/stdin` pipes cannot be
/// read twice, which `apply` learned when it read-then-reloaded).
fn read_config_source(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("could not read the file: {e}"),
        example: "create an eqproxy.toml (see eqproxy.toml.example) and pass --config <path>"
            .to_owned(),
    })
}

/// Parses and semantically checks already-read config text.
fn parse_and_check(source: &str, path: &Path) -> Result<(Config, CheckResult), ConfigError> {
    let config = eqproxy_config::parse_str(source, path)?;
    let result = validate::check(&config, source, path);
    Ok((config, result))
}

fn validate(path: &Path) -> u8 {
    let (config, result) = match load_and_check(path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        eprintln!(
            "invalid config: {} error(s) in {}",
            result.errors.len(),
            path.display()
        );
        return 1;
    }
    // Resolution loads certificates/keys and verifies the config is
    // really usable (addresses, TLS, balancing), not just parseable.
    if let Err(msg) = resolve(&config, base_dir(path)) {
        eprintln!("error: inconsistent configuration after validation: {msg}");
        return 1;
    }
    println!(
        "config OK: {} listener(s), {} backend(s) in {}",
        config.listener.len(),
        config.backend.len(),
        path.display()
    );
    0
}

/// The SIGHUP gate (S-CFG-01): the same checks as startup, without side
/// effects. A rejected candidate never reaches the dataplane and the
/// running config keeps serving. Errors come back as text for the
/// "config reload rejected" line.
fn reload_gate(path: &Path) -> Result<Vec<ResolvedListener>, String> {
    let (config, result) = load_and_check(path).map_err(|err| err.to_string())?;
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        return Err(result
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "));
    }
    let listeners = resolve(&config, base_dir(path))
        .map_err(|msg| format!("inconsistent configuration after validation: {msg}"))?;
    if listeners.is_empty() {
        return Err("the configuration defines no listeners; nothing to serve".to_owned());
    }
    Ok(listeners)
}

/// Compares two configurations for the pre-apply safety workflow (Phase 3).
///
/// Both sides must load and validate like `validate` does; the comparison
/// itself is pure (`diff_report`) and needs no network, certs or processes.
/// Exit 0 always carries the report on stdout (verdict line first, so
/// automation can gate on it); exit 1 means a side could not be loaded or
/// validated, with the errors on stderr.
fn diff(left: &Path, right: &Path) -> u8 {
    let (left_config, left_result) = match load_and_check(left) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    let (right_config, right_result) = match load_and_check(right) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in left_result.warnings.iter().chain(&right_result.warnings) {
        eprintln!("warning: {warning}");
    }
    for err in left_result.errors.iter().chain(&right_result.errors) {
        eprintln!("{err}");
    }
    if !left_result.is_valid() || !right_result.is_valid() {
        eprintln!("invalid config: refusing to diff until both sides validate");
        return 1;
    }
    println!("{}", diff_report(&left_config, &right_config));
    0
}

/// Renders the comparison. Pure function of the two parsed configs
/// (verified by unit test); the only I/O of `diff` is printing it.
///
/// Line vocabulary, mirroring `diff(1)`: `+` only in right, `-` only in
/// left, `~` changed. Section maps are `BTreeMap`s, so the order is
/// deterministic. Server lists compare through `server_entries`, hence the
/// legacy single `server` and the `servers` list use one vocabulary.
fn diff_report(left: &Config, right: &Config) -> String {
    use std::fmt::Write as _;
    let changes = diff_changes(left, right);
    let mut out = String::new();
    if changes.is_empty() {
        out.push_str("no differences");
    } else {
        let _ = writeln!(out, "{} difference(s):", changes.len());
        for change in &changes {
            let _ = writeln!(out, "{change}");
        }
    }
    out
}

/// The individual change lines of [`diff_report`], exposed so `apply` and
/// `rollback` can count them for their verdict line.
fn diff_changes(left: &Config, right: &Config) -> Vec<String> {
    let mut changes = Vec::new();
    if left.schema_version != right.schema_version {
        changes.push(format!(
            "~ schema_version: {} -> {}",
            left.schema_version, right.schema_version
        ));
    }
    if left.shutdown_grace != right.shutdown_grace {
        changes.push(format!(
            "~ shutdown_grace: {:?} -> {:?}",
            left.shutdown_grace, right.shutdown_grace
        ));
    }
    for name in left
        .listener
        .keys()
        .filter(|n| !right.listener.contains_key(*n))
    {
        changes.push(format!("- listener \"{name}\" (only in left)"));
    }
    for name in right
        .listener
        .keys()
        .filter(|n| !left.listener.contains_key(*n))
    {
        changes.push(format!("+ listener \"{name}\" (only in right)"));
    }
    for name in left
        .listener
        .keys()
        .filter(|n| right.listener.contains_key(*n))
    {
        let l = &left.listener[name];
        let r = &right.listener[name];
        if l.listen != r.listen {
            changes.push(format!(
                "~ listener \"{name}\" listen: {} -> {}",
                l.listen, r.listen
            ));
        }
        if l.mode != r.mode {
            changes.push(format!(
                "~ listener \"{name}\" mode: {:?} -> {:?}",
                l.mode, r.mode
            ));
        }
        if l.backend != r.backend {
            changes.push(format!(
                "~ listener \"{name}\" backend: {} -> {}",
                l.backend, r.backend
            ));
        }
        if l.maxconn != r.maxconn {
            changes.push(format!(
                "~ listener \"{name}\" maxconn: {} -> {}",
                l.maxconn, r.maxconn
            ));
        }
        for (field, a, b) in [
            ("connect_timeout", l.connect_timeout, r.connect_timeout),
            ("idle_timeout", l.idle_timeout, r.idle_timeout),
            (
                "client_header_timeout",
                l.client_header_timeout,
                r.client_header_timeout,
            ),
            (
                "server_header_timeout",
                l.server_header_timeout,
                r.server_header_timeout,
            ),
        ] {
            if a != b {
                changes.push(format!("~ listener \"{name}\" {field}: {a:?} -> {b:?}"));
            }
        }
        if l.tls != r.tls {
            changes.push(format!(
                "~ listener \"{name}\" tls: {} -> {}",
                tls_server_summary(l.tls.as_ref()),
                tls_server_summary(r.tls.as_ref())
            ));
        }
    }
    for name in left
        .backend
        .keys()
        .filter(|n| !right.backend.contains_key(*n))
    {
        changes.push(format!("- backend \"{name}\" (only in left)"));
    }
    for name in right
        .backend
        .keys()
        .filter(|n| !left.backend.contains_key(*n))
    {
        changes.push(format!("+ backend \"{name}\" (only in right)"));
    }
    for name in left
        .backend
        .keys()
        .filter(|n| right.backend.contains_key(*n))
    {
        let l = &left.backend[name];
        let r = &right.backend[name];
        let l_servers: Vec<(String, u32)> = l
            .server_entries()
            .into_iter()
            .map(|(addr, w)| (addr.to_owned(), w))
            .collect();
        let r_servers: Vec<(String, u32)> = r
            .server_entries()
            .into_iter()
            .map(|(addr, w)| (addr.to_owned(), w))
            .collect();
        if l_servers != r_servers {
            changes.push(format!(
                "~ backend \"{name}\" servers: {} -> {}",
                entries_summary(&l_servers),
                entries_summary(&r_servers)
            ));
        }
        if l.balance != r.balance {
            changes.push(format!(
                "~ backend \"{name}\" balance: {:?} -> {:?}",
                l.balance, r.balance
            ));
        }
        if l.proxy_protocol != r.proxy_protocol {
            changes.push(format!(
                "~ backend \"{name}\" proxy_protocol: {:?} -> {:?}",
                l.proxy_protocol, r.proxy_protocol
            ));
        }
        if l.health_check != r.health_check {
            changes.push(format!(
                "~ backend \"{name}\" health_check: {} -> {}",
                health_summary(l.health_check.as_ref()),
                health_summary(r.health_check.as_ref())
            ));
        }
        if l.tls != r.tls {
            changes.push(format!(
                "~ backend \"{name}\" tls: {} -> {}",
                tls_client_summary(l.tls.as_ref()),
                tls_client_summary(r.tls.as_ref())
            ));
        }
    }
    changes
}

/// `addr(weight), …` for a normalized server list; `[]` when empty.
fn entries_summary(entries: &[(String, u32)]) -> String {
    let items: Vec<String> = entries
        .iter()
        .map(|(addr, w)| format!("{addr}({w})"))
        .collect();
    format!("[{}]", items.join(", "))
}

fn tls_server_summary(tls: Option<&eqproxy_config::schema::TlsServerConfig>) -> String {
    match tls {
        None => "none".to_owned(),
        Some(t) => format!(
            "cert={} key={} alpn=[{}] min={:?}",
            t.cert,
            t.key,
            t.alpn.join(","),
            t.min_version
        ),
    }
}

fn tls_client_summary(tls: Option<&eqproxy_config::schema::TlsClientConfig>) -> String {
    match tls {
        None => "none".to_owned(),
        Some(t) => format!(
            "verify={} ca={} server_name={} alpn=[{}] min={:?}",
            t.verify,
            t.ca_file.as_deref().unwrap_or("-"),
            t.server_name.as_deref().unwrap_or("-"),
            t.alpn.join(","),
            t.min_version
        ),
    }
}

fn health_summary(hc: Option<&eqproxy_config::schema::HealthCheckConfig>) -> String {
    match hc {
        None => "none".to_owned(),
        Some(h) => format!(
            "interval={:?} timeout={:?} fall={} rise={}",
            h.interval, h.timeout, h.fall, h.rise
        ),
    }
}

/// Simulates one routing decision with no external effects (SPEC §8).
///
/// Loads, validates and resolves the config, picks the listener (explicit
/// `--listener` when several exist), then reports the listener, the backend
/// with its servers, and the first weighted round-robin pick computed on a
/// throwaway balancer. No sockets are opened and no shared state is touched.
fn explain(path: &Path, want: Option<&str>, method: &str, host: &str, req_path: &str) -> u8 {
    let (config, result) = match load_and_check(path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }
    let listeners = match resolve(&config, base_dir(path)) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: inconsistent configuration after validation: {msg}");
            return 1;
        }
    };
    let listener = match select_listener(&listeners, want) {
        Ok(listener) => listener,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 1;
        }
    };
    println!(
        "{}",
        explain_report(&config, listener, method, host, req_path)
    );
    0
}

/// Shows what `run` would activate from this config, without starting
/// anything (Phase 3 dry run; the future hot-apply will diff against the
/// live snapshot here).
///
/// Loads, validates and resolves like `run` does — certificates are read,
/// addresses parsed, backends assembled — then reports the full activation
/// inventory instead of binding or dialing. Exit 0 carries the report;
/// exit 1 carries the same actionable errors `run` would fail with.
fn plan(path: &Path) -> u8 {
    let (config, result) = match load_and_check(path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }
    let listeners = match resolve(&config, base_dir(path)) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: inconsistent configuration after validation: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: the configuration defines no listeners; nothing to serve");
        return 1;
    }
    println!("{}", plan_report(&config, &listeners));
    0
}

/// Renders the activation inventory. Pure function of the validated config
/// and the resolved model (verified by unit test); the only I/O of `plan`
/// is printing it. One defensive line per listener/backend/server so the
/// operator can eyeball exactly what `run` would bring up.
fn plan_report(config: &Config, listeners: &[ResolvedListener]) -> String {
    use std::fmt::Write as _;
    let mut backend_names: Vec<&str> = listeners.iter().map(|l| l.backend_name.as_str()).collect();
    backend_names.sort_unstable();
    backend_names.dedup();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "plan: {} listener(s), {} backend(s) — nothing started (dry run)",
        listeners.len(),
        backend_names.len()
    );
    for listener in listeners {
        let mode = match listener.mode {
            ProxyMode::Tcp => "tcp",
            ProxyMode::Http => "http",
        };
        let tls = match listener.server_tls.as_ref() {
            None => "no".to_owned(),
            Some(t) => {
                let protos: Vec<String> = t
                    .alpn()
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                format!("yes(alpn=[{}])", protos.join(","))
            }
        };
        let _ = writeln!(
            out,
            "listener \"{}\": bind {} mode={} maxconn={} tls={} backend=\"{}\"",
            listener.name, listener.listen, mode, listener.maxconn, tls, listener.backend_name
        );
        let _ = writeln!(
            out,
            "  timeouts: connect={:?} idle={:?} client_header={:?} server_header={:?} shutdown_grace={:?}",
            listener.connect_timeout,
            listener.idle_timeout,
            listener.client_header_timeout,
            listener.server_header_timeout,
            config.shutdown_grace
        );
    }
    for name in backend_names {
        let backend = &listeners
            .iter()
            .find(|l| l.backend_name == name)
            .expect("backend referenced by a listener")
            .backend;
        let proxy_protocol = match backend.proxy_protocol {
            ProxyProtocolMode::None => "none",
            ProxyProtocolMode::V1 => "v1",
        };
        let health = backend
            .health_check
            .as_ref()
            .map(|hc| format!("interval={:?} timeout={:?}", hc.interval, hc.timeout))
            .unwrap_or_else(|| "none".to_owned());
        let _ = writeln!(
            out,
            "backend \"{}\": servers={} tls={} proxy_protocol={} health_check={}",
            backend.name,
            backend.servers.len(),
            if backend.tls.is_some() { "yes" } else { "no" },
            proxy_protocol,
            health
        );
        for server in &backend.servers {
            let _ = writeln!(out, "  server {} weight={}", server.addr, server.weight);
        }
    }
    out
}

/// Local versioned state for `apply`/`rollback` (Phase 3, offline).
///
/// Layout: `<dir>/current.toml` plus `<dir>/history/NNNN-<nanos>.toml`.
/// `<dir>` is `./.eqproxy` unless `EQPROXY_STATE_DIR` overrides it (that
/// override is also how the E2E tests isolate parallel runs without
/// touching the process working directory).
fn state_dir() -> PathBuf {
    std::env::var_os("EQPROXY_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".eqproxy"))
}

/// Maximum retained backups; older ones are pruned on `apply`.
const HISTORY_CAP: usize = 32;

/// History entry names, ascending (the zero-padded sequence sorts first,
/// so lexical order is chronological).
fn list_history(history: &Path) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(history) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name.ends_with(".toml")
                && entry.file_type().is_ok_and(|t| t.is_file())
            {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names
}

/// Next history name after `entries` (pure, unit-tested). `unique` only
/// disambiguates two applies within the same sequence slot.
fn next_history_name(entries: &[String], unique: u128) -> String {
    let seq = entries
        .iter()
        .filter_map(|n| n.split_at_checked(4))
        .filter_map(|(prefix, _)| prefix.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    format!("{seq:04}-{unique}.toml")
}

/// Drops the oldest entries beyond `cap`; returns how many were removed.
/// A pruning failure never fails the apply itself: the operator is warned
/// and the new backup is already safely stored.
fn prune_history(history: &Path, cap: usize) -> usize {
    let entries = list_history(history);
    if entries.len() <= cap {
        return 0;
    }
    let mut pruned = 0;
    for stale in entries.iter().take(entries.len() - cap) {
        match std::fs::remove_file(history.join(stale)) {
            Ok(()) => pruned += 1,
            Err(e) => eprintln!(
                "warning: cannot prune old backup {}: {e}",
                history.join(stale).display()
            ),
        }
    }
    pruned
}

/// Header stamped on every history entry: the directory the candidate was
/// applied from, so `rollback` resolves relative cert/CA paths against the
/// same base (TOML `#` comments, ignored by the parser).
fn history_header(origin: &Path, unique: u128) -> String {
    format!(
        "# eqproxy-history: applied-from={} unix_nanos={unique}\n",
        origin.display()
    )
}

/// The directory a history entry was applied from, if it carries the header.
fn history_origin(raw: &[u8]) -> Option<PathBuf> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("# eqproxy-history:") {
            continue;
        }
        for field in line.split_whitespace() {
            if let Some(dir) = field.strip_prefix("applied-from=") {
                return Some(PathBuf::from(dir));
            }
        }
    }
    None
}

/// The candidate bytes of a history entry, without the header lines.
fn history_body(raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
        if trimmed.starts_with(b"# eqproxy-history:") {
            continue;
        }
        body.extend_from_slice(line);
    }
    body
}

/// Same-directory write + rename: the target is either the complete new
/// content or the untouched previous one, never a half-written file.
fn atomic_write(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = target.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Applies a candidate configuration to the local state (Phase 3, offline).
///
/// Fail-closed gate first: the candidate must load, validate and resolve
/// exactly like `run` needs it (certificates are read, addresses parsed);
/// exit 1 leaves the state untouched. Then the previous current, if any
/// and different, is pushed to `history/` and the candidate bytes become
/// the new `current.toml` via atomic rename. Re-applying identical bytes
/// is a no-op report (exit 0, no new backup).
///
/// This touches no running process: hot-apply under traffic stays pending
/// (S-CFG-01); the operator keeps pointing `run --config` at their file.
fn apply(path: &Path) -> u8 {
    // Single read: the bytes gate the config AND become the stored
    // current (pipes like /dev/stdin cannot be read twice).
    let candidate = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "error: cannot apply {}: could not read the file: {e}",
                path.display()
            );
            eprintln!(
                "  example: create an eqproxy.toml (see eqproxy.toml.example) and pass --config <path>"
            );
            return 1;
        }
    };
    let source = String::from_utf8_lossy(&candidate);
    let (config, result) = match parse_and_check(&source, path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }
    let listeners = match resolve(&config, base_dir(path)) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: inconsistent configuration after validation: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: the configuration defines no listeners; nothing to serve");
        return 1;
    }

    let dir = state_dir();
    let history = dir.join("history");
    if let Err(e) = std::fs::create_dir_all(&history) {
        eprintln!(
            "error: cannot use state in {}: {e} (check permissions or set EQPROXY_STATE_DIR=<path>)",
            dir.display()
        );
        return 1;
    }
    let current = dir.join("current.toml");
    let previous = std::fs::read(&current).ok();
    if previous.as_deref() == Some(candidate.as_slice()) {
        println!(
            "already applied: {} matches current (no changes)",
            path.display()
        );
        return 0;
    }
    // The previous current was valid when applied; parse-only is enough
    // for the change report (a hand-edited current still diffs or skips).
    let previous_config = previous.as_deref().and_then(|bytes| {
        eqproxy_config::parse_str(&String::from_utf8_lossy(bytes), &current).ok()
    });
    let mut backup_note = String::new();
    if let Some(prev) = previous.as_deref() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = next_history_name(&list_history(&history), unique);
        let entry = history.join(&name);
        let mut stored = history_header(&absolute_base(path), unique).into_bytes();
        stored.extend_from_slice(prev);
        if let Err(e) = std::fs::write(&entry, &stored) {
            eprintln!("error: cannot back up current to {}: {e}", entry.display());
            return 1;
        }
        backup_note = format!(", backup {name}");
        if prune_history(&history, HISTORY_CAP) > 0 {
            backup_note.push_str(" (oldest backup pruned)");
        }
    }
    if let Err(e) = atomic_write(&current, &candidate) {
        eprintln!(
            "error: cannot install {} as current: {e}",
            current.display()
        );
        return 1;
    }
    match previous_config {
        Some(prev) => {
            let changes = diff_changes(&prev, &config);
            println!(
                "applied: {} -> {} ({} difference(s) vs previous{backup_note})",
                path.display(),
                current.display(),
                changes.len()
            );
            println!("{}", diff_report(&prev, &config));
        }
        None => {
            println!(
                "applied: {} -> {} (no previous configuration)",
                path.display(),
                current.display()
            );
            println!("{}", plan_report(&config, &listeners));
        }
    }
    0
}

/// Absolute base directory of a config path, for the history header.
fn absolute_base(path: &Path) -> PathBuf {
    let base = base_dir(path);
    std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf())
}

/// Restores the most recent backup into current (Phase 3, offline).
///
/// Fail-closed like `apply`: the backup must parse, validate and resolve
/// (relative cert paths against the apply-time directory recorded in its
/// header) before anything is replaced; exit 1 leaves the state
/// untouched. On success the entry is popped: walking back takes one
/// `rollback` per `apply`, and going forward again is a fresh `apply`.
fn rollback() -> u8 {
    let dir = state_dir();
    let history = dir.join("history");
    let mut entries = list_history(&history);
    let Some(name) = entries.pop() else {
        eprintln!(
            "error: no previous configuration to restore (history in {} is empty)",
            history.display()
        );
        eprintln!(
            "  example: eqproxy config apply --config <candidate> records the previous current first"
        );
        return 1;
    };
    let entry = history.join(&name);
    let raw = match std::fs::read(&entry) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("error: cannot read backup {}: {e}", entry.display());
            return 1;
        }
    };
    let body = history_body(&raw);
    let text = String::from_utf8_lossy(&body);
    let config = match eqproxy_config::parse_str(&text, &entry) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: backup {name} is not usable: {err}");
            return 1;
        }
    };
    let result = validate::check(&config, &text, &entry);
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("error: backup {name} is not usable: {err}");
        }
        return 1;
    }
    let base = history_origin(&raw).unwrap_or_else(|| history.clone());
    let listeners = match resolve(&config, &base) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: backup {name} is not usable: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: backup {name} defines no listeners; refusing to restore");
        return 1;
    }
    let current = dir.join("current.toml");
    let displaced = std::fs::read(&current).ok().and_then(|bytes| {
        eqproxy_config::parse_str(&String::from_utf8_lossy(&bytes), &current).ok()
    });
    if let Err(e) = atomic_write(&current, &body) {
        eprintln!(
            "error: cannot restore {} as current: {e}",
            current.display()
        );
        return 1;
    }
    if let Err(e) = std::fs::remove_file(&entry) {
        eprintln!("warning: restored {name} but cannot remove the spent backup: {e}");
    }
    match displaced {
        Some(prev) => {
            let changes = diff_changes(&prev, &config);
            println!(
                "rolled back: current restored from {name} ({} difference(s) vs applied)",
                changes.len()
            );
            println!("{}", diff_report(&prev, &config));
        }
        None => {
            println!("rolled back: current restored from {name} (no previous current to compare)");
            println!("{}", plan_report(&config, &listeners));
        }
    }
    0
}

/// Environment diagnostics for a config that is about to run (Phase 3).
///
/// Side-effect discipline: nothing is dialed and no state is touched. The
/// only interaction with the outside world is a momentary TCP bind per
/// listener (proving the port is free and permitted) plus reading the
/// process FD limit. Backend reachability is deliberately NOT probed: a
/// down backend at check time is not a config error, and dialing would
/// pollute backend logs and health state.
///
/// Exit 0 unless the config gate fails or any check errors; warnings
/// (e.g. a tight FD budget) never fail the run.
fn doctor(path: Option<&Path>) -> u8 {
    let Some(path) = path else {
        let mut report = DoctorReport::new("environment only (no --config)".to_owned());
        report.push_fd(None);
        print!("{report}");
        return 0;
    };
    let (config, result) = match load_and_check(path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }
    let listeners = match resolve(&config, base_dir(path)) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: inconsistent configuration after validation: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: the configuration defines no listeners; nothing to serve");
        return 1;
    }
    let mut report = DoctorReport::new(path.display().to_string());
    for listener in &listeners {
        report.push_bind(listener);
        report.push_tls(listener);
    }
    report.push_fd(Some(&listeners));
    let code = report.exit_code();
    print!("{report}");
    code
}

/// One `ok:`/`warn:`/`err:`/`info:` line.
struct DoctorLine {
    level: &'static str,
    detail: String,
}

/// The rendered doctor report: check lines plus a verdict (pure data,
/// unit-tested; the only I/O of `doctor` is printing it).
struct DoctorReport {
    subject: String,
    lines: Vec<DoctorLine>,
}

impl DoctorReport {
    fn new(subject: String) -> Self {
        Self {
            subject,
            lines: Vec::new(),
        }
    }

    fn ok(&mut self, detail: String) {
        self.lines.push(DoctorLine {
            level: "ok",
            detail,
        });
    }

    fn warn(&mut self, detail: String) {
        self.lines.push(DoctorLine {
            level: "warn",
            detail,
        });
    }

    fn err(&mut self, detail: String) {
        self.lines.push(DoctorLine {
            level: "err",
            detail,
        });
    }

    /// Momentary TCP bind: proves the port is free and permitted.
    fn push_bind(&mut self, listener: &ResolvedListener) {
        match std::net::TcpListener::bind(listener.listen) {
            Ok(bound) => {
                drop(bound);
                self.ok(format!(
                    "bind {} (listener \"{}\")",
                    listener.listen, listener.name
                ));
            }
            Err(e) => self.err(format!(
                "bind {} (listener \"{}\"): {e} — run would fail to start this listener",
                listener.listen, listener.name
            )),
        }
    }

    /// TLS material already loaded by `resolve`: surfacing per listener.
    fn push_tls(&mut self, listener: &ResolvedListener) {
        self.ok(format!(
            "tls {} (listener \"{}\")",
            if listener.server_tls.is_some() {
                "enabled, cert/key parsed"
            } else {
                "disabled (plain TCP)"
            },
            listener.name
        ));
    }

    /// FD budget (SPEC §7.3, T07): 2 FDs per proxied connection plus one
    /// per listener, with a 10 % margin, against the soft `NOFILE` limit.
    fn push_fd(&mut self, listeners: Option<&[ResolvedListener]>) {
        let limit = fd_soft_limit();
        let Some(listeners) = listeners else {
            match limit {
                Some(n) => self.lines.push(DoctorLine {
                    level: "info",
                    detail: format!("fd limit={n} (pass --config to assess it against maxconn)"),
                }),
                None => self.warn("fd limit unreadable; cannot assess the FD budget".to_owned()),
            }
            return;
        };
        let needed = fd_needed(listeners);
        let maxconn: u32 = listeners.iter().map(|l| l.maxconn).sum();
        match limit {
            Some(n) if n >= needed => self.ok(format!(
                "fds: limit={n} need~{needed} (2x maxconn {maxconn} + {} listeners + 10% margin)",
                listeners.len()
            )),
            Some(n) => self.warn(format!(
                "fds: limit={n} below need~{needed} (2x maxconn {maxconn} + {} listeners + 10% margin); raise `ulimit -n` or lower maxconn",
                listeners.len()
            )),
            None => self.warn("fd limit unreadable; cannot assess the FD budget".to_owned()),
        }
    }

    fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut err = 0;
        for line in &self.lines {
            match line.level {
                // `info` is a satisfied observation, never a problem.
                "ok" | "info" => ok += 1,
                "warn" => warn += 1,
                _ => err += 1,
            }
        }
        (ok, warn, err)
    }

    fn exit_code(&self) -> u8 {
        if self.counts().2 > 0 { 1 } else { 0 }
    }
}

impl std::fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (ok, warn, err) = self.counts();
        let _ = writeln!(f, "doctor checks for {}", self.subject);
        for line in &self.lines {
            let _ = writeln!(f, "{}: {}", line.level, line.detail);
        }
        let _ = writeln!(
            f,
            "doctor: {} ({ok} ok, {warn} warn, {err} err)",
            if err > 0 { "FAIL" } else { "PASS" }
        );
        Ok(())
    }
}

/// FDs `run` may hold: 2 per connection across all listeners plus one per
/// listener, with a 10 % margin (SPEC §7.3). Pure, unit-tested.
fn fd_needed(listeners: &[ResolvedListener]) -> u64 {
    let conns: u64 = listeners.iter().map(|l| u64::from(l.maxconn)).sum();
    (2 * conns + listeners.len() as u64) * 11 / 10
}

/// Soft `NOFILE` limit of this process; `None` when unreadable.
fn fd_soft_limit() -> Option<u64> {
    rlimit::getrlimit(rlimit::Resource::NOFILE)
        .ok()
        .map(|(soft, _)| soft)
}

/// Picks the listener to explain: by name when requested, the only one when
/// unambiguous, otherwise an error that lists the candidates (never guesses).
fn select_listener<'a>(
    listeners: &'a [ResolvedListener],
    want: Option<&str>,
) -> Result<&'a ResolvedListener, String> {
    if let Some(name) = want {
        return listeners.iter().find(|l| l.name == name).ok_or_else(|| {
            let names = listener_names(listeners);
            format!("unknown listener \"{name}\"; available: {names}")
        });
    }
    if listeners.len() == 1 {
        return Ok(&listeners[0]);
    }
    let names = listener_names(listeners);
    Err(format!(
        "{} listeners; select one with --listener <name>: {names}",
        listeners.len()
    ))
}

fn listener_names(listeners: &[ResolvedListener]) -> String {
    listeners
        .iter()
        .map(|l| l.name.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders the simulation report. Pure function of the resolved config
/// (verified by unit test); the only I/O of `explain` is printing it.
fn explain_report(
    config: &Config,
    listener: &ResolvedListener,
    method: &str,
    host: &str,
    req_path: &str,
) -> String {
    use std::fmt::Write as _;
    let backend = &listener.backend;
    let mode = match listener.mode {
        ProxyMode::Tcp => "tcp",
        ProxyMode::Http => "http",
    };
    let (fall, rise) = config
        .backend
        .get(&listener.backend_name)
        .and_then(|b| b.health_check.as_ref())
        .map(|hc| (hc.fall, hc.rise))
        .unwrap_or((3, 2));
    // Throwaway balancer: the simulated pick advances no shared state.
    let sim = eqproxy_net::Balancer::new(backend.servers.clone(), fall, rise);
    let pick = sim.pick();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "simulation: true (no requests issued, no state changed)"
    );
    let _ = writeln!(out, "request: {method} {req_path} host={host}");
    let _ = writeln!(
        out,
        "listener \"{}\": listen={} mode={} maxconn={} tls={}",
        listener.name,
        listener.listen,
        mode,
        listener.maxconn,
        if listener.server_tls.is_some() {
            "yes"
        } else {
            "no"
        },
    );
    let proxy_protocol = match backend.proxy_protocol {
        ProxyProtocolMode::None => "none",
        ProxyProtocolMode::V1 => "v1",
    };
    let health = backend
        .health_check
        .as_ref()
        .map(|hc| {
            format!(
                "interval={:?} timeout={:?} fall={} rise={}",
                hc.interval, hc.timeout, fall, rise
            )
        })
        .unwrap_or_else(|| "none".to_owned());
    let _ = writeln!(
        out,
        "backend \"{}\": balance=roundrobin servers={} tls={} proxy_protocol={} health_check={}",
        backend.name,
        backend.servers.len(),
        if backend.tls.is_some() { "yes" } else { "no" },
        proxy_protocol,
        health,
    );
    // Phase timeouts and their observable outcome when they fire (Q4/H5:
    // no surprises — `explain` documents what each timeout does BEFORE it
    // can fire, including the response the client receives).
    let _ = writeln!(
        out,
        "timeouts: connect={:?} idle={:?} client_header={:?} server_header={:?}",
        listener.connect_timeout,
        listener.idle_timeout,
        listener.client_header_timeout,
        listener.server_header_timeout
    );
    let fire = match listener.mode {
        ProxyMode::Tcp => format!(
            "connect=close after {:?}; idle=close after {:?} (tcp: no response channel)",
            listener.connect_timeout, listener.idle_timeout
        ),
        ProxyMode::Http => format!(
            "connect=502 after {:?}; client_header=408(first exchange)/close after {:?}; server_header=504 after {:?}; idle=close after {:?}",
            listener.connect_timeout,
            listener.client_header_timeout,
            listener.server_header_timeout,
            listener.idle_timeout
        ),
    };
    let _ = writeln!(out, "timeout_on_fire: {fire}");
    let queue = backend.queue.as_ref().map_or_else(
        || "none (no server up -> 503 immediately)".to_owned(),
        |q| {
            format!(
                "maxqueue={} timeout={:?} (full->503; expired->503)",
                q.settings.maxqueue, q.settings.timeout
            )
        },
    );
    let _ = writeln!(out, "queue: {queue}");
    let retries = if backend.retries.max == 0 {
        "none (one dial per exchange)".to_owned()
    } else {
        format!(
            "max={} scope={} (connect-phase only; failed server excluded)",
            backend.retries.max,
            if backend.retries.non_idempotent {
                "all methods"
            } else {
                "idempotent-only"
            }
        )
    };
    let _ = writeln!(out, "retries: {retries}");
    if let Some(local) = &listener.local_response {
        let _ = writeln!(
            out,
            "local_response: status={} content_type=\"{}\" body_bytes={} (no-server class)",
            local.status,
            local.content_type,
            local.body.len()
        );
    }
    for server in &backend.servers {
        let state = if sim.is_up(server.addr) {
            "UP(initial)"
        } else {
            "DOWN(initial)"
        };
        let _ = writeln!(
            out,
            "server {} weight={} state={state}",
            server.addr, server.weight
        );
    }
    match pick {
        Some(addr) => {
            let _ = writeln!(
                out,
                "decision: server {addr} reason=\"first weighted round-robin pick on a throwaway balancer (simulation)\""
            );
        }
        None => {
            let _ = writeln!(
                out,
                "decision: none reason=\"no operational server (all drained or zero-weight)\""
            );
        }
    }
    out
}

/// Base directory for relative config paths (certs, keys, CAs).
fn base_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Resolves the validated config to the dataplane model: parsed
/// addresses, shared backends (one [`Balancer`] per backend), PEM-loaded
/// TLS and health checks. `base_dir` is the base of relative paths.
fn resolve(config: &Config, base_dir: &Path) -> Result<Vec<ResolvedListener>, String> {
    let mut backends: std::collections::BTreeMap<String, Arc<ResolvedBackend>> =
        std::collections::BTreeMap::new();
    for (name, backend) in &config.backend {
        let servers: Vec<ResolvedServer> = backend
            .server_entries()
            .into_iter()
            .map(|(addr, weight)| {
                let addr: SocketAddr = addr.parse().map_err(|_| {
                    format!("backend.{name} invalid address: \"{addr}\" (expected IP:PORT)")
                })?;
                Ok(ResolvedServer { addr, weight })
            })
            .collect::<Result<_, String>>()?;
        let (fall, rise) = backend
            .health_check
            .as_ref()
            .map(|hc| (hc.fall, hc.rise))
            .unwrap_or((3, 2));
        let mut resolved = ResolvedBackend::new(name.clone(), servers, fall, rise)
            .with_proxy_protocol(match backend.proxy_protocol {
                eqproxy_config::schema::ProxyProtocolMode::None => ProxyProtocolMode::None,
                eqproxy_config::schema::ProxyProtocolMode::V1 => ProxyProtocolMode::V1,
            });
        if let Some(hc) = &backend.health_check {
            let mut check = HealthCheck::tcp(hc.interval, hc.timeout).with_passive(hc.passive);
            if hc.kind == eqproxy_config::schema::HealthCheckKind::Http {
                let expect_status =
                    eqproxy_core::expectation::StatusExpectation::parse(&hc.expect_status)
                        .map_err(|why| {
                            format!("backend.{name}.health_check.expect_status: {why}")
                        })?;
                let expect_rstring = hc
                    .expect_rstring
                    .as_deref()
                    .map(eqproxy_core::expectation::RegexMatcher::parse)
                    .transpose()
                    .map_err(|why| format!("backend.{name}.health_check.expect_rstring: {why}"))?;
                check = check.with_http(eqproxy_net::health::HttpCheck {
                    method: match hc.http_method {
                        eqproxy_config::schema::HealthCheckMethod::Get => {
                            eqproxy_net::health::HttpCheckMethod::Get
                        }
                        eqproxy_config::schema::HealthCheckMethod::Head => {
                            eqproxy_net::health::HttpCheckMethod::Head
                        }
                    },
                    path: hc.http_path.clone(),
                    host: hc.http_host.clone(),
                    expect_status,
                    expect_rstring,
                });
            }
            resolved = resolved.with_health_check(check);
        }
        // Bounded wait queue (B-H7): `maxqueue = 0` = reject immediately.
        if backend.maxqueue > 0 {
            resolved = resolved.with_queue(eqproxy_net::proxy::QueueSettings {
                maxqueue: backend.maxqueue,
                timeout: backend.timeout_queue,
            });
        }
        // Connect-phase retries (B-H7): idempotent only unless the
        // explicit `retry_non_idempotent` opt-in.
        resolved = resolved.with_retries(eqproxy_net::proxy::RetryPolicy {
            max: backend.retries,
            non_idempotent: backend.retry_non_idempotent,
        });
        if let Some(client_tls) = &backend.tls {
            let ca = client_tls
                .ca_file
                .as_deref()
                .map(|ca| read_pem(base_dir, &format!("backend.{name}.tls.ca_file"), ca))
                .transpose()?;
            let tls = tls::client_config(
                ca.as_deref(),
                client_tls.verify,
                client_tls.server_name.as_deref(),
                &client_tls.alpn,
                tls_version(client_tls.min_version),
            )
            .map_err(|e| format!("backend.{name}.tls: {e}"))?;
            resolved = resolved.with_tls(tls);
        }
        backends.insert(name.clone(), Arc::new(resolved));
    }

    config
        .listener
        .iter()
        .map(|(name, listener)| {
            let listen: SocketAddr = listener
                .listen
                .parse()
                .map_err(|_| format!("listener.{name}.listen invalid: \"{}\"", listener.listen))?;
            let backend = backends.get(&listener.backend).ok_or_else(|| {
                format!(
                    "listener.{name}.backend does not exist: \"{}\"",
                    listener.backend
                )
            })?;
            let mut resolved = ResolvedListener::new(
                name.clone(),
                listen,
                listener.backend.clone(),
                backend.servers[0].addr,
                match listener.mode {
                    eqproxy_config::ListenerMode::Tcp => ProxyMode::Tcp,
                    eqproxy_config::ListenerMode::Http => ProxyMode::Http,
                },
                listener.maxconn,
                listener.connect_timeout,
                listener.idle_timeout,
                listener.client_header_timeout,
                listener.server_header_timeout,
            )
            .with_backend(Arc::clone(backend));
            // PROXY v1 reception (B-H9/B-E10): strict front door with
            // allowlisted origins only.
            if listener.proxy_receive {
                let allowlist =
                    eqproxy_core::expectation::IpAllowlist::parse(&listener.proxy_allow)
                        .map_err(|why| format!("listener.{name}.proxy_allow: {why}"))?;
                resolved = resolved.with_proxy_receive(allowlist);
            }
            resolved = resolved.with_forwarded_headers(match listener.forwarded_headers {
                eqproxy_config::schema::ForwardedHeaders::Off => {
                    eqproxy_net::proxy::ForwardedMode::Off
                }
                eqproxy_config::schema::ForwardedHeaders::Append => {
                    eqproxy_net::proxy::ForwardedMode::Append
                }
                eqproxy_config::schema::ForwardedHeaders::Replace => {
                    eqproxy_net::proxy::ForwardedMode::Replace
                }
            });
            if let Some(local) = &listener.local_response {
                resolved = resolved.with_local_response(eqproxy_net::proxy::LocalResponse {
                    status: local.status,
                    content_type: local.content_type.clone(),
                    body: local.body.clone(),
                });
            }
            if let Some(server_tls) = &listener.tls {
                let cert = read_pem(
                    base_dir,
                    &format!("listener.{name}.tls.cert"),
                    &server_tls.cert,
                )?;
                let key = read_pem(
                    base_dir,
                    &format!("listener.{name}.tls.key"),
                    &server_tls.key,
                )?;
                // mTLS (A15): optional client CA = mutual TLS enforced.
                let client_ca = server_tls
                    .client_ca
                    .as_deref()
                    .map(|ca| read_pem(base_dir, &format!("listener.{name}.tls.client_ca"), ca))
                    .transpose()?;
                let acceptor = tls::server_config(
                    &cert,
                    &key,
                    client_ca.as_deref(),
                    &server_tls.alpn,
                    tls_version(server_tls.min_version),
                )
                .map_err(|e| format!("listener.{name}.tls: {e}"))?;
                resolved = resolved.with_server_tls(acceptor);
            }
            Ok(resolved)
        })
        .collect()
}

fn tls_version(version: eqproxy_config::schema::TlsVersion) -> TlsVersion {
    match version {
        eqproxy_config::schema::TlsVersion::V1_2 => TlsVersion::V1_2,
        eqproxy_config::schema::TlsVersion::V1_3 => TlsVersion::V1_3,
    }
}

/// Reads a PEM (cert, key or CA) with an actionable error when missing.
fn read_pem(base_dir: &Path, field: &str, path: &str) -> Result<Vec<u8>, String> {
    let full = base_dir.join(path);
    std::fs::read(&full).map_err(|e| {
        format!(
            "{field} \"{path}\": could not read {} — {e}",
            full.display()
        )
    })
}

async fn run(path: PathBuf, metrics_interval: String) -> u8 {
    let interval = match eqproxy_config::duration::parse(&metrics_interval) {
        Ok(value) if !value.is_zero() => value,
        _ => {
            eprintln!(
                "error: --metrics-interval \"{metrics_interval}\" is not a valid duration; example: 30s"
            );
            return 1;
        }
    };

    let (config, result) = match load_and_check(&path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }

    let listeners = match resolve(&config, base_dir(&path)) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: inconsistent configuration after validation: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: the configuration defines no listeners; nothing to serve");
        return 1;
    }

    let metrics = Arc::new(Metrics::default());
    let bound = match bind(listeners, Arc::clone(&metrics)).await {
        Ok(bound) => bound,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };
    for (name, addr) in bound.local_addrs() {
        eprintln!("INFO listener {name} listening on {addr}");
    }

    let (handle, signal) = shutdown::channel();

    // Metrics reporter: exits on the shutdown signal.
    let reporter_metrics = Arc::clone(&metrics);
    let mut reporter_signal = signal.clone();
    let reporter = tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = tick.tick() => eprintln!("METRICS {}", reporter_metrics.snapshot()),
                _ = reporter_signal.wait() => break,
            }
        }
    });

    // Ctrl-C / SIGINT → graceful shutdown.
    let signal_handle = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("INFO shutdown signal received; draining connections");
            signal_handle.trigger();
        }
    });

    // SIGHUP → hot config reload (S-CFG-01, unix): re-read the file, run
    // the startup gate and send the resolved listeners to the dataplane.
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);
    #[cfg(unix)]
    {
        let hup_path = path.clone();
        let hup_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut hup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(hup) => hup,
                    Err(err) => {
                        eprintln!("ERROR SIGHUP handler unavailable: {err}");
                        return;
                    }
                };
            while hup.recv().await.is_some() {
                match reload_gate(&hup_path) {
                    Ok(listeners) => {
                        if reload_tx.send(listeners).await.is_err() {
                            break;
                        }
                    }
                    Err(msg) => {
                        hup_metrics
                            .config_reload_failures
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!("ERROR config reload rejected: {msg}");
                    }
                }
            }
        });
    }
    #[cfg(not(unix))]
    let _ = reload_tx;

    let serve_result = bound
        .serve_with_reloads(signal, config.shutdown_grace, reload_rx)
        .await;
    let _ = reporter.await;
    eprintln!("METRICS {} (final)", metrics.snapshot());
    match serve_result {
        Ok(()) => {
            eprintln!("shutdown complete");
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn two_server_listener() -> (Config, ResolvedListener) {
        let mut backend = BTreeMap::new();
        backend.insert(
            "api".to_owned(),
            eqproxy_config::schema::BackendConfig {
                servers: Some(vec![
                    eqproxy_config::schema::ServerConfig {
                        addr: "127.0.0.1:9000".to_owned(),
                        weight: 3,
                    },
                    eqproxy_config::schema::ServerConfig {
                        addr: "127.0.0.1:9001".to_owned(),
                        weight: 1,
                    },
                ]),
                ..eqproxy_config::schema::BackendConfig::default()
            },
        );
        let config = Config {
            schema_version: 1,
            listener: BTreeMap::new(),
            backend,
            shutdown_grace: Duration::from_secs(10),
            metrics: eqproxy_config::schema::MetricsConfig::default(),
        };
        let backend = Arc::new(ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: "127.0.0.1:9000".parse().expect("addr"),
                    weight: 3,
                },
                ResolvedServer {
                    addr: "127.0.0.1:9001".parse().expect("addr"),
                    weight: 1,
                },
            ],
            3,
            2,
        ));
        let listener = ResolvedListener::new(
            "web",
            "127.0.0.1:8080".parse().expect("addr"),
            "api",
            "127.0.0.1:9000".parse().expect("addr"),
            ProxyMode::Http,
            1024,
            Duration::from_secs(5),
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .with_backend(backend);
        (config, listener)
    }

    #[test]
    fn select_listener_prefers_the_only_one() {
        let (_, listener) = two_server_listener();
        let all = [listener];
        assert_eq!(select_listener(&all, None).expect("one").name, "web");
        assert_eq!(
            select_listener(&all, Some("web")).expect("named").name,
            "web"
        );
    }

    #[test]
    fn select_listener_errors_name_candidates() {
        let (_, first) = two_server_listener();
        let (_, second) = two_server_listener();
        let all = [first, second];
        let err = select_listener(&all, None).expect_err("ambiguous");
        assert!(err.contains("--listener"), "error: {err}");
        let err = select_listener(&all, Some("nope")).expect_err("unknown");
        assert!(err.contains("unknown listener"), "error: {err}");
    }

    fn parse_config(source: &str) -> Config {
        eqproxy_config::parse_str(source, Path::new("test.toml")).expect("test config")
    }

    #[test]
    fn diff_report_is_empty_for_identical_configs() {
        let source = "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9000\"\n";
        let report = diff_report(&parse_config(source), &parse_config(source));
        assert_eq!(report, "no differences");
    }

    #[test]
    fn diff_report_names_changed_weight_and_added_listener() {
        let left = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", weight = 3 }]\n",
        );
        let right = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[listener.extra]\nlisten = \"127.0.0.1:8081\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", weight = 1 }]\n",
        );
        let report = diff_report(&left, &right);
        for expected in [
            "2 difference(s):",
            "+ listener \"extra\" (only in right)",
            "~ backend \"api\" servers: [127.0.0.1:9000(3)] -> [127.0.0.1:9000(1)]",
        ] {
            assert!(
                report.contains(expected),
                "missing {expected:?} in:\n{report}"
            );
        }
    }

    #[test]
    fn plan_report_inventories_listeners_backends_and_servers() {
        let (config, listener) = two_server_listener();
        let report = plan_report(&config, &[listener]);
        for expected in [
            "plan: 1 listener(s), 1 backend(s) — nothing started (dry run)",
            "listener \"web\": bind 127.0.0.1:8080 mode=http maxconn=1024 tls=no backend=\"api\"",
            "backend \"api\": servers=2 tls=no proxy_protocol=none health_check=none",
            "server 127.0.0.1:9000 weight=3",
            "server 127.0.0.1:9001 weight=1",
        ] {
            assert!(
                report.contains(expected),
                "missing {expected:?} in:\n{report}"
            );
        }
    }

    #[test]
    fn explain_report_labels_simulation_and_decision() {
        let (config, listener) = two_server_listener();
        let report = explain_report(&config, &listener, "GET", "example.com", "/a");
        for expected in [
            "simulation: true",
            "request: GET /a host=example.com",
            "listener \"web\": listen=127.0.0.1:8080 mode=http",
            "backend \"api\": balance=roundrobin servers=2",
            "server 127.0.0.1:9000 weight=3 state=UP(initial)",
            "decision: server 127.0.0.1:9000",
        ] {
            assert!(
                report.contains(expected),
                "missing {expected:?} in:\n{report}"
            );
        }
    }

    #[test]
    fn explain_report_details_what_each_timeout_fires() {
        use eqproxy_net::proxy::{LocalResponse, QueueSettings, RetryPolicy, WaitQueue};

        let (config, mut listener) = two_server_listener();
        let backend = Arc::get_mut(&mut listener.backend).expect("unique backend");
        backend.queue = Some(WaitQueue::new(QueueSettings {
            maxqueue: 8,
            timeout: Duration::from_millis(500),
        }));
        backend.retries = RetryPolicy {
            max: 1,
            non_idempotent: false,
        };
        let listener = listener.with_local_response(LocalResponse {
            status: 503,
            content_type: "text/plain".to_owned(),
            body: "back soon".to_owned(),
        });
        let report = explain_report(&config, &listener, "GET", "example.com", "/a");
        for expected in [
            "timeouts: connect=5s idle=60s client_header=5s server_header=30s",
            "timeout_on_fire: connect=502 after 5s; client_header=408(first exchange)/close after 5s; server_header=504 after 30s; idle=close after 60s",
            "queue: maxqueue=8 timeout=500ms (full->503; expired->503)",
            "retries: max=1 scope=idempotent-only (connect-phase only; failed server excluded)",
            "local_response: status=503 content_type=\"text/plain\" body_bytes=9 (no-server class)",
        ] {
            assert!(
                report.contains(expected),
                "missing {expected:?} in:\n{report}"
            );
        }
    }

    #[test]
    fn history_names_sequence_and_sort() {
        assert_eq!(next_history_name(&[], 7), "0001-7.toml");
        let entries = vec!["0001-9.toml".to_owned(), "0009-1.toml".to_owned()];
        assert_eq!(next_history_name(&entries, 3), "0010-3.toml");
        // Non-conforming names never reset the sequence.
        let entries = vec!["scratch.toml".to_owned(), "0002-0.toml".to_owned()];
        assert_eq!(next_history_name(&entries, 0), "0003-0.toml");
    }

    #[test]
    fn history_header_round_trips_origin_and_body() {
        let raw = [
            history_header(Path::new("/etc/eqproxy"), 42).into_bytes(),
            b"schema_version = 1\n".to_vec(),
        ]
        .concat();
        assert_eq!(history_origin(&raw), Some(PathBuf::from("/etc/eqproxy")));
        assert_eq!(history_body(&raw), b"schema_version = 1\n");
        // Entries without a header resolve against the history dir.
        assert_eq!(history_origin(b"schema_version = 1\n"), None);
        assert_eq!(
            history_body(b"schema_version = 1\n"),
            b"schema_version = 1\n"
        );
    }

    #[test]
    fn atomic_write_replaces_whole_content() {
        let target = std::env::temp_dir().join(format!(
            "eqproxy-atomic-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::write(&target, b"old").expect("seed");
        atomic_write(&target, b"new").expect("replace");
        assert_eq!(std::fs::read(&target).expect("read"), b"new");
        std::fs::remove_file(&target).expect("cleanup");
    }

    #[test]
    fn fd_needed_matches_the_spec_budget() {
        assert_eq!(fd_needed(&[]), 0);
        // (2*1024 + 1 listener) * 11/10 = 2253.
        let (_, listener) = two_server_listener();
        assert_eq!(fd_needed(&[listener]), 2253);
    }

    #[test]
    fn doctor_report_counts_and_verdict() {
        let mut report = DoctorReport::new("test".to_owned());
        report.ok("bind 127.0.0.1:0".to_owned());
        report.warn("fds tight".to_owned());
        let shown = report.to_string();
        assert!(
            shown.contains("doctor: PASS (1 ok, 1 warn, 0 err)"),
            "{shown}"
        );
        assert_eq!(report.exit_code(), 0);
        report.err("bind 127.0.0.1:1: permission denied".to_owned());
        let shown = report.to_string();
        assert!(
            shown.contains("doctor: FAIL (1 ok, 1 warn, 1 err)"),
            "{shown}"
        );
        assert_eq!(report.exit_code(), 1);
    }

    // `push_fd` reads the soft NOFILE limit through `rlimit::getrlimit`
    // (FFI): miri has no shim for it on macOS. The test runs in every
    // normal `cargo test`; only the miri pass skips it (repo convention).
    #[cfg_attr(
        miri,
        ignore = "needs getrlimit (FFI): miri does not support foreign functions on macOS"
    )]
    #[test]
    fn doctor_fd_line_names_limit_and_formula() {
        let (_, listener) = two_server_listener();
        let mut report = DoctorReport::new("test".to_owned());
        report.push_fd(Some(&[listener]));
        let shown = report.to_string();
        assert!(shown.contains("need~2253"), "{shown}");
        assert!(
            shown.contains("fds: limit=") || shown.contains("fd limit unreadable"),
            "{shown}"
        );
        // Warnings never fail the run.
        assert_eq!(report.exit_code(), 0);
    }
}
