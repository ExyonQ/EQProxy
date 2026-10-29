//! EQProxy CLI.
//!
//! Implemented: `run`, `config validate/explain/diff/plan/apply/rollback`
//! and `doctor`. The rest **fail explicitly** with exit code 2
//! (never fake success).

#![forbid(unsafe_code)]

// One allocator for the whole binary. Profiling S-H3-01 put ~20 % of the CPU
// in musl's malloc lock plus the futex wakeups it causes across the tokio
// workers (`docs/evidence/v07-h3-profile.md`); the same path is 39 % faster
// with per-thread free lists. The decision and its trade-offs are ADR-0014.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use clap::{Parser, Subcommand};

use eqproxy_config::error::ConfigError;
use eqproxy_config::schema::{AdminConfig, Config};
use eqproxy_config::validate::{self, CheckResult};
use eqproxy_core::{Metrics, RequestFacts, shutdown};
use eqproxy_net::admin::{
    AdminTopology, ApplyMessage, ApplyReply, CertificateInfo, ConfigChange, UnixSocketPolicy,
};
use eqproxy_net::health::HealthCheck;
use eqproxy_net::proxy::SwapRequest;
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    AdminEndpoint, AdminState, ListenerInfo, ProxyMode, ProxyProtocolMode, ResolvedAdmin,
    ResolvedBackend, ResolvedListener, ResolvedServer, UnixSocketOptions, bind,
};

/// Writes a generated report to stdout, treating a reader that closed the
/// pipe as success.
///
/// `println!` panics on `EPIPE`, so `eqproxy config explain | head` used to
/// abort with "failed printing to stdout: Broken pipe" once the reader had
/// seen enough. Printing a report is best-effort: the reader stopping early
/// is not an error and must not turn a successful command into a panic.
fn emit_report(text: &str) {
    use std::io::{ErrorKind, Write as _};
    let mut out = std::io::stdout().lock();
    match out
        .write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
    {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::BrokenPipe => {}
        Err(err) => eprintln!("error: could not write the report to stdout: {err}"),
    }
}

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
        /// Simulated client IP for `ip` rule conditions
        #[arg(long, default_value = "127.0.0.1")]
        client_ip: String,
        /// Simulated request header for `headers` rule conditions
        /// (repeatable, "name=value")
        #[arg(long = "header", value_name = "NAME=VALUE")]
        headers: Vec<String>,
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
    /// Prints the JSON Schema of the configuration (Q1/CE1) for editor
    /// completion and inline validation: generated from the same types the
    /// parser accepts, so it never drifts from the format
    Schema {
        /// Write the schema to this file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
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
            client_ip,
            headers,
        } => explain(
            &config,
            listener.as_deref(),
            &method,
            &host,
            &path,
            &client_ip,
            &headers,
        ),
        ConfigCommand::Diff { left, right } => diff(&left, &right),
        ConfigCommand::Plan { config } => plan(&config),
        ConfigCommand::Apply { config } => apply(&config),
        ConfigCommand::Schema { output } => schema(output.as_deref()),
        ConfigCommand::Rollback => rollback(),
        ConfigCommand::Import { .. } => not_implemented("config import", "Phase 8"),
    }
}

/// `config schema` (Q1/CE1): the public JSON Schema of the configuration,
/// generated from the same Rust types the parser deserializes. Writes to
/// `--output` when given (so the repo copy is reproducible with one
/// command), otherwise to stdout.
fn schema(output: Option<&std::path::Path>) -> u8 {
    let schema = match eqproxy_config::json_schema() {
        Ok(schema) => schema,
        Err(err) => {
            eprintln!("error: could not render the configuration schema: {err}");
            return 1;
        }
    };
    match output {
        Some(path) => {
            let mut text = schema;
            text.push('\n');
            if let Err(err) = std::fs::write(path, text) {
                eprintln!("error: could not write {}: {err}", path.display());
                return 1;
            }
            0
        }
        None => {
            emit_report(&schema);
            0
        }
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
    emit_report(&diff_report(&left_config, &right_config));
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
            (
                "max_stream_duration",
                l.max_stream_duration,
                r.max_stream_duration,
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
        let l_servers: Vec<(String, u32, bool, u32)> = l
            .server_entries()
            .into_iter()
            .map(|s| (s.addr.to_owned(), s.weight, s.backup, s.priority))
            .collect();
        let r_servers: Vec<(String, u32, bool, u32)> = r
            .server_entries()
            .into_iter()
            .map(|s| (s.addr.to_owned(), s.weight, s.backup, s.priority))
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
        if l.all_backups != r.all_backups {
            changes.push(format!(
                "~ backend \"{name}\" all_backups: {} -> {}",
                l.all_backups, r.all_backups
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

/// `addr(weight)` for a primary and `addr(weight,backup)` for a backup
/// (B8), for a normalized server list; `[]` when empty.
fn entries_summary(entries: &[(String, u32, bool, u32)]) -> String {
    let items: Vec<String> = entries
        .iter()
        .map(|(addr, w, backup, priority)| match (*backup, *priority) {
            (true, 0) => format!("{addr}({w},backup)"),
            (true, p) => format!("{addr}({w},backup,{p})"),
            (false, _) => format!("{addr}({w})"),
        })
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
fn explain(
    path: &Path,
    want: Option<&str>,
    method: &str,
    host: &str,
    req_path: &str,
    client_ip: &str,
    raw_headers: &[String],
) -> u8 {
    let client_ip: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!(
                "error: --client-ip \"{client_ip}\" is not a valid IP address; example: --client-ip 10.1.2.3"
            );
            return 1;
        }
    };
    let mut headers = Vec::with_capacity(raw_headers.len());
    for raw in raw_headers {
        let Some((name, value)) = raw.split_once('=') else {
            eprintln!(
                "error: --header \"{raw}\" is not name=value; example: --header x-tenant=acme"
            );
            return 1;
        };
        headers.push((name.to_owned(), value.to_owned()));
    }
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
    emit_report(&explain_report(
        &config, listener, method, host, req_path, &headers, client_ip,
    ));
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
    emit_report(&plan_report(&config, &listeners));
    0
}

/// Renders the activation inventory. Pure function of the validated config
/// and the resolved model (verified by unit test); the only I/O of `plan`
/// is printing it. One defensive line per listener/backend/server so the
/// operator can eyeball exactly what `run` would bring up.
fn plan_report(config: &Config, listeners: &[ResolvedListener]) -> String {
    use std::fmt::Write as _;
    // One entry per distinct default backend, taken from the resolved
    // listeners themselves: the inventory cannot disagree with the model it
    // prints (no name lookup to miss).
    let mut backends: Vec<&ResolvedBackend> =
        listeners.iter().map(|l| l.backend.as_ref()).collect();
    backends.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    backends.dedup_by(|a, b| a.name == b.name);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "plan: {} listener(s), {} backend(s) — nothing started (dry run)",
        listeners.len(),
        backends.len()
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
                if t.sni_names().is_empty() {
                    format!("yes(alpn=[{}])", protos.join(","))
                } else {
                    let names: Vec<String> =
                        t.sni_names().iter().map(|entry| entry.join(",")).collect();
                    format!(
                        "yes(alpn=[{}] sni=[{}])",
                        protos.join(","),
                        names.join("; ")
                    )
                }
            }
        };
        let quic = if listener.quic { " quic=h3/udp" } else { "" };
        let _ = writeln!(
            out,
            "listener \"{}\": bind {} mode={} maxconn={} tls={} backend=\"{}\"{}",
            listener.name,
            listener.listen,
            mode,
            listener.maxconn,
            tls,
            listener.backend_name,
            quic
        );
        let _ = writeln!(
            out,
            "  timeouts: connect={:?} idle={:?} client_header={:?} server_header={:?} max_stream={:?} shutdown_grace={:?}",
            listener.connect_timeout,
            listener.idle_timeout,
            listener.client_header_timeout,
            listener.server_header_timeout,
            listener.max_stream_duration,
            config.shutdown_grace
        );
    }
    for backend in backends {
        let proxy_protocol = match backend.proxy_protocol {
            ProxyProtocolMode::None => "none",
            ProxyProtocolMode::V1 => "v1",
            ProxyProtocolMode::V2 => "v2",
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
            emit_report(&diff_report(&prev, &config));
        }
        None => {
            println!(
                "applied: {} -> {} (no previous configuration)",
                path.display(),
                current.display()
            );
            emit_report(&plan_report(&config, &listeners));
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
            emit_report(&diff_report(&prev, &config));
        }
        None => {
            println!("rolled back: current restored from {name} (no previous current to compare)");
            emit_report(&plan_report(&config, &listeners));
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
/// One-line summary of a rule action for `config explain` (v0.6 slice
/// 2): the redirect shows its Location rendered against the simulated
/// request, so the operator sees the exact URL the client would get.
/// One-line summary of a rule's header actions (B-N4/B-I4/B-E17) for
/// `config explain`; empty when the rule has none.
fn headers_summary(headers: Option<&eqproxy_net::ResolvedHeaders>) -> String {
    let Some(headers) = headers else {
        return String::new();
    };
    let mut parts = Vec::new();
    for (name, value) in &headers.set {
        parts.push(format!("set {name} -> {value:?}"));
    }
    for (name, value) in &headers.add {
        parts.push(format!("add {name} -> {value:?}"));
    }
    for name in &headers.del {
        parts.push(format!("del {name}"));
    }
    for (name, value) in &headers.response {
        parts.push(format!("response set {name} -> {value:?}"));
    }
    if let Some(cors) = &headers.cors {
        parts.push(format!("cors origin {}", cors.allow_origin));
    }
    if let Some(limit) = &headers.rate_limit {
        parts.push(limit.describe());
    }
    if let Some(auth) = &headers.auth {
        let mut kinds = Vec::new();
        if auth.basic.is_some() {
            kinds.push(format!("basic realm {:?}", auth.realm));
        }
        if let Some(url) = &auth.url {
            kinds.push(format!(
                "subrequest http://{}:{}{}",
                url.host, url.port, url.path
            ));
        }
        parts.push(format!("auth {}", kinds.join(" + ")));
    }
    if let Some(mirror) = &headers.mirror {
        parts.push(mirror.describe());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [headers: {}]", parts.join(", "))
    }
}

fn action_summary(action: &eqproxy_net::RouteAction, host: &str, req_path: &str) -> String {
    match action {
        eqproxy_net::RouteAction::Backend { backend, rewrite } => {
            let mut out = format!("use_backend \"{}\"", backend.name);
            if let Some(rewrite) = rewrite {
                let mut parts = Vec::new();
                if let Some(prefix) = &rewrite.path_prefix_rewrite {
                    parts.push(format!(
                        "path_prefix {:?} -> {prefix:?}",
                        rewrite.matched_prefix
                    ));
                }
                if let Some(new_host) = &rewrite.host_rewrite {
                    parts.push(format!("host -> {new_host:?}"));
                }
                out.push_str(&format!(" (rewrite: {})", parts.join(", ")));
            }
            out
        }
        eqproxy_net::RouteAction::Split { targets, hash, .. } => {
            let parts: Vec<String> = targets
                .targets()
                .iter()
                .map(|target| format!("{} w={}", target.backend.name, target.weight))
                .collect();
            // Without a hash policy, selection rotates; with one, the same
            // key sticks to the same target (B-H3).
            let selection = match hash {
                Some(hash) => format!(
                    "{} (weighted rendezvous: the key keeps its target)",
                    hash.describe()
                ),
                None => "smooth weighted round-robin per request".to_owned(),
            };
            format!("split [{}] ({selection})", parts.join(", "))
        }
        eqproxy_net::RouteAction::Redirect { status, location } => {
            let rendered = eqproxy_core::rules::render_location(location, host, req_path)
                .unwrap_or_else(|why| format!("(invalid template: {why})"));
            format!("redirect {status} -> {rendered:?}")
        }
        eqproxy_net::RouteAction::Direct {
            status,
            content_type,
            body,
        } => format!(
            "direct_response {status} {content_type:?} ({} bytes)",
            body.len()
        ),
    }
}

fn explain_report(
    config: &Config,
    listener: &ResolvedListener,
    method: &str,
    host: &str,
    req_path: &str,
    headers: &[(String, String)],
    client_ip: std::net::IpAddr,
) -> String {
    use std::fmt::Write as _;
    let mode = match listener.mode {
        ProxyMode::Tcp => "tcp",
        ProxyMode::Http => "http",
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "simulation: true (no requests issued, no state changed)"
    );
    let _ = writeln!(out, "request: {method} {req_path} host={host}");
    // TLS with its SNI names (B-I2/B-H10/B-E9) when the listener has more
    // than the default certificate.
    let tls = match listener.server_tls.as_ref() {
        None => "no".to_owned(),
        Some(t) if t.sni_names().is_empty() => "yes".to_owned(),
        Some(t) => {
            let names: Vec<String> = t.sni_names().iter().map(|entry| entry.join(",")).collect();
            format!("yes sni=[{}]", names.join("; "))
        }
    };
    let _ = writeln!(
        out,
        "listener \"{}\": listen={} mode={} maxconn={} tls={tls}",
        listener.name, listener.listen, mode, listener.maxconn,
    );
    // Routing (B-H3/B-H4, H4): every rule and why it matched or not, then
    // the decision — never a bare backend without the path to it.
    let facts = RequestFacts {
        method,
        host,
        path: req_path,
        headers,
        peer: client_ip,
        maps: listener.maps.as_ref(),
    };
    if !listener.routes.is_empty() {
        let _ = writeln!(out, "rules: {} (first match wins)", listener.routes.len());
    }
    let mut chosen: Option<&eqproxy_net::RouteAction> = None;
    let mut chosen_headers: Option<&eqproxy_net::ResolvedHeaders> = None;
    for (i, route) in listener.routes.iter().enumerate() {
        let label = format!("rule[{i}] \"{}\"", route.rule.name);
        match route.rule.explain(&facts) {
            Ok(()) => {
                let _ = writeln!(
                    out,
                    "{label}: match -> {}{}",
                    action_summary(&route.action, host, req_path),
                    headers_summary(route.headers.as_ref())
                );
                if chosen.is_none() {
                    chosen = Some(&route.action);
                    chosen_headers = route.headers.as_ref();
                }
            }
            Err(reason) => {
                let _ = writeln!(out, "{label}: no match ({reason})");
            }
        }
    }
    let _ = writeln!(
        out,
        "route_decision: {}",
        chosen.map_or_else(
            || format!(
                "no rule matched -> default backend \"{}\"",
                listener.backend.name
            ),
            |action| format!(
                "first matching rule -> {}{}",
                action_summary(action, host, req_path),
                headers_summary(chosen_headers)
            )
        )
    );
    // Data maps in force (C10): what `map` conditions see (the file
    // watchers keep this data fresh without any reload).
    for map in listener.maps.iter() {
        let _ = writeln!(out, "map \"{}\": {}", map.name(), map.describe());
    }
    // Backend involvement (v0.6 slice 2): local actions (redirect /
    // direct_response) never contact one, so the backend, balancer and
    // server lines only appear when a backend is actually used. For a
    // `split` (B-I11) the shown backend is the target a throwaway
    // splitter picks first — the simulated pick advances no shared
    // state, same contract as the sim balancer.
    let sim_backend: Option<Arc<ResolvedBackend>> = match chosen {
        Some(
            eqproxy_net::RouteAction::Redirect { .. } | eqproxy_net::RouteAction::Direct { .. },
        ) => None,
        Some(eqproxy_net::RouteAction::Backend { backend, .. }) => Some(Arc::clone(backend)),
        Some(eqproxy_net::RouteAction::Split { targets, .. }) => {
            let throwaway = eqproxy_net::SplitTargets::new(
                targets
                    .targets()
                    .iter()
                    .map(|target| eqproxy_net::SplitTarget {
                        backend: Arc::clone(&target.backend),
                        weight: target.weight,
                    })
                    .collect(),
            );
            Some(Arc::clone(throwaway.pick()))
        }
        None => Some(Arc::clone(&listener.backend)),
    };
    let sim_pick: Option<(eqproxy_net::Balancer, Option<std::net::SocketAddr>)> = match &sim_backend
    {
        None => {
            let _ = writeln!(out, "action: local response (no backend contacted)");
            None
        }
        Some(backend) => {
            let backend_cfg = config.backend.get(&backend.name);
            let (fall, rise) = backend_cfg
                .and_then(|b| b.health_check.as_ref())
                .map(|hc| (hc.fall, hc.rise))
                .unwrap_or((3, 2));
            let (algorithm, slow_start, all_backups) = backend_cfg.map_or(
                (
                    eqproxy_config::schema::BalanceAlgorithm::RoundRobin,
                    std::time::Duration::ZERO,
                    false,
                ),
                |b| (b.balance, b.slow_start, b.all_backups),
            );
            // Throwaway balancer: the simulated pick advances no shared state.
            let sim = eqproxy_net::Balancer::with_options(
                backend.servers.clone(),
                fall,
                rise,
                balance_algorithm(algorithm),
                slow_start,
            )
            .with_all_backups(all_backups);
            let pick = sim.pick();
            let affinity = match &backend.affinity {
                Some(affinity) => match affinity.mode {
                    eqproxy_net::AffinityMode::Cookie => format!("cookie({})", affinity.cookie),
                    eqproxy_net::AffinityMode::Source => "source".to_owned(),
                },
                None => "none".to_owned(),
            };
            let proxy_protocol = match backend.proxy_protocol {
                ProxyProtocolMode::None => "none",
                ProxyProtocolMode::V1 => "v1",
                ProxyProtocolMode::V2 => "v2",
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
            let balance_name = match algorithm {
                eqproxy_config::schema::BalanceAlgorithm::RoundRobin => "roundrobin",
                eqproxy_config::schema::BalanceAlgorithm::LeastConn => "leastconn",
            };
            let slow = if slow_start.is_zero() {
                String::new()
            } else {
                format!(" slow_start={slow_start:?}")
            };
            // `option allbackups` (B8) changes which server the simulated
            // pick reaches, so `explain` names it when it is on.
            let backups_pool = if all_backups {
                " all_backups=true".to_owned()
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "backend \"{}\": balance={} servers={} tls={} proxy_protocol={} health_check={} affinity={}{}{}",
                backend.name,
                balance_name,
                backend.servers.len(),
                if backend.tls.is_some() { "yes" } else { "no" },
                proxy_protocol,
                health,
                affinity,
                backups_pool,
                slow
            );
            Some((sim, pick))
        }
    };
    // Phase timeouts and their observable outcome when they fire (Q4/H5:
    // no surprises — `explain` documents what each timeout does BEFORE it
    // can fire, including the response the client receives).
    let _ = writeln!(
        out,
        "timeouts: connect={:?} idle={:?} client_header={:?} server_header={:?} max_stream={:?}",
        listener.connect_timeout,
        listener.idle_timeout,
        listener.client_header_timeout,
        listener.server_header_timeout,
        listener.max_stream_duration
    );
    let fire = match listener.mode {
        ProxyMode::Tcp => format!(
            "connect=close after {:?}; idle=close after {:?} (tcp: no response channel)",
            listener.connect_timeout, listener.idle_timeout
        ),
        ProxyMode::Http => {
            let mut fire = format!(
                "connect=502 after {:?}; client_header=408(first exchange)/close after {:?}; server_header=504 after {:?}; idle=close after {:?}",
                listener.connect_timeout,
                listener.client_header_timeout,
                listener.server_header_timeout,
                listener.idle_timeout
            );
            if !listener.max_stream_duration.is_zero() {
                fire.push_str(&format!(
                    "; max_stream=504(before head)/close after {:?}",
                    listener.max_stream_duration
                ));
            }
            fire
        }
    };
    let _ = writeln!(out, "timeout_on_fire: {fire}");
    if listener.quic {
        let _ = writeln!(
            out,
            "http3: yes (QUIC on udp/{}, ALPN h3; a TLS change needs a process restart)",
            listener.listen.port()
        );
    }
    if let Some(compression) = &listener.compression {
        let types = compression
            .types
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let codings = match (compression.gzip, compression.brotli) {
            (true, true) => format!(
                "gzip level={} brotli quality={}",
                compression.level, compression.brotli_quality
            ),
            (true, false) => format!("gzip level={}", compression.level),
            (false, true) => format!("brotli quality={}", compression.brotli_quality),
            (false, false) => "none".to_owned(),
        };
        let _ = writeln!(
            out,
            "compression: {codings} min_size={} types=[{types}] (negotiated from Accept-Encoding; HTTP/1.1 chunked)",
            compression.min_size
        );
    }
    if let Some(local) = &listener.local_response {
        let _ = writeln!(
            out,
            "local_response: status={} content_type=\"{}\" body_bytes={} (no-server class)",
            local.status,
            local.content_type,
            local.body.len()
        );
    }
    if let (Some((sim, pick)), Some(backend)) = (&sim_pick, &sim_backend) {
        let backend: &ResolvedBackend = backend;
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
        for server in &backend.servers {
            let state = match &server.addr {
                eqproxy_net::ServerAddr::Ip(ip) => {
                    if sim.is_up(*ip) {
                        "UP(initial)"
                    } else {
                        "DOWN(initial)"
                    }
                }
                // Names are resolved in the background (B-H13): the
                // simulation never blocks on DNS.
                eqproxy_net::ServerAddr::Name { .. } => "UNRESOLVED(dns)",
            };
            let _ = writeln!(
                out,
                "server {} weight={} state={state}",
                server.addr, server.weight
            );
        }
        match pick {
            Some(addr) => {
                let reason = match sim.algorithm() {
                    eqproxy_net::Balance::RoundRobin => "first weighted round-robin pick",
                    eqproxy_net::Balance::LeastConn => "first least-connections pick",
                };
                let _ = writeln!(
                    out,
                    "decision: server {addr} reason=\"{reason} on a throwaway balancer (simulation)\""
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "decision: none reason=\"no operational server (all drained or zero-weight)\""
                );
            }
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

/// Config balancing algorithm → dataplane (B-H5/B-N12/B-E6).
fn balance_algorithm(algorithm: eqproxy_config::schema::BalanceAlgorithm) -> eqproxy_net::Balance {
    match algorithm {
        eqproxy_config::schema::BalanceAlgorithm::RoundRobin => eqproxy_net::Balance::RoundRobin,
        eqproxy_config::schema::BalanceAlgorithm::LeastConn => eqproxy_net::Balance::LeastConn,
    }
}

/// Loads the `[maps.*]` data maps (C10/PP-02) into one registry per
/// config generation: file maps are read here (fail-closed at load,
/// like certificates) and watched by the dataplane afterwards, which
/// swaps their data in hot without any reload.
fn load_maps(
    config: &Config,
    base_dir: &Path,
) -> Result<Arc<eqproxy_core::maps::MapRegistry>, String> {
    let mut registry = eqproxy_core::maps::MapRegistry::new();
    for (name, map) in &config.maps {
        let (data, file) = match (&map.file, &map.entries) {
            (Some(file), None) => {
                let path = if Path::new(file).is_absolute() {
                    PathBuf::from(file)
                } else {
                    base_dir.join(file)
                };
                let meta = std::fs::metadata(&path)
                    .map_err(|e| format!("maps.{name}.file cannot be read: {e}"))?;
                if meta.len() > eqproxy_core::maps::MAX_MAP_FILE_BYTES {
                    return Err(format!(
                        "maps.{name}.file is {} bytes (maximum {})",
                        meta.len(),
                        eqproxy_core::maps::MAX_MAP_FILE_BYTES
                    ));
                }
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("maps.{name}.file cannot be read: {e}"))?;
                let data = eqproxy_core::maps::MapData::parse_bytes(&bytes, map.default.clone())
                    .map_err(|why| format!("maps.{name}.file: {why} (example: {})", why.example))?;
                (data, Some(path))
            }
            (None, Some(entries)) => {
                let data = eqproxy_core::maps::MapData::from_entries(entries, map.default.clone())
                    .map_err(|why| {
                        format!("maps.{name}.entries: {why} (example: {})", why.example)
                    })?;
                (data, None)
            }
            _ => {
                return Err(format!("maps.{name}: set exactly one of file or entries"));
            }
        };
        registry.insert(eqproxy_core::maps::HotMap::new(
            name.clone(),
            data,
            file,
            map.reload_interval,
        ));
    }
    Ok(Arc::new(registry))
}

/// Translates `[access_log]` to the dataplane settings (ADR-0020). A
/// relative path is resolved against the configuration file, like every
/// other file the document names (TLS, CAs, maps).
fn access_settings(config: &Config, base_dir: &Path) -> Option<eqproxy_net::AccessLogSettings> {
    let access = config.access_log.as_ref()?;
    Some(eqproxy_net::AccessLogSettings {
        path: access.path.as_ref().map(|path| base_dir.join(path)),
        format: match access.format {
            eqproxy_config::schema::AccessLogFormat::Json => eqproxy_net::AccessLogFormat::Json,
            eqproxy_config::schema::AccessLogFormat::Combined => {
                eqproxy_net::AccessLogFormat::Combined
            }
        },
    })
}

/// Resolves `[admin]` (v0.8, D6): the endpoint (TCP address or Unix socket
/// path, ADR-0021) and the bearer token. The token file is read here,
/// fail-closed like certificates; the running process never re-reads it
/// (changing it needs a restart).
fn resolve_admin(config: &Config, base_dir: &Path) -> Result<Option<ResolvedAdmin>, String> {
    let Some(admin) = &config.admin else {
        return Ok(None);
    };
    let endpoint = match (&admin.listen, &admin.unix_socket) {
        (Some(listen), None) => AdminEndpoint::Tcp(
            listen
                .parse()
                .map_err(|_| format!("admin.listen invalid: \"{listen}\""))?,
        ),
        (None, Some(path)) => AdminEndpoint::Unix(base_dir.join(path)),
        (Some(_), Some(_)) => {
            return Err("admin: set exactly one of listen or unix_socket, not both".to_owned());
        }
        (None, None) => {
            return Err("admin: set exactly one of listen or unix_socket".to_owned());
        }
    };
    let unix = unix_socket_options(admin)?;
    let token = admin_secret(
        admin.token.as_deref(),
        admin.token_file.as_deref(),
        base_dir,
        "token",
    )?
    .ok_or_else(|| "admin.token: set exactly one of token or token_file".to_owned())?;
    let write_token = admin_secret(
        admin.write_token.as_deref(),
        admin.write_token_file.as_deref(),
        base_dir,
        "write_token",
    )?;
    if let Some(write) = &write_token
        && write == &token
    {
        // Defence in depth: validation already refuses a shared secret.
        return Err(
            "admin.write_token equals admin.token: one secret per privilege level".to_owned(),
        );
    }
    Ok(Some(ResolvedAdmin {
        endpoint,
        unix,
        token,
        write_token,
        panel: admin.panel,
    }))
}

/// The Unix-socket half of `[admin]` (ADR-0021/0022/0023), shared by the
/// initial bind and by the SIGHUP path that re-applies it to a live socket.
/// Only the two documented modes exist; every other value is a configuration
/// error, never a silently rounded one.
fn unix_socket_options(admin: &AdminConfig) -> Result<UnixSocketOptions, String> {
    Ok(UnixSocketOptions {
        mode: match admin.unix_socket_mode.as_deref().unwrap_or("0600") {
            "0600" => 0o600,
            "0660" => 0o660,
            other => {
                return Err(format!(
                    "admin.unix_socket_mode: \"{other}\" is not 0600 or 0660"
                ));
            }
        },
        gid: admin.unix_socket_gid,
        allow_uids: admin.unix_socket_allow_uids.iter().copied().collect(),
        acl_uids: admin.unix_socket_acl_uids.iter().copied().collect(),
    })
}

/// Reads one admin secret (`<field>` or `<field>_file`, trailing newline
/// trimmed) and enforces the minimum length. `None` when neither is set.
fn admin_secret(
    token: Option<&str>,
    file: Option<&Path>,
    base_dir: &Path,
    field: &str,
) -> Result<Option<Arc<str>>, String> {
    let value = match (token, file) {
        (Some(token), None) => token.to_owned(),
        (None, Some(file)) => {
            let path = if file.is_absolute() {
                file.to_path_buf()
            } else {
                base_dir.join(file)
            };
            let raw = std::fs::read_to_string(&path)
                .map_err(|error| format!("admin.{field}_file cannot be read: {error}"))?;
            raw.trim_end_matches(['\r', '\n']).to_owned()
        }
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(format!(
                "admin.{field}: set exactly one of {field} or {field}_file"
            ));
        }
    };
    if value.len() < eqproxy_config::schema::MIN_ADMIN_TOKEN_BYTES {
        return Err(format!(
            "admin.{field} is {} bytes; use at least {}",
            value.len(),
            eqproxy_config::schema::MIN_ADMIN_TOKEN_BYTES
        ));
    }
    Ok(Some(Arc::from(value.as_str())))
}

/// The listener view the API reports. `bound` carries the addresses the
/// dataplane really opened, so a configured port 0 is reported by its
/// assigned port (the operator asked what is running, not what was written).
fn listener_infos(
    config: &Config,
    bound: &[(String, SocketAddr)],
    certificates: &BTreeMap<String, String>,
) -> Vec<ListenerInfo> {
    config
        .listener
        .iter()
        .map(|(name, listener)| ListenerInfo {
            name: name.clone(),
            listen: bound
                .iter()
                .find(|(bound_name, _)| bound_name == name)
                .map_or_else(|| listener.listen.clone(), |(_, addr)| addr.to_string()),
            mode: match listener.mode {
                eqproxy_config::schema::ListenerMode::Http => "http",
                eqproxy_config::schema::ListenerMode::Tcp => "tcp",
            }
            .to_owned(),
            backend: listener.backend.clone(),
            maxconn: listener.maxconn,
            // Read from the acceptors, not from the config: a renewal that
            // was rejected must not be reported as applied (D7).
            tls_fingerprint: certificates.get(name).cloned(),
        })
        .collect()
}

/// The applied generation the API reports and `If-Match` guards. The
/// configuration task is its only writer.
fn admin_topology(
    config: &Config,
    bound: &[(String, SocketAddr)],
    backends: Vec<Arc<ResolvedBackend>>,
    revision: String,
    certificates: &BTreeMap<String, String>,
) -> AdminTopology {
    AdminTopology {
        revision,
        listeners: listener_infos(config, bound, certificates),
        backends,
    }
}

/// Single writer of the configuration (ADR-0019): API `PUT`s and SIGHUP
/// arrive in one queue, so a revision check and the swap it authorizes can
/// never interleave with another write. The candidate is parsed, validated
/// and resolved **before** the dataplane is asked to swap; the applied
/// document and the revision advance only after the swap commits.
struct ConfigApplier {
    path: PathBuf,
    config: Config,
    revision: u64,
    modes: Arc<eqproxy_net::ServerModes>,
    topology: Arc<RwLock<AdminTopology>>,
    reloads: tokio::sync::mpsc::Sender<SwapRequest>,
    metrics: Arc<Metrics>,
    /// Access-log sink fixed at startup (ADR-0020): every generation keeps
    /// writing to the same destination, even when the file edits the section.
    access: Option<Arc<eqproxy_net::AccessLog>>,
    /// Live Unix socket policy of the admin plane (ADR-0022); `None` when the
    /// plane is on TCP or off, so no reload can widen a socket it does not own.
    admin_unix: Option<UnixSocketPolicy>,
    /// The `sha256:` leaf fingerprint each TLS listener was serving before the
    /// current generation, so a renewal can say what it actually changed
    /// (D7). Seeded from the acceptors opened at startup.
    certificates: BTreeMap<String, String>,
}

impl ConfigApplier {
    async fn run(
        mut self,
        mut messages: tokio::sync::mpsc::Receiver<ApplyMessage>,
        mut shutdown: shutdown::Shutdown,
    ) {
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                message = messages.recv() => {
                    let Some(message) = message else { break };
                    let reply = self.handle(&message).await;
                    // A closed receiver (the caller went away) is not an error.
                    let _ = message.reply.send(reply);
                }
            }
        }
    }

    async fn handle(&mut self, message: &ApplyMessage) -> ApplyReply {
        if matches!(message.change, ConfigChange::Reload) {
            return self.reload().await;
        }
        let current = format!("v{}", self.revision);
        if message.if_match.as_deref() != Some(current.as_str()) {
            return ApplyReply::Precondition { revision: current };
        }
        let mut candidate = self.config.clone();
        match &message.change {
            ConfigChange::Backend { name, table } => {
                match eqproxy_config::parse_backend_table(table, &self.path, name) {
                    Ok(backend) => {
                        candidate.backend.insert(name.clone(), backend);
                    }
                    Err(err) => {
                        return ApplyReply::Invalid {
                            message: err.to_string(),
                        };
                    }
                }
            }
            ConfigChange::Listener { name, table } => {
                match eqproxy_config::parse_listener_table(table, &self.path, name) {
                    Ok(listener) => {
                        candidate.listener.insert(name.clone(), listener);
                    }
                    Err(err) => {
                        return ApplyReply::Invalid {
                            message: err.to_string(),
                        };
                    }
                }
            }
            ConfigChange::Reload => unreachable!("handled above"),
        }
        self.apply_candidate(candidate).await
    }

    async fn reload(&mut self) -> ApplyReply {
        let loaded = match load_and_check(&self.path) {
            Ok(loaded) => loaded,
            Err(err) => return self.reload_failed(err.to_string()),
        };
        let (config, result) = loaded;
        for warning in &result.warnings {
            eprintln!("warning: {warning}");
        }
        if !result.is_valid() {
            return self.reload_failed(
                result
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let reply = self.apply_candidate(config).await;
        // A candidate rejected after validation (an impossible socket policy,
        // an inconsistent topology, a certificate that does not parse) is
        // still a failed reload: the counter must show it and the process log
        // must say why, or an operator sees a green metric and a silent
        // rejected renewal. Validation failures were already reported by
        // `reload_failed`.
        if let ApplyReply::Invalid { message } = &reply {
            self.metrics
                .config_reload_failures
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("ERROR config reload rejected: {message}");
        }
        reply
    }

    fn reload_failed(&self, message: String) -> ApplyReply {
        self.metrics
            .config_reload_failures
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("ERROR config reload rejected: {message}");
        ApplyReply::Invalid { message }
    }

    /// Validates and resolves the whole candidate, then asks the dataplane to
    /// swap. Nothing is committed until the dataplane confirms, and a failed
    /// validation never reaches it (the running generation keeps serving).
    async fn apply_candidate(&mut self, candidate: Config) -> ApplyReply {
        let result = validate::check(&candidate, "", &self.path);
        for warning in &result.warnings {
            eprintln!("warning: {warning}");
        }
        if !result.is_valid() {
            return ApplyReply::Invalid {
                message: result
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            };
        }
        if candidate.access_log != self.config.access_log {
            eprintln!(
                "WARN [access_log] changed in the configuration but the sink is fixed at startup; restart to apply the new destination or format"
            );
        }
        let (listeners, backends) = match resolve_with(
            &candidate,
            base_dir(&self.path),
            &self.modes,
            self.access.as_ref(),
        ) {
            Ok(resolved) => resolved,
            Err(message) => {
                return ApplyReply::Invalid {
                    message: format!("inconsistent configuration after validation: {message}"),
                };
            }
        };
        if listeners.is_empty() {
            return ApplyReply::Invalid {
                message: "the configuration defines no listeners; nothing to serve".to_owned(),
            };
        }
        // The admin socket policy moves before the dataplane swap and is put
        // back if the swap is refused: a rejected generation leaves neither
        // a new socket mode nor a new allowlist behind.
        let previous_unix = match self.apply_admin_unix_policy(&candidate) {
            Ok(previous) => previous,
            Err(message) => return ApplyReply::Invalid { message },
        };
        let (reply, outcome) = tokio::sync::oneshot::channel();
        let swap = if self
            .reloads
            .send(SwapRequest {
                listeners,
                reply: Some(reply),
            })
            .await
            .is_err()
        {
            Err("the dataplane is not accepting swaps".to_owned())
        } else {
            match outcome.await {
                Ok(Ok(outcome)) => Ok(outcome),
                Ok(Err(message)) => Err(message),
                Err(_) => Err("the dataplane dropped the swap without an answer".to_owned()),
            }
        };
        let outcome = match swap {
            Ok(outcome) => outcome,
            Err(message) => {
                self.restore_admin_unix(previous_unix);
                return ApplyReply::Rejected { message };
            }
        };
        // What the reload actually changed, listener by listener (D7): the
        // fingerprints come from the live acceptors after the commit, so a
        // certificate that failed to load is never reported as renewed.
        let certificates: Vec<CertificateInfo> = outcome
            .certificates
            .iter()
            .map(|fact| CertificateInfo {
                listener: fact.listener.clone(),
                listen: fact.listen.to_string(),
                fingerprint: fact.fingerprint.clone(),
                changed: self.certificates.get(&fact.listener) != Some(&fact.fingerprint),
                quic: fact.quic,
            })
            .collect();
        for fact in &outcome.certificates {
            self.certificates
                .insert(fact.listener.clone(), fact.fingerprint.clone());
        }
        self.revision += 1;
        let revision = format!("v{}", self.revision);
        let view = admin_topology(
            &candidate,
            &outcome.listeners,
            backends,
            revision.clone(),
            &self.certificates,
        );
        *self
            .topology
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = view;
        self.apply_metrics_options(&candidate);
        self.config = candidate;
        ApplyReply::Applied {
            revision,
            summary: outcome.summary.to_string(),
            elapsed_ms: u64::try_from(outcome.elapsed.as_millis()).unwrap_or(u64::MAX),
            listeners: outcome
                .listeners
                .into_iter()
                .map(|(name, addr)| (name, addr.to_string()))
                .collect(),
            certificates,
        }
    }
}

impl ConfigApplier {
    /// Applies the `[metrics]` options of `candidate` after a committed swap
    /// (CE4). `detailed` moves in hot — enabling starts an empty window and
    /// disabling drops it, so the export never shows a window whose flag is
    /// off. The budget is fixed at startup: shrinking it under live series
    /// would need an eviction policy nobody asked for, so it is reported and
    /// left for the next restart instead of being silently ignored.
    fn apply_metrics_options(&self, candidate: &Config) {
        if candidate.metrics.detailed != self.config.metrics.detailed {
            self.metrics.detail.set_enabled(candidate.metrics.detailed);
            eprintln!(
                "INFO metrics detail {} (budget {} series)",
                if candidate.metrics.detailed {
                    "enabled"
                } else {
                    "disabled; collected series dropped"
                },
                self.metrics.detail.budget()
            );
        }
        if candidate.metrics.max_series != self.config.metrics.max_series {
            eprintln!(
                "WARN [metrics] max_series changed from {} to {} but the budget is fixed at startup; restart to apply it (the live budget stays {})",
                self.config.metrics.max_series,
                candidate.metrics.max_series,
                self.metrics.detail.budget()
            );
        }
    }

    /// Applies the `[admin]` Unix socket policy of `candidate` to the socket
    /// this process already bound (ADR-0022). Returns the policy that was in
    /// force when the socket changed, so a refused swap can restore it.
    ///
    /// Only the mode, the owning group and the peer-uid allowlist are hot: the
    /// endpoint is a bound socket and the tokens were loaded at startup, so
    /// those changes are reported and left for the next restart instead of
    /// being silently pretended.
    fn apply_admin_unix_policy(
        &self,
        candidate: &Config,
    ) -> Result<Option<UnixSocketOptions>, String> {
        let Some(policy) = &self.admin_unix else {
            return Ok(None);
        };
        let Some(next_admin) = candidate.admin.as_ref() else {
            eprintln!(
                "WARN [admin] removed from the configuration but the plane is fixed at startup; it keeps serving until a restart"
            );
            return Ok(None);
        };
        let current_admin = self.config.admin.as_ref();
        let moved = current_admin.is_none_or(|current| {
            current.listen != next_admin.listen || current.unix_socket != next_admin.unix_socket
        });
        if moved {
            eprintln!(
                "WARN [admin] endpoint changed but the plane is fixed at startup; restart to move it (the bound socket keeps serving)"
            );
            return Ok(None);
        }
        let next = unix_socket_options(next_admin)?;
        let current = policy.options();
        if next.mode == current.mode
            && next.gid == current.gid
            && next.allow_uids == current.allow_uids
            && next.acl_uids == current.acl_uids
        {
            return Ok(None);
        }
        if let Err(error) = policy.apply(&next) {
            // The socket keeps the policy it had: the rejection is reported
            // once, here, with the failing syscall, and nothing is swapped.
            let message = format!("admin unix socket policy cannot be applied: {error}");
            eprintln!("ERROR {message}");
            return Err(message);
        }
        eprintln!(
            "INFO admin socket policy applied: mode {:04o}, gid {}, {} allowed uid(s)",
            next.mode,
            next.gid
                .map_or_else(|| "unchanged".to_owned(), |gid| gid.to_string()),
            next.allow_uids.len()
        );
        Ok(Some(current))
    }

    /// Puts the previous policy back after the dataplane refused the swap.
    fn restore_admin_unix(&self, previous: Option<UnixSocketOptions>) {
        let (Some(policy), Some(previous)) = (&self.admin_unix, previous) else {
            return;
        };
        if let Err(error) = policy.apply(&previous) {
            eprintln!("WARN admin socket policy cannot be restored after a refused swap: {error}");
        }
    }
}

/// Resolves the validated config to the dataplane model: parsed
/// addresses, shared backends (one [`Balancer`] per backend), PEM-loaded
/// TLS and health checks. `base_dir` is the base of relative paths.
fn resolve(config: &Config, base_dir: &Path) -> Result<Vec<ResolvedListener>, String> {
    // One-off registry: the check paths (`config validate`, `plan`) only need
    // the listeners, and no state can be declared there. No access sink: a
    // validation command never opens a log file (ADR-0020).
    resolve_with(
        config,
        base_dir,
        &Arc::new(eqproxy_net::ServerModes::new()),
        None,
    )
    .map(|(listeners, _)| listeners)
}

/// [`resolve`] with a shared administration-state registry (ADR-0018): the
/// same registry is handed to every balancer and to the admin plane, and the
/// resolved backends come back for the admin's live view.
fn resolve_with(
    config: &Config,
    base_dir: &Path,
    modes: &Arc<eqproxy_net::ServerModes>,
    access: Option<&Arc<eqproxy_net::AccessLog>>,
) -> Result<
    (
        Vec<ResolvedListener>,
        Vec<Arc<eqproxy_net::ResolvedBackend>>,
    ),
    String,
> {
    let maps = load_maps(config, base_dir)?;
    let mut backends: std::collections::BTreeMap<String, Arc<ResolvedBackend>> =
        std::collections::BTreeMap::new();
    for (name, backend) in &config.backend {
        let servers: Vec<ResolvedServer> = backend
            .server_entries()
            .into_iter()
            .map(|entry| {
                // Literal IPs serve immediately; hostnames start
                // unresolved and the background resolver (B-H13) fills
                // them in — nothing here blocks on DNS.
                let target = eqproxy_config::schema::parse_server_target(entry.addr)
                    .map_err(|why| format!("backend.{name} invalid server address: {why}"))?;
                let addr = match target {
                    eqproxy_config::schema::ServerTarget::Ip(ip) => eqproxy_net::ServerAddr::Ip(ip),
                    eqproxy_config::schema::ServerTarget::Name { host, port } => {
                        eqproxy_net::ServerAddr::Name { host, port }
                    }
                };
                Ok(ResolvedServer {
                    addr,
                    weight: entry.weight,
                    backup: entry.backup,
                    priority: entry.priority,
                })
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
                eqproxy_config::schema::ProxyProtocolMode::V2 => ProxyProtocolMode::V2,
            })
            // Balance avanzado (B-H5/B-N12/B-E6 + B14): algoritmo y
            // ventana de slow start (ponderación dinámica).
            .with_balance(balance_algorithm(backend.balance), backend.slow_start)
            // Backups en conjunto (`option allbackups`, B8): con true la
            // tier de backup completa balancea por peso.
            .with_all_backups(backend.all_backups)
            // DNS dinámico (B-H13/B-N18/B-E15): re-resolución periódica
            // de HOSTNAME:PORT fuera de la ruta caliente.
            .with_resolve_interval(backend.resolve_interval);
        if let Some(affinity) = &backend.affinity {
            resolved = resolved.with_affinity(eqproxy_net::ResolvedAffinity {
                mode: if affinity.mode == "source" {
                    eqproxy_net::AffinityMode::Source
                } else {
                    eqproxy_net::AffinityMode::Cookie
                },
                cookie: affinity
                    .cookie
                    .clone()
                    .unwrap_or_else(|| "eqproxy_affinity".to_owned()),
            });
        }
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
        resolved = resolved.with_server_modes(Arc::clone(modes));
        backends.insert(name.clone(), Arc::new(resolved));
    }

    let listeners = config
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
                backend.servers[0].addr.clone(),
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
            // Routing rules (B-H3/B-H4): compiled once here (the gate and
            // the runtime share the matcher grammar), order preserved.
            let mut routes = Vec::with_capacity(listener.rules.len());
            for (i, rule) in listener.rules.iter().enumerate() {
                let compiled =
                    eqproxy_core::rules::Rule::compile(&rule.to_spec(i)).map_err(|why| {
                        format!("listener.{name}.rules[{i}].{}: {}", why.field, why.cause)
                    })?;
                // The rewrite applies to the forwarded request on both
                // forwarding actions (`use_backend` and `split`).
                let rewrite = || {
                    rule.rewrite.as_ref().map(|rewrite| eqproxy_net::ResolvedRewrite {
                        matched_prefix: rule.path_prefix.clone().unwrap_or_default(),
                        path_prefix_rewrite: rewrite.path_prefix_rewrite.clone(),
                        host_rewrite: rewrite.host_rewrite.clone(),
                    })
                };
                let action = if let Some(backend_name) = &rule.use_backend {
                    let target = backends.get(backend_name).ok_or_else(|| {
                        format!(
                            "listener.{name}.rules[{i}].use_backend does not exist: \"{backend_name}\""
                        )
                    })?;
                    eqproxy_net::RouteAction::Backend {
                        backend: Arc::clone(target),
                        rewrite: rewrite(),
                    }
                } else if let Some(targets) = &rule.split {
                    // Weighted traffic split (B-I11): one SWRR state for
                    // the rule, one target per configured backend.
                    let resolved = targets
                        .iter()
                        .map(|target| {
                            let backend = backends.get(&target.backend).ok_or_else(|| {
                                format!(
                                    "listener.{name}.rules[{i}].split backend does not exist: \"{}\"",
                                    target.backend
                                )
                            })?;
                            Ok(eqproxy_net::SplitTarget {
                                backend: Arc::clone(backend),
                                weight: target.weight,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    eqproxy_net::RouteAction::Split {
                        targets: Arc::new(eqproxy_net::SplitTargets::new(resolved)),
                        rewrite: rewrite(),
                        hash: rule
                            .hash_policy
                            .as_ref()
                            .map(|policy| {
                                eqproxy_net::HashPolicy::parse(&policy.key).map_err(|why| {
                                    format!(
                                        "listener.{name}.rules[{i}].hash_policy.key: {why}"
                                    )
                                })
                            })
                            .transpose()?,
                    }
                } else if let Some(redirect) = &rule.redirect {
                    eqproxy_net::RouteAction::Redirect {
                        status: redirect.status.unwrap_or(301),
                        location: redirect.location.clone(),
                    }
                } else if let Some(direct) = &rule.direct_response {
                    eqproxy_net::RouteAction::Direct {
                        status: direct.status,
                        content_type: direct
                            .content_type
                            .clone()
                            .unwrap_or_else(|| "text/plain".to_owned()),
                        body: direct.body.clone().unwrap_or_default(),
                    }
                } else {
                    return Err(format!(
                        "listener.{name}.rules[{i}]: set exactly one of use_backend, split, redirect or direct_response"
                    ));
                };
                let headers = eqproxy_net::ResolvedHeaders {
                    set: rule
                        .set_headers
                        .iter()
                        .map(|op| (op.name.clone(), op.value.clone()))
                        .collect(),
                    add: rule
                        .add_headers
                        .iter()
                        .map(|op| (op.name.clone(), op.value.clone()))
                        .collect(),
                    del: rule.del_headers.clone(),
                    response: rule
                        .response_headers
                        .iter()
                        .map(|op| (op.name.clone(), op.value.clone()))
                        .collect(),
                    mirror: rule
                        .request_mirror
                        .as_ref()
                        .map(|mirror| {
                            let target = backends.get(&mirror.backend).ok_or_else(|| {
                                format!(
                                    "listener.{name}.rules[{i}].request_mirror.backend does not exist: \"{}\"",
                                    mirror.backend
                                )
                            })?;
                            Ok::<_, String>(std::sync::Arc::new(eqproxy_net::MirrorPolicy::new(
                                Arc::clone(target),
                                mirror.percentage,
                            )))
                        })
                        .transpose()?,
                    rate_limit: rule.rate_limit.as_ref().map(|limit| {
                        std::sync::Arc::new(eqproxy_net::RateLimiter::new(
                            limit.rate,
                            limit.per,
                            limit.burst.unwrap_or(limit.rate),
                        ))
                    }),
                    cors: rule.cors.as_ref().map(|cors| eqproxy_net::ResolvedCors {
                        allow_origin: cors.allow_origin.clone(),
                        allow_methods: cors
                            .allow_methods
                            .clone()
                            .unwrap_or_else(|| "GET, HEAD, POST, OPTIONS".to_owned()),
                        allow_headers: cors.allow_headers.clone(),
                        expose_headers: cors.expose_headers.clone(),
                        max_age: cors.max_age,
                        allow_credentials: cors.allow_credentials,
                    }),
                    auth: rule
                        .auth
                        .as_ref()
                        .map(|auth| -> Result<eqproxy_net::ResolvedAuth, String> {
                            let basic = if auth.kind.is_some() {
                                Some(std::sync::Arc::new(
                                    eqproxy_core::auth::BasicUsers::parse(&auth.users).map_err(
                                        |why| {
                                            format!("listener.{name}.rules[{i}].auth.users: {why}")
                                        },
                                    )?,
                                ))
                            } else {
                                None
                            };
                            Ok(eqproxy_net::ResolvedAuth {
                                url: auth
                                    .url
                                    .as_deref()
                                    .map(eqproxy_core::auth::parse_auth_url)
                                    .transpose()
                                    .map_err(|why| {
                                        format!("listener.{name}.rules[{i}].auth.url: {why}")
                                    })?,
                                basic,
                                realm: auth.realm.clone().unwrap_or_else(|| "EQProxy".to_owned()),
                            })
                        })
                        .transpose()?,
                };
                let headers = (!headers.set.is_empty()
                    || !headers.add.is_empty()
                    || !headers.del.is_empty()
                    || !headers.response.is_empty()
                    || headers.cors.is_some()
                    || headers.rate_limit.is_some()
                    || headers.auth.is_some()
                    || headers.mirror.is_some())
                .then_some(headers);
                routes.push(eqproxy_net::ResolvedRoute {
                    rule: compiled,
                    action,
                    headers,
                });
            }
            resolved = resolved.with_routes(routes).with_maps(Arc::clone(&maps));
            // PROXY v1 reception (B-H9/B-E10): strict front door with
            // allowlisted origins only.
            if listener.proxy_receive {
                let allowlist =
                    eqproxy_core::expectation::IpAllowlist::parse(&listener.proxy_allow)
                        .map_err(|why| format!("listener.{name}.proxy_allow: {why}"))?;
                resolved = resolved.with_proxy_receive(allowlist);
            }
            resolved = resolved.with_max_stream_duration(listener.max_stream_duration);
            // Message limits and per-stream buffers (B-N19/B-I17/B-E19): the
            // runtime receives exactly the values the gate bounded.
            resolved = resolved.with_limits(eqproxy_net::ResolvedLimits {
                max_head_bytes: listener.limits.max_head_bytes,
                max_headers: listener.limits.max_headers,
                max_body_bytes: listener.limits.max_body_bytes,
                stream_buffer_bytes: listener.limits.stream_buffer_bytes,
            });
            // WASM request filter (B-I5/B-E4, ADR-0031): compiled here, so a
            // bad module rejects the snapshot (check/apply) instead of
            // failing per request. Relative paths resolve from the config
            // file's directory, like certificates and maps.
            if let Some(plugin) = &listener.plugin {
                let host = eqproxy_net::PluginHost::load(
                    eqproxy_net::PluginSettings {
                        path: PathBuf::from(&plugin.path),
                        fuel: plugin.fuel,
                        timeout: plugin.timeout,
                        memory_bytes: plugin.memory_bytes,
                        max_header_ops: plugin.max_header_ops,
                        on_error: match plugin.on_error {
                            eqproxy_config::schema::PluginFailurePolicy::Closed => {
                                eqproxy_net::FailurePolicy::Closed
                            }
                            eqproxy_config::schema::PluginFailurePolicy::Open => {
                                eqproxy_net::FailurePolicy::Open
                            }
                        },
                    },
                    base_dir,
                )
                .map_err(|why| format!("listener.{name}.plugin: {why}"))?;
                resolved = resolved.with_plugin(std::sync::Arc::new(host));
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
            // Response compression (B-N6/H6): validated here so the runtime
            // receives exactly the grammar the gate accepted.
            if listener.compression.gzip || listener.compression.brotli {
                let settings = eqproxy_net::compression::ResolvedCompression::new(
                    listener.compression.gzip,
                    listener.compression.brotli,
                    listener.compression.level,
                    listener.compression.brotli_quality,
                    listener.compression.min_size,
                    &listener.compression.types,
                )
                .map_err(|why| format!("listener.{name}.compression: {why}"))?;
                resolved = resolved.with_compression(settings);
            }
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
                // SNI certificates (B-I2/B-H10/B-E9): each entry carries its
                // own chain and key; the pair above stays the default.
                let mut sni = Vec::with_capacity(server_tls.certs.len());
                for (index, entry) in server_tls.certs.iter().enumerate() {
                    let cert_pem = read_pem(
                        base_dir,
                        &format!("listener.{name}.tls.certs[{index}].cert"),
                        &entry.cert,
                    )?;
                    let key_pem = read_pem(
                        base_dir,
                        &format!("listener.{name}.tls.certs[{index}].key"),
                        &entry.key,
                    )?;
                    sni.push(tls::SniCertPem {
                        names: entry.names.clone(),
                        cert_chain_pem: cert_pem,
                        key_pem,
                    });
                }
                let acceptor = tls::server_config_with_sni(
                    &cert,
                    &key,
                    &sni,
                    client_ca.as_deref(),
                    &server_tls.alpn,
                    tls_version(server_tls.min_version),
                )
                .map_err(|e| format!("listener.{name}.tls: {e}"))?;
                resolved = resolved.with_server_tls(acceptor);
            }
            // HTTP/3 (B-H2): the UDP endpoint is opened by the dataplane on
            // the same address; validation already required TLS and http.
            resolved = resolved.with_quic(listener.quic);
            // One process-wide sink, attached to every listener (ADR-0020).
            if let Some(log) = access {
                resolved = resolved.with_access(Arc::clone(log));
            }
            Ok(resolved)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((listeners, backends.into_values().collect()))
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

    // CE4: the detail registry exists from startup; whether it records, and
    // the budget it can never exceed, come from the configuration.
    let metrics = Arc::new(Metrics::with_detail(
        config.metrics.detailed,
        config.metrics.max_series,
    ));
    // Access log (ADR-0020): opened once, before any listener serves. A
    // configured sink the process cannot open is a startup error, never a
    // silent downgrade.
    let access_handle = match access_settings(&config, base_dir(&path)) {
        Some(access_cfg) => {
            match eqproxy_net::AccessLog::start(&access_cfg, Arc::clone(&metrics)).await {
                Ok(handle) => Some(handle),
                Err(err) => {
                    eprintln!("error: access log cannot be opened: {err}");
                    return 1;
                }
            }
        }
        None => None,
    };
    let access = access_handle.as_ref().map(|handle| Arc::clone(&handle.log));
    // One registry for the whole process: the admin plane writes to it and
    // every balancer (startup and each SIGHUP reload) reads it (ADR-0018).
    let modes = Arc::new(eqproxy_net::ServerModes::new());
    let (listeners, live_backends) =
        match resolve_with(&config, base_dir(&path), &modes, access.as_ref()) {
            Ok(resolved) => resolved,
            Err(msg) => {
                eprintln!("error: inconsistent configuration after validation: {msg}");
                return 1;
            }
        };
    if listeners.is_empty() {
        eprintln!("error: the configuration defines no listeners; nothing to serve");
        return 1;
    }
    let admin_cfg = match resolve_admin(&config, base_dir(&path)) {
        Ok(admin) => admin,
        Err(msg) => {
            eprintln!("error: {msg}");
            return 1;
        }
    };

    // The shutdown and reload signals are armed before any listener is bound
    // or announced. `tokio::signal::unix::signal` installs the OS handler when
    // it is called, so a SIGINT or SIGHUP arriving the instant the first
    // socket is ready finds the handler instead of the default action, which
    // terminates the process without a clean shutdown or a reload.
    let (handle, signal) = shutdown::channel();
    // One queue for every configuration mutation (ADR-0019): the admin API
    // and SIGHUP both land here, so the revision check and the swap it
    // authorizes are serialized in a single consumer.
    let (apply_tx, apply_rx) = tokio::sync::mpsc::channel::<ApplyMessage>(8);

    #[cfg(unix)]
    {
        let mut interrupt =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(interrupt) => interrupt,
                Err(err) => {
                    eprintln!("ERROR SIGINT handler unavailable: {err}");
                    return 1;
                }
            };
        let signal_handle = handle.clone();
        tokio::spawn(async move {
            if interrupt.recv().await.is_some() {
                eprintln!("INFO shutdown signal received; draining connections");
                signal_handle.trigger();
            }
        });

        // SIGHUP → hot config reload (S-CFG-01, unix). The signal does not
        // touch the dataplane directly: it asks the same single configuration
        // task that serves the API, which re-reads the file, validates it and
        // swaps (or rejects) as one serialized generation. A reload that
        // arrives before the applier starts waits in the bounded queue.
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(hup) => hup,
            Err(err) => {
                eprintln!("ERROR SIGHUP handler unavailable: {err}");
                return 1;
            }
        };
        let hup_apply = apply_tx.clone();
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                let (reply, answer) = tokio::sync::oneshot::channel();
                if hup_apply
                    .send(ApplyMessage {
                        change: ConfigChange::Reload,
                        if_match: None,
                        reply,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                // The task logs validation rejections; the swap outcome is
                // logged by the dataplane when it commits or refuses.
                let _ = answer.await;
            }
        });
    }
    #[cfg(not(unix))]
    {
        let signal_handle = handle.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("INFO shutdown signal received; draining connections");
                signal_handle.trigger();
            }
        });
    }

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
    // What the acceptors are serving now: the baseline a renewal reports
    // against (D7), read from the dataplane and never from the config files.
    let certificates: BTreeMap<String, String> = bound
        .certificates()
        .into_iter()
        .map(|fact| (fact.listener, fact.fingerprint))
        .collect();
    let topology = Arc::new(RwLock::new(admin_topology(
        &config,
        &bound.local_addrs(),
        live_backends,
        "v1".to_owned(),
        &certificates,
    )));
    // Bind the admin plane only after the dataplane is open, and fail the
    // process when it cannot open: a configured plane that silently downgrades
    // is worse than not starting. Dropping `bound` on this path closes the
    // dataplane sockets, so startup stays all-or-nothing.
    let admin = match admin_cfg {
        Some(cfg) => {
            let writable = cfg.write_token.is_some();
            let panel_on = cfg.panel;
            let panel = panel_on.then(|| Arc::new(eqproxy_net::Panel::new()));
            let state = Arc::new(AdminState {
                version: env!("CARGO_PKG_VERSION"),
                started: std::time::Instant::now(),
                topology: Arc::clone(&topology),
                modes: Arc::clone(&modes),
                metrics: Arc::clone(&metrics),
                // Without a write token the plane stays read-only; the sender
                // exists so a later-generated token cannot be implied.
                apply: writable.then(|| apply_tx.clone()),
                panel,
            });
            match eqproxy_net::admin::bind(cfg, state).await {
                Ok(handle) => {
                    eprintln!(
                        "INFO admin listening on {} (routes: /api/v1/status, /metrics{}{})",
                        handle.endpoint(),
                        if writable {
                            ", PUT /api/v1/backends/{name}, PUT /api/v1/listeners/{name}, \
                             PUT /api/v1/backends/{backend}/servers/{target}/state, \
                             POST /api/v1/certificates/reload"
                        } else {
                            " (read-only)"
                        },
                        if panel_on { ", panel /panel" } else { "" }
                    );
                    Some(handle)
                }
                Err(err) => {
                    eprintln!("error: admin plane cannot bind: {err}");
                    return 1;
                }
            }
        }
        None => None,
    };
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);
    let grace = config.shutdown_grace;
    let applier = tokio::spawn(
        ConfigApplier {
            path: path.clone(),
            config,
            revision: 1,
            modes: Arc::clone(&modes),
            topology: Arc::clone(&topology),
            reloads: reload_tx,
            metrics: Arc::clone(&metrics),
            access: access.clone(),
            admin_unix: admin
                .as_ref()
                .and_then(|handle| handle.unix_policy().cloned()),
            certificates,
        }
        .run(apply_rx, signal.clone()),
    );

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

    #[cfg(not(unix))]
    let _ = apply_tx;

    let serve_result = bound.serve_with_reloads(signal, grace, reload_rx).await;
    let _ = applier.await;
    // The dataplane and the applier hold the last clones: drop ours, then
    // flush what the writer still has (ADR-0020).
    drop(access);
    if let Some(handle) = access_handle {
        handle.shutdown().await;
    }
    if let Some(admin) = admin {
        admin.shutdown().await;
    }
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
                        backup: false,
                        priority: 0,
                    },
                    eqproxy_config::schema::ServerConfig {
                        addr: "127.0.0.1:9001".to_owned(),
                        weight: 1,
                        backup: false,
                        priority: 0,
                    },
                ]),
                ..eqproxy_config::schema::BackendConfig::default()
            },
        );
        let config = Config {
            schema_version: 1,
            listener: BTreeMap::new(),
            backend,
            maps: BTreeMap::new(),
            shutdown_grace: Duration::from_secs(10),
            metrics: eqproxy_config::schema::MetricsConfig::default(),
            admin: None,
            access_log: None,
        };
        let backend = Arc::new(ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: eqproxy_net::ServerAddr::Ip("127.0.0.1:9000".parse().expect("addr")),
                    weight: 3,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: eqproxy_net::ServerAddr::Ip("127.0.0.1:9001".parse().expect("addr")),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
            ],
            3,
            2,
        ));
        let listener = ResolvedListener::new(
            "web",
            "127.0.0.1:8080".parse().expect("addr"),
            "api",
            "127.0.0.1:9000".parse::<SocketAddr>().expect("addr"),
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

    const CLIENT_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

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
    fn diff_report_names_a_server_turning_backup() {
        let left = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\" }]\n",
        );
        let right = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", backup = true }]\n",
        );
        let report = diff_report(&left, &right);
        assert!(
            report.contains(
                "~ backend \"api\" servers: [127.0.0.1:9000(1)] -> [127.0.0.1:9000(1,backup)]"
            ),
            "missing the backup transition in:\n{report}"
        );
    }

    #[test]
    fn diff_report_names_a_priority_change() {
        let left = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", backup = true }]\n",
        );
        let right = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", backup = true, priority = 10 }]\n",
        );
        let report = diff_report(&left, &right);
        assert!(
            report.contains(
                "~ backend \"api\" servers: [127.0.0.1:9000(1,backup)] -> [127.0.0.1:9000(1,backup,10)]"
            ),
            "missing the priority transition in:\n{report}"
        );
    }

    #[test]
    fn diff_report_names_an_all_backups_change() {
        let left = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", backup = true }, { addr = \"127.0.0.1:9001\", backup = true }]\n",
        );
        let right = parse_config(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n[backend.api]\nall_backups = true\nservers = [{ addr = \"127.0.0.1:9000\", backup = true }, { addr = \"127.0.0.1:9001\", backup = true }]\n",
        );
        let report = diff_report(&left, &right);
        assert!(
            report.contains("~ backend \"api\" all_backups: false -> true"),
            "missing the all_backups transition in:\n{report}"
        );
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
        let report = explain_report(
            &config,
            &listener,
            "GET",
            "example.com",
            "/a",
            &[],
            CLIENT_IP,
        );
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
    fn explain_report_shows_leastconn_and_slow_start() {
        let (mut config, listener) = two_server_listener();
        let backend = config.backend.get_mut("api").expect("backend api");
        backend.balance = eqproxy_config::schema::BalanceAlgorithm::LeastConn;
        backend.slow_start = Duration::from_secs(30);
        let report = explain_report(
            &config,
            &listener,
            "GET",
            "example.com",
            "/a",
            &[],
            CLIENT_IP,
        );
        for expected in [
            "backend \"api\": balance=leastconn servers=2",
            "slow_start=30s",
            "decision: server 127.0.0.1:9000",
            "least-connections pick",
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
        let report = explain_report(
            &config,
            &listener,
            "GET",
            "example.com",
            "/a",
            &[],
            CLIENT_IP,
        );
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
