//! EQProxy CLI.
//!
//! Implemented: `run`, `config validate`, `config explain` and `config diff`.
//! The rest **fail explicitly** with exit code 2 (never fake success).

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

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
    /// Environment diagnostics (Phase 3)
    Doctor,
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
    /// Applies a configuration hot (Phase 3)
    Apply {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Rolls back to the previously applied configuration (Phase 3)
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
        Command::Doctor => not_implemented("eqproxy doctor", "Phase 3"),
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
        ConfigCommand::Apply { .. } => not_implemented("config apply", "Phase 3"),
        ConfigCommand::Rollback => not_implemented("config rollback", "Phase 3"),
        ConfigCommand::Import { .. } => not_implemented("config import", "Phase 8"),
    }
}

/// Explicit failure for unimplemented functionality: never fakes success.
fn not_implemented(feature: &str, phase: &str) -> u8 {
    eprintln!("error: \"{feature}\" is not implemented yet (planned for {phase}; see ROADMAP.md)");
    2
}

/// Reads, parses and validates. The parse error already carries line, field and example.
fn load_and_check(path: &Path) -> Result<(Config, CheckResult), ConfigError> {
    let source = std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("could not read the file: {e}"),
        example: "create an eqproxy.toml (see eqproxy.toml.example) and pass --config <path>"
            .to_owned(),
    })?;
    let config = eqproxy_config::parse_str(&source, path)?;
    let result = validate::check(&config, &source, path);
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
            resolved = resolved.with_health_check(HealthCheck {
                interval: hc.interval,
                timeout: hc.timeout,
            });
        }
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
                let acceptor = tls::server_config(
                    &cert,
                    &key,
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

    let serve_result = bound.serve(signal, config.shutdown_grace).await;
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
}
