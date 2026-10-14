//! EQProxy CLI.
//!
//! Commands implemented in Phase 1: `run` and `config validate`. The rest
//! **fail explicitly** with exit code 2 (never fake success).

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
    /// Shows the effective configuration (Phase 3)
    Explain {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Compares two configurations (Phase 3)
    Diff { left: PathBuf, right: PathBuf },
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
        ConfigCommand::Explain { .. } => not_implemented("config explain", "Phase 3"),
        ConfigCommand::Diff { .. } => not_implemented("config diff", "Phase 3"),
        ConfigCommand::Plan { .. } => not_implemented("config plan", "Phase 3"),
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
