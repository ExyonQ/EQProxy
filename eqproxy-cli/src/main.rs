//! CLI de EQProxy.
//!
//! Comandos implementados en Fase 1: `run` y `config validate`. El resto
//! **falla explícitamente** con el código de salida 2 (nunca simulan éxito).

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
use eqproxy_net::{ProxyMode, ResolvedListener, bind};

#[derive(Parser)]
#[command(
    name = "eqproxy",
    version,
    about = "ExyonQ Proxy (EQProxy): proxy inverso y balanceador de carga"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ejecuta el dataplane con la configuración dada
    Run {
        /// Archivo de configuración TOML
        #[arg(short, long)]
        config: PathBuf,
        /// Intervalo del reporte de métricas (sufijos: ms, s, m, h)
        #[arg(long, default_value = "30s")]
        metrics_interval: String,
    },
    /// Comandos de configuración
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Diagnóstico del entorno (Fase 3)
    Doctor,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Valida la configuración: errores con archivo, línea, campo, causa y ejemplo
    Validate {
        /// Archivo de configuración TOML
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Muestra la configuración efectiva (Fase 3)
    Explain {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Compara dos configuraciones (Fase 3)
    Diff { left: PathBuf, right: PathBuf },
    /// Muestra el plan de cambios sin aplicarlos (Fase 3)
    Plan {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Aplica una configuración en caliente (Fase 3)
    Apply {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Revierte a la configuración aplicada anterior (Fase 3)
    Rollback,
    /// Conversor de configuración de otros proxies a EQProxy
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },
}

#[derive(Subcommand)]
enum ImportSource {
    /// Convierte config-de-referencia a eqproxy.toml (Fase 8: conversor ref → EQProxy)
    ref {
        /// Archivo de origen (config-de-referencia)
        #[arg(long)]
        input: PathBuf,
        /// Archivo de destino (eqproxy.toml)
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
        Command::Doctor => not_implemented("eqproxy doctor", "Fase 3"),
    };
    ExitCode::from(code)
}

fn config_command(command: ConfigCommand) -> u8 {
    match command {
        ConfigCommand::Validate { config } => validate(&config),
        ConfigCommand::Explain { .. } => not_implemented("config explain", "Fase 3"),
        ConfigCommand::Diff { .. } => not_implemented("config diff", "Fase 3"),
        ConfigCommand::Plan { .. } => not_implemented("config plan", "Fase 3"),
        ConfigCommand::Apply { .. } => not_implemented("config apply", "Fase 3"),
        ConfigCommand::Rollback => not_implemented("config rollback", "Fase 3"),
        ConfigCommand::Import { source } => match source {
            ImportSource::ref { .. } => not_implemented("config import ref", "Fase 8"),
        },
    }
}

/// Falla explícita para funcionalidad no implementada: nunca simula éxito.
fn not_implemented(feature: &str, phase: &str) -> u8 {
    eprintln!(
        "error: «{feature}» no está implementado todavía (planificada para {phase}; ver ROADMAP.md)"
    );
    2
}

/// Lee, parsea y valida. El error de parseo ya trae línea, campo y ejemplo.
fn load_and_check(path: &Path) -> Result<(Config, CheckResult), ConfigError> {
    let source = std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("no se pudo leer el archivo: {e}"),
        example: "crea un eqproxy.toml (ver eqproxy.toml.example) y pasa --config <ruta>"
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
        eprintln!("aviso: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        eprintln!(
            "config inválida: {} error(es) en {}",
            result.errors.len(),
            path.display()
        );
        return 1;
    }
    println!(
        "config OK: {} listener(es), {} backend(s) en {}",
        config.listener.len(),
        config.backend.len(),
        path.display()
    );
    0
}

fn resolve(config: &Config) -> Result<Vec<ResolvedListener>, String> {
    config
        .listener
        .iter()
        .map(|(name, listener)| {
            let listen: SocketAddr = listener
                .listen
                .parse()
                .map_err(|_| format!("listener.{name}.listen inválido: «{}»", listener.listen))?;
            let backend = config.backend.get(&listener.backend).ok_or_else(|| {
                format!(
                    "listener.{name}.backend inexistente: «{}»",
                    listener.backend
                )
            })?;
            let server: SocketAddr = backend.server.parse().map_err(|_| {
                format!(
                    "backend.{}.server inválido: «{}»",
                    listener.backend, backend.server
                )
            })?;
            Ok(ResolvedListener::new(
                name.clone(),
                listen,
                listener.backend.clone(),
                server,
                match listener.mode {
                    eqproxy_config::ListenerMode::Tcp => ProxyMode::Tcp,
                    eqproxy_config::ListenerMode::Http => ProxyMode::Http,
                },
                listener.maxconn,
                listener.connect_timeout,
                listener.idle_timeout,
                listener.client_header_timeout,
                listener.server_header_timeout,
            ))
        })
        .collect()
}

async fn run(path: PathBuf, metrics_interval: String) -> u8 {
    let interval = match eqproxy_config::duration::parse(&metrics_interval) {
        Ok(value) if !value.is_zero() => value,
        _ => {
            eprintln!(
                "error: --metrics-interval «{metrics_interval}» no es una duración válida; ejemplo: 30s"
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
        eprintln!("aviso: {warning}");
    }
    if !result.is_valid() {
        for err in &result.errors {
            eprintln!("{err}");
        }
        return 1;
    }

    let listeners = match resolve(&config) {
        Ok(listeners) => listeners,
        Err(msg) => {
            eprintln!("error: configuración inconsistente tras validar: {msg}");
            return 1;
        }
    };
    if listeners.is_empty() {
        eprintln!("error: la configuración no define listeners; nada que servir");
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
        eprintln!("INFO listener {name} escuchando en {addr}");
    }

    let (handle, signal) = shutdown::channel();

    // Reportero de métricas: sale con la señal de apagado.
    let reporter_metrics = Arc::clone(&metrics);
    let mut reporter_signal = signal.clone();
    let reporter = tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = tick.tick() => eprintln!("METRICAS {}", reporter_metrics.snapshot()),
                _ = reporter_signal.wait() => break,
            }
        }
    });

    // Ctrl-C / SIGINT → apagado gradual.
    let signal_handle = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("INFO señal de apagado recibida; drenando conexiones");
            signal_handle.trigger();
        }
    });

    let serve_result = bound.serve(signal, config.shutdown_grace).await;
    let _ = reporter.await;
    eprintln!("METRICAS {} (final)", metrics.snapshot());
    match serve_result {
        Ok(()) => {
            eprintln!("apagado completado");
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}
