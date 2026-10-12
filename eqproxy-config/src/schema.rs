//! Esquema versionado de la configuración canónica (TOML).
//!
//! Tipos estrictos + `deny_unknown_fields`: un campo desconocido es error, no
//! se ignora en silencio (regla del conversor aplicada a nuestro propio
//! formato).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

use crate::duration;

/// Versión de esquema soportada por este binario.
pub const SCHEMA_VERSION: u32 = 1;

fn default_maxconn() -> u32 {
    1024
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_shutdown_grace() -> Duration {
    Duration::from_secs(10)
}

fn default_client_header_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_server_header_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Modo de proxy de un listener (A1 `tcp`, A2 `http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    /// Túnel TCP sin interpretación (Fase 1).
    #[default]
    Tcp,
    /// Proxy HTTP/1.1 con framing estricto (Fase 2a).
    Http,
}

/// Configuración completa de EQProxy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Versión del esquema; debe ser [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Frontends TCP/HTTP definidos por nombre.
    #[serde(default)]
    pub listener: BTreeMap<String, ListenerConfig>,
    /// Backends definidos por nombre.
    #[serde(default)]
    pub backend: BTreeMap<String, BackendConfig>,
    /// Ventana de drenaje al apagar: conexiones vivas pueden terminar.
    #[serde(default = "default_shutdown_grace", with = "duration")]
    pub shutdown_grace: Duration,
}

/// Un frontend: dónde escuchar y a qué backend enviar.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Dirección `IP:PUERTO` de escucha (puerto 0 = efímero, útil en tests).
    pub listen: String,
    /// Modo: `"tcp"` (túnel, por defecto) u `"http"` (HTTP/1.1 estricto).
    #[serde(default)]
    pub mode: ListenerMode,
    /// Nombre del backend ([`BackendConfig`] en `Config::backend`).
    pub backend: String,
    /// Conexiones simultáneas máximas; al llenarse se rechaza explícitamente.
    #[serde(default = "default_maxconn")]
    pub maxconn: u32,
    /// Timeout de conexión al backend.
    #[serde(default = "default_connect_timeout", with = "duration")]
    pub connect_timeout: Duration,
    /// Timeout de inactividad por dirección (sin bytes en ninguno de los sentidos).
    #[serde(default = "default_idle_timeout", with = "duration")]
    pub idle_timeout: Duration,
    /// Fase cliente: máximo para recibir la cabecera de petición (solo `http`).
    #[serde(default = "default_client_header_timeout", with = "duration")]
    pub client_header_timeout: Duration,
    /// Fase servidor: máximo para recibir la cabecera de respuesta (solo `http`).
    #[serde(default = "default_server_header_timeout", with = "duration")]
    pub server_header_timeout: Duration,
}

/// Un backend: servidor de origen (Fase 1: un único servidor; balanceo en Fase 2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Dirección `IP:PUERTO` del servidor de origen.
    pub server: String,
}
