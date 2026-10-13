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

/// Presupuesto de recursos (ADR-0002): tamaño máximo del archivo de
/// configuración. Un config mayor es rechazado antes de parsear.
pub const MAX_CONFIG_BYTES: usize = 1_048_576;

/// Presupuesto de recursos (ADR-0002): máximo de secciones
/// `[listener.*]` + `[backend.*]` combinadas.
pub const MAX_SECTIONS: usize = 1024;

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

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_health_interval() -> Duration {
    Duration::from_secs(2)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_fall() -> u32 {
    3
}

fn default_rise() -> u32 {
    2
}

/// Peso máximo por servidor (rango HAProxy `weight`, cfg 3.4 «server»).
pub const MAX_SERVER_WEIGHT: u32 = 256;

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

/// Algoritmo de balanceo (Fase 2b: solo `roundrobin`; B2–B5 en fases siguientes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BalanceAlgorithm {
    /// Round-robin ponderado suave (B1 + B7).
    #[default]
    RoundRobin,
}

/// Envío de PROXY protocol hacia el backend (A9; recepción en Fase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// Sin cabecera PROXY (por defecto).
    #[default]
    None,
    /// Cabecera PROXY protocol v1 (`PROXY TCP4/TCP6 …`).
    V1,
}

/// Versión mínima de TLS aceptada (A11/A12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2 (por defecto; TLS 1.0/1.1 nunca se aceptan).
    #[default]
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    V1_3,
}

/// TLS termination en el listener (A11): certificado, clave y ALPN.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsServerConfig {
    /// Ruta a la cadena de certificados PEM (hoja primero).
    pub cert: String,
    /// Ruta a la clave privada PEM (PKCS#8, PKCS#1 o SEC1).
    pub key: String,
    /// Protocolos ALPN ofrecidos (p. ej. `["http/1.1"]`); vacío = sin ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Versión mínima de TLS (por defecto 1.2).
    #[serde(default)]
    pub min_version: TlsVersion,
}

/// TLS hacia el backend (A12): verificación activada por defecto.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientConfig {
    /// Verificación de certificado y nombre del servidor (por defecto `true`).
    #[serde(default = "default_true")]
    pub verify: bool,
    /// PEM de CA adicionales para verificar el backend (CAs privadas, tests).
    pub ca_file: Option<String>,
    /// Nombre a verificar/SNI; por defecto la parte de host de la dirección.
    pub server_name: Option<String>,
    /// Protocolos ALPN a ofrecer en el handshake; vacío = sin ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Versión mínima de TLS (por defecto 1.2).
    #[serde(default)]
    pub min_version: TlsVersion,
}

/// Un servidor del backend con su peso (B7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Dirección `IP:PUERTO` del servidor.
    pub addr: String,
    /// Peso en el balanceo (0 = drenado: nunca seleccionado, sí health-checked).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Health check TCP activo (B11 TCP): `fall` fallos seguidos caen al servidor,
/// `rise` éxitos seguidos lo levantan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Intervalo entre ciclos de comprobación.
    #[serde(default = "default_health_interval", with = "duration")]
    pub interval: Duration,
    /// Timeout de cada intento de conexión TCP.
    #[serde(default = "default_health_timeout", with = "duration")]
    pub timeout: Duration,
    /// Fallos consecutivos para marcar un servidor caído.
    #[serde(default = "default_fall")]
    pub fall: u32,
    /// Éxitos consecutivos para marcar un servidor operativo.
    #[serde(default = "default_rise")]
    pub rise: u32,
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
    /// TLS termination en este listener (A11). Ausente = TCP plano.
    #[serde(default)]
    pub tls: Option<TlsServerConfig>,
}

/// Un backend: uno o varios servidores de origen con balanceo (Fase 2b).
///
/// `server` (un servidor, compat 0.1) y `servers` (lista con pesos) son
/// excluyentes: exactamente uno debe estar presente (validado en [`crate::check`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Dirección `IP:PUERTO` del servidor de origen (compat 0.1.0).
    pub server: Option<String>,
    /// Servidores con peso (B1/B7). Excluyente con `server`.
    pub servers: Option<Vec<ServerConfig>>,
    /// Algoritmo de balanceo (Fase 2b: `"roundrobin"`).
    #[serde(default)]
    pub balance: BalanceAlgorithm,
    /// Envío de PROXY protocol v1 hacia los servidores (A9).
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolMode,
    /// Health check TCP activo (B11). Ausente = todos los servidores operativos.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// TLS hacia los servidores (A12). Ausente = TCP plano.
    #[serde(default)]
    pub tls: Option<TlsClientConfig>,
}

impl BackendConfig {
    /// Pares (dirección, peso) declarados, sea por `server` o por `servers`.
    #[must_use]
    pub fn server_entries(&self) -> Vec<(&str, u32)> {
        match (&self.server, &self.servers) {
            (Some(addr), _) => vec![(addr.as_str(), 1)],
            (None, Some(servers)) => servers
                .iter()
                .map(|s| (s.addr.as_str(), s.weight))
                .collect(),
            (None, None) => Vec::new(),
        }
    }
}
