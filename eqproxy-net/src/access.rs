//! Structured access log (v0.8, ADR-0020).
//!
//! One line per HTTP request, produced by the engine that answered it
//! (`http1::serve_http`, which HTTP/2 and HTTP/3 feed). The dataplane never
//! writes: entries go into a **bounded** channel and a dedicated task owns the
//! destination. A full channel drops the entry and advances
//! `access_log_dropped`, so a slow sink costs lines, never request latency.
//!
//! Formats: `json` (one object per line) and `combined` (nginx shape). Both
//! are single-line by construction: control characters are escaped and the
//! query string is never logged (ADR-0020, T17).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eqproxy_core::Metrics;
use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{Notify, mpsc};

/// Entries buffered between the dataplane and the writer task. Bounded on
/// purpose: overload drops lines (counted) instead of growing memory.
pub const CHANNEL_CAPACITY: usize = 4096;

/// How long shutdown waits for the writer to flush what it already has.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Line format of the access log (mirrors the configuration enum; the
/// dataplane crate does not depend on `eqproxy-config`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogFormat {
    /// One JSON object per request.
    #[default]
    Json,
    /// nginx combined shape, UTC timestamps.
    Combined,
}

/// Runtime settings, translated from `[access_log]` by the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessLogSettings {
    /// Destination file in append mode; absent = stdout.
    pub path: Option<PathBuf>,
    pub format: AccessLogFormat,
}

/// HTTP version a request arrived on. `serve_http` is shared by all three, so
/// the caller states which translation produced the h1 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocol {
    /// HTTP/1.1 over TCP or TLS.
    Http1,
    /// HTTP/2 (TLS ALPN `h2` or h2c prior knowledge).
    Http2,
    /// HTTP/3 over QUIC.
    Http3,
}

impl ClientProtocol {
    /// Wire name used in the `protocol` field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "http/2",
            Self::Http3 => "http/3",
        }
    }

    /// Protocol token as it appears in a request line (`HTTP/1.1`), used by
    /// the combined format.
    #[must_use]
    pub fn as_request_line(self) -> &'static str {
        match self {
            Self::Http1 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }
}

/// One completed (or aborted) request, owned by the writer task.
#[derive(Debug, Clone)]
pub struct AccessEntry {
    /// Unix epoch milliseconds; formatted per line format.
    pub time_unix_ms: u64,
    pub listener: String,
    pub client: SocketAddr,
    pub protocol: ClientProtocol,
    pub method: String,
    pub path: String,
    pub host: String,
    /// Final status, or `0` when the exchange ended without a response.
    pub status: u16,
    pub duration_ms: u64,
    pub backend: Option<String>,
    pub server: Option<SocketAddr>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    /// Response body bytes when exactly known; `None` otherwise.
    pub bytes: Option<u64>,
}

#[derive(Serialize)]
struct JsonLine<'a> {
    time: String,
    listener: &'a str,
    client: String,
    protocol: &'static str,
    method: &'a str,
    path: &'a str,
    host: &'a str,
    status: u16,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    referer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
}

/// Shared handle the dataplane clones into every listener.
#[derive(Debug)]
pub struct AccessLog {
    tx: mpsc::Sender<AccessEntry>,
    dropped: AtomicU64,
    metrics: Arc<Metrics>,
    close: Notify,
}

/// The sink plus its writer task. The CLI holds this for the process
/// lifetime and calls [`AccessHandle::shutdown`] after the dataplane drains.
pub struct AccessHandle {
    pub log: Arc<AccessLog>,
    writer: tokio::task::JoinHandle<()>,
}

impl AccessLog {
    /// Creates a sink and its receiver without a writer task (unit tests and
    /// in-process E2E read the entries directly).
    #[must_use]
    pub fn channel(metrics: Arc<Metrics>) -> (Arc<Self>, mpsc::Receiver<AccessEntry>) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        (
            Arc::new(Self {
                tx,
                dropped: AtomicU64::new(0),
                metrics,
                close: Notify::new(),
            }),
            rx,
        )
    }

    /// Opens the configured destination and starts the writer task.
    ///
    /// Opening the file happens once, before any listener serves: a sink the
    /// process cannot open is a startup error (ADR-0020).
    pub async fn start(
        config: &AccessLogSettings,
        metrics: Arc<Metrics>,
    ) -> io::Result<AccessHandle> {
        let writer: Box<dyn AsyncWrite + Send + Unpin> = match &config.path {
            Some(path) => Box::new(
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await?,
            ),
            None => Box::new(tokio::io::stdout()),
        };
        let format = config.format;
        let (log, rx) = Self::channel(metrics);
        let task_log = Arc::clone(&log);
        let writer = tokio::spawn(writer_task(rx, writer, format, task_log));
        Ok(AccessHandle { log, writer })
    }

    /// Lines lost because the channel was full or the writer had stopped.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Non-blocking send: never awaits, so a full sink cannot delay a request.
    fn emit(&self, entry: AccessEntry) {
        if self.tx.try_send(entry).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .access_log_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AccessHandle {
    /// Flushes the queue (bounded wait) and stops the writer. Other clones of
    /// the sink may still exist; after this call they count as dropped.
    pub async fn shutdown(self) {
        self.log.close.notify_one();
        if tokio::time::timeout(CLOSE_TIMEOUT, self.writer)
            .await
            .is_err()
        {
            eprintln!("WARN access log writer did not stop within {CLOSE_TIMEOUT:?}");
        }
    }
}

async fn writer_task(
    mut rx: mpsc::Receiver<AccessEntry>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    format: AccessLogFormat,
    log: Arc<AccessLog>,
) {
    let mut out = BufWriter::new(writer);
    loop {
        tokio::select! {
            _ = log.close.notified() => {
                // Whatever is already queued belongs to requests that were
                // answered before shutdown; write it, then flush and stop.
                while let Ok(entry) = rx.try_recv() {
                    if write_line(&mut out, format, &entry).await.is_err() {
                        break;
                    }
                }
                if let Err(err) = out.flush().await {
                    eprintln!("WARN access log flush failed on shutdown: {err}");
                }
                return;
            }
            item = rx.recv() => match item {
                Some(entry) => {
                    if let Err(err) = write_line(&mut out, format, &entry).await {
                        eprintln!("ERROR access log write failed: {err}; sink stopped");
                        return;
                    }
                }
                None => {
                    if let Err(err) = out.flush().await {
                        eprintln!("WARN access log flush failed: {err}");
                    }
                    return;
                }
            }
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(
    out: &mut W,
    format: AccessLogFormat,
    entry: &AccessEntry,
) -> io::Result<()> {
    let line = match format {
        AccessLogFormat::Json => format_json(entry),
        AccessLogFormat::Combined => format_combined(entry),
    };
    out.write_all(line.as_bytes()).await?;
    out.write_all(b"\n").await?;
    // One flush per line: `tail -f` and a collector see the request promptly,
    // and a crash loses at most the line being written.
    out.flush().await
}

impl AccessEntry {
    fn json_time(&self) -> String {
        rfc3339(self.time_unix_ms)
    }
}

fn format_json(entry: &AccessEntry) -> String {
    let line = JsonLine {
        time: entry.json_time(),
        listener: &entry.listener,
        client: entry.client.to_string(),
        protocol: entry.protocol.as_str(),
        method: &entry.method,
        path: &entry.path,
        host: &entry.host,
        status: entry.status,
        duration_ms: entry.duration_ms,
        backend: entry.backend.as_deref(),
        server: entry.server.map(|addr| addr.to_string()),
        referer: entry.referer.as_deref(),
        user_agent: entry.user_agent.as_deref(),
        bytes: entry.bytes,
    };
    // The struct is plain data (strings, numbers, options): serialization
    // cannot fail, but a failure must still produce a line, never a panic.
    serde_json::to_string(&line)
        .unwrap_or_else(|_| "{\"error\":\"access_log_serialize\"}".to_owned())
}

fn format_combined(entry: &AccessEntry) -> String {
    let date = combined_date(entry.time_unix_ms / 1000);
    let bytes = entry
        .bytes
        .map_or_else(|| "-".to_owned(), |n| n.to_string());
    let ua = entry.user_agent.as_deref().unwrap_or("-");
    format!(
        "{} - - [{}] \"{} {} {}\" {} {} \"-\" \"{}\"",
        entry.client.ip(),
        date,
        escape_combined(&entry.method),
        escape_combined(&entry.path),
        entry.protocol.as_request_line(),
        entry.status,
        bytes,
        escape_combined(ua)
    )
}

/// Escapes a combined-format field so one request can never inject a second
/// line (or forge a quote-delimited field).
fn escape_combined(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC, millisecond precision).
fn rfc3339(unix_ms: u64) -> String {
    let (year, month, day, hour, minute, second) = utc_parts(unix_ms / 1000);
    let millis = unix_ms % 1000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// `dd/Mon/yyyy:HH:MM:SS +0000` (nginx combined, always UTC).
fn combined_date(seconds: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day, hour, minute, second) = utc_parts(seconds);
    format!(
        "{day:02}/{}/{year:04}:{hour:02}:{minute:02}:{second:02} +0000",
        MONTHS[usize::try_from(month.saturating_sub(1)).unwrap_or(0)]
    )
}

/// UTC calendar fields for a Unix timestamp (proleptic Gregorian, Howard
/// Hinnant's `civil_from_days`). No timezone database: the log is UTC.
fn utc_parts(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rem = seconds % 86_400;
    let hour = u32::try_from(rem / 3_600).unwrap_or(0);
    let minute = u32::try_from((rem % 3_600) / 60).unwrap_or(0);
    let second = u32::try_from(rem % 60).unwrap_or(0);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(mp + if mp < 10 { 3 } else { -9 }).unwrap_or(1);
    if month <= 2 {
        year += 1;
    }
    (year, month, day, hour, minute, second)
}

/// Borrowed, request-scoped record. Every terminal path in `serve_http` sets
/// what it knows (status, backend, bytes) and lets the record drop, which is
/// where the entry is stamped with its duration and sent. Paths that end
/// without a response leave `status = 0`, so the line is honest.
pub struct AccessRecord {
    log: Arc<AccessLog>,
    started: Instant,
    entry: Option<AccessEntry>,
}

impl AccessRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: Arc<AccessLog>,
        listener: &str,
        client: SocketAddr,
        protocol: ClientProtocol,
        method: &str,
        path: &str,
        host: &str,
        referer: Option<&str>,
        user_agent: Option<&str>,
    ) -> Self {
        let time_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Self {
            log,
            started: Instant::now(),
            entry: Some(AccessEntry {
                time_unix_ms,
                listener: listener.to_owned(),
                client,
                protocol,
                method: method.to_owned(),
                path: path.to_owned(),
                host: host.to_owned(),
                status: 0,
                duration_ms: 0,
                backend: None,
                server: None,
                referer: referer.map(ToOwned::to_owned),
                user_agent: user_agent.map(ToOwned::to_owned),
                bytes: None,
            }),
        }
    }

    pub fn status(&mut self, status: u16) {
        if let Some(entry) = self.entry.as_mut() {
            entry.status = status;
        }
    }

    pub fn backend(&mut self, name: &str, server: SocketAddr) {
        if let Some(entry) = self.entry.as_mut() {
            entry.backend = Some(name.to_owned());
            entry.server = Some(server);
        }
    }

    pub fn bytes(&mut self, bytes: u64) {
        if let Some(entry) = self.entry.as_mut() {
            entry.bytes = Some(bytes);
        }
    }
}

impl Drop for AccessRecord {
    fn drop(&mut self) {
        let Some(mut entry) = self.entry.take() else {
            return;
        };
        entry.duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.log.emit(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn client() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 54321)
    }

    fn entry() -> AccessEntry {
        AccessEntry {
            time_unix_ms: 1_792_896_000_123, // 2026-10-25T02:40:00.123Z
            listener: "web".to_owned(),
            client: client(),
            protocol: ClientProtocol::Http2,
            method: "GET".to_owned(),
            path: "/api/items".to_owned(),
            host: "example.test".to_owned(),
            status: 200,
            duration_ms: 12,
            backend: Some("api".to_owned()),
            server: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                9000,
            )),
            referer: None,
            user_agent: Some("curl/8.7".to_owned()),
            bytes: Some(17),
        }
    }

    #[test]
    fn utc_calendar_matches_known_instants() {
        assert_eq!(utc_parts(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(utc_parts(1_000_000_000), (2001, 9, 9, 1, 46, 40));
        assert_eq!(utc_parts(1_792_896_000), (2026, 10, 25, 2, 40, 0));
        // Leap day, and the day after.
        assert_eq!(utc_parts(1_709_164_800), (2024, 2, 29, 0, 0, 0));
        assert_eq!(utc_parts(1_709_251_200), (2024, 3, 1, 0, 0, 0));
    }

    #[test]
    fn json_is_one_line_with_the_documented_fields() {
        let line = format_json(&entry());
        assert!(!line.contains('\n'), "{line}");
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(value["time"], "2026-10-25T02:40:00.123Z");
        assert_eq!(value["listener"], "web");
        assert_eq!(value["client"], "203.0.113.7:54321");
        assert_eq!(value["protocol"], "http/2");
        assert_eq!(value["method"], "GET");
        assert_eq!(value["path"], "/api/items");
        assert_eq!(value["host"], "example.test");
        assert_eq!(value["status"], 200);
        assert_eq!(value["duration_ms"], 12);
        assert_eq!(value["backend"], "api");
        assert_eq!(value["server"], "10.0.0.2:9000");
        assert_eq!(value["user_agent"], "curl/8.7");
        assert_eq!(value["bytes"], 17);
        assert!(value.get("referer").is_none(), "absent stays absent");
    }

    #[test]
    fn combined_is_one_line_and_escapes_injection() {
        let mut value = entry();
        value.method = "GET\" \nFAKE".to_owned();
        value.path = "/x\\y".to_owned();
        value.user_agent = Some("a\"b\nc".to_owned());
        let line = format_combined(&value);
        assert!(!line.contains('\n'), "{line}");
        assert!(line.contains("GET\\\" \\nFAKE"), "{line}");
        assert!(line.contains("/x\\\\y"), "{line}");
        assert!(line.contains("a\\\"b\\nc"), "{line}");
        assert!(line.contains("[25/Oct/2026:02:40:00 +0000]"), "{line}");
        assert!(line.contains("\" 200 17 "), "{line}");
    }

    #[test]
    fn absent_values_are_dashes_in_combined() {
        let mut value = entry();
        value.bytes = None;
        value.user_agent = None;
        let line = format_combined(&value);
        assert!(line.ends_with("\" 200 - \"-\" \"-\""), "{line}");
    }

    #[tokio::test]
    async fn a_stopped_writer_counts_dropped_lines() {
        let metrics = Arc::new(Metrics::default());
        let (log, receiver) = AccessLog::channel(Arc::clone(&metrics));
        // No writer: the channel closes, so the next entry cannot be queued.
        drop(receiver);
        let mut record = AccessRecord::new(
            Arc::clone(&log),
            "web",
            client(),
            ClientProtocol::Http1,
            "GET",
            "/x",
            "h",
            None,
            None,
        );
        record.status(200);
        drop(record);
        assert_eq!(log.dropped(), 1);
        assert_eq!(metrics.access_log_dropped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_writer_flushes_the_queued_lines_on_shutdown() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "eqproxy-access-unit-{}-{}.log",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let settings = AccessLogSettings {
            path: Some(path.clone()),
            format: AccessLogFormat::Json,
        };
        let handle = AccessLog::start(&settings, Arc::new(Metrics::default()))
            .await
            .expect("open sink");
        for status in [200, 404] {
            let mut record = AccessRecord::new(
                Arc::clone(&handle.log),
                "web",
                client(),
                ClientProtocol::Http1,
                "GET",
                "/queued",
                "h",
                None,
                None,
            );
            record.status(status);
        }
        handle.shutdown().await;
        let text = std::fs::read_to_string(&path).expect("log written");
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 2, "{text}");
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("json");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("json");
        assert_eq!(first["status"], 200);
        assert_eq!(second["status"], 404);
        let _ = std::fs::remove_file(&path);
    }
}
