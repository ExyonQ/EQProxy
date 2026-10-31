//! TOML emitter and Markdown report of the configuration importer.
//!
//! The emitter writes only the fields the schema does not default to, so the
//! file stays readable; the converter then parses and validates the result
//! with EQProxy's own parser before handing it over (`import::convert`).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::{Conv, Counts, Severity, Source, toml_key, toml_string};

/// Serialises the accumulated IR as `eqproxy.toml`.
pub fn emit_toml(conv: &Conv) -> String {
    let mut out = String::new();
    out.push_str("# Generado por `eqproxy config import`.\n");
    out.push_str("# Revise el informe de conversión antes de usarlo en producción.\n");
    out.push_str("schema_version = 1\n");

    for (name, backend) in &conv.backends {
        let _ = writeln!(out, "\n[backend.{}]", toml_key(name));
        if backend.servers.len() == 1
            && backend.servers[0].weight == 1
            && !backend.servers[0].backup
            && backend.servers[0].maxconn == 0
        {
            let _ = writeln!(out, "server = {}", toml_string(&backend.servers[0].addr));
        } else if !backend.servers.is_empty() {
            let rendered: Vec<String> = backend
                .servers
                .iter()
                .map(|server| {
                    let mut fields = vec![format!("addr = {}", toml_string(&server.addr))];
                    if server.weight != 1 {
                        fields.push(format!("weight = {}", server.weight));
                    }
                    if server.backup {
                        fields.push("backup = true".to_owned());
                    }
                    if server.maxconn != 0 {
                        fields.push(format!("maxconn = {}", server.maxconn));
                    }
                    format!("{{ {} }}", fields.join(", "))
                })
                .collect();
            let _ = writeln!(out, "servers = [{}]", rendered.join(", "));
        }
        if !backend.balance.is_empty() && backend.balance != "roundrobin" {
            let _ = writeln!(out, "balance = {}", toml_string(&backend.balance));
        }
        if backend.proxy_protocol_v1 {
            out.push_str("proxy_protocol = \"v1\"\n");
        }
        if backend.retries > 0 {
            let _ = writeln!(out, "retries = {}", backend.retries);
        }
        if backend.maxqueue > 0 {
            let _ = writeln!(out, "maxqueue = {}", backend.maxqueue);
        }
        if let Some(slow_start) = &backend.slow_start {
            let _ = writeln!(out, "slow_start = {}", toml_string(slow_start));
        }

        if let Some(health) = &backend.health_check {
            let _ = writeln!(out, "\n[backend.{}.health_check]", toml_key(name));
            let _ = writeln!(out, "interval = {}", toml_string(&health.interval));
            let _ = writeln!(out, "timeout = {}", toml_string(&health.timeout));
            let _ = writeln!(out, "fall = {}", health.fall);
            let _ = writeln!(out, "rise = {}", health.rise);
            if let Some(kind) = health.kind {
                let _ = writeln!(out, "type = {}", toml_string(kind));
            }
            if let Some(path) = &health.http_path {
                let _ = writeln!(out, "http_path = {}", toml_string(path));
            }
            if let Some(status) = &health.expect_status {
                let _ = writeln!(out, "expect_status = {}", toml_string(status));
            }
            if let Some(host) = &health.http_host {
                let _ = writeln!(out, "http_host = {}", toml_string(host));
            }
        }

        if let Some(tls) = &backend.tls {
            let _ = writeln!(out, "\n[backend.{}.tls]", toml_key(name));
            let _ = writeln!(out, "verify = {}", tls.verify);
            if let Some(ca) = &tls.ca_file {
                let _ = writeln!(out, "ca_file = {}", toml_string(ca));
            }
            if let Some(server_name) = &tls.server_name {
                let _ = writeln!(out, "server_name = {}", toml_string(server_name));
            }
            if !tls.alpn.is_empty() {
                let _ = writeln!(out, "alpn = {}", string_list(&tls.alpn));
            }
            if let Some(version) = tls.min_version {
                let _ = writeln!(out, "min_version = {}", toml_string(version));
            }
        }

        if let Some(affinity) = &backend.affinity {
            let _ = writeln!(out, "\n[backend.{}.affinity]", toml_key(name));
            let _ = writeln!(out, "mode = {}", toml_string(&affinity.mode));
            if let Some(cookie) = &affinity.cookie {
                let _ = writeln!(out, "cookie = {}", toml_string(cookie));
            }
        }
    }

    for (name, listener) in &conv.listeners {
        let _ = writeln!(out, "\n[listener.{}]", toml_key(name));
        let _ = writeln!(out, "listen = {}", toml_string(&listener.listen));
        let _ = writeln!(out, "mode = {}", toml_string(&listener.mode));
        let _ = writeln!(out, "backend = {}", toml_string(&listener.backend));
        if listener.maxconn != 1024 {
            let _ = writeln!(out, "maxconn = {}", listener.maxconn);
        }
        for (field, value) in [
            ("connect_timeout", &listener.connect_timeout),
            ("idle_timeout", &listener.idle_timeout),
            ("client_header_timeout", &listener.client_header_timeout),
            ("server_header_timeout", &listener.server_header_timeout),
        ] {
            if let Some(value) = value {
                let _ = writeln!(out, "{field} = {}", toml_string(value));
            }
        }
        if let Some(forwarded) = listener.forwarded_headers {
            let _ = writeln!(out, "forwarded_headers = {}", toml_string(forwarded));
        }
        if listener.proxy_receive {
            out.push_str("proxy_receive = true\n");
        }
        if listener.quic {
            out.push_str("quic = true\n");
        }

        if let Some(tls) = &listener.tls {
            let _ = writeln!(out, "\n[listener.{}.tls]", toml_key(name));
            let _ = writeln!(out, "cert = {}", toml_string(&tls.cert));
            let _ = writeln!(out, "key = {}", toml_string(&tls.key));
            if !tls.alpn.is_empty() {
                let _ = writeln!(out, "alpn = {}", string_list(&tls.alpn));
            }
            if let Some(version) = tls.min_version {
                let _ = writeln!(out, "min_version = {}", toml_string(version));
            }
            if let Some(ca) = &tls.client_ca {
                let _ = writeln!(out, "client_ca = {}", toml_string(ca));
            }
        }
        if listener.compression_gzip {
            let _ = writeln!(out, "\n[listener.{}.compression]", toml_key(name));
            out.push_str("gzip = true\n");
            if let Some(level) = listener.compression_level {
                let _ = writeln!(out, "level = {level}");
            }
            if let Some(min_size) = listener.compression_min_size {
                let _ = writeln!(out, "min_size = {min_size}");
            }
        }
        if let Some(max_body_bytes) = listener.max_body_bytes {
            let _ = writeln!(out, "\n[listener.{}.limits]", toml_key(name));
            let _ = writeln!(out, "max_body_bytes = {max_body_bytes}");
        }
        if listener.cache {
            let _ = writeln!(out, "\n[listener.{}.cache]", toml_key(name));
        }
        for rule in &listener.rules {
            let _ = writeln!(out, "\n[[listener.{}.rules]]", toml_key(name));
            if !rule.name.is_empty() {
                let _ = writeln!(out, "name = {}", toml_string(&rule.name));
            }
            if let Some(backend) = &rule.use_backend {
                let _ = writeln!(out, "use_backend = {}", toml_string(backend));
            }
            if let Some(prefix) = &rule.path_prefix {
                let _ = writeln!(out, "path_prefix = {}", toml_string(prefix));
            }
            if let Some(path) = &rule.path {
                let _ = writeln!(out, "path = {}", toml_string(path));
            }
            if let Some(host) = &rule.host {
                let _ = writeln!(out, "host = {}", toml_string(host));
            }
            if let Some(regex) = &rule.host_regex {
                let _ = writeln!(out, "host_regex = {}", toml_string(regex));
            }
            if !rule.methods.is_empty() {
                let _ = writeln!(out, "methods = {}", string_list(&rule.methods));
            }
            if !rule.ip.is_empty() {
                let _ = writeln!(out, "ip = {}", string_list(&rule.ip));
            }
            if !rule.set_headers.is_empty() {
                let _ = writeln!(out, "set_headers = {}", header_ops(&rule.set_headers));
            }
            if !rule.add_headers.is_empty() {
                let _ = writeln!(out, "add_headers = {}", header_ops(&rule.add_headers));
            }
            if !rule.response_headers.is_empty() {
                let _ = writeln!(
                    out,
                    "response_headers = {}",
                    header_ops(&rule.response_headers)
                );
            }
            if let Some(origin) = &rule.cors_origin {
                let _ = writeln!(out, "cors = {{ allow_origin = {} }}", toml_string(origin));
            }
            if let Some((rate, per, burst)) = &rule.rate_limit {
                let burst = burst.map_or_else(String::new, |value| format!(", burst = {value}"));
                let _ = writeln!(
                    out,
                    "rate_limit = {{ rate = {rate}, per = {}{burst} }}",
                    toml_string(per)
                );
            }
            if let Some(prefix) = &rule.rewrite_prefix {
                let _ = writeln!(
                    out,
                    "rewrite = {{ path_prefix_rewrite = {} }}",
                    toml_string(prefix)
                );
            }
            if let Some((status, body)) = &rule.direct_response {
                match body {
                    Some(body) => {
                        let _ = writeln!(
                            out,
                            "direct_response = {{ status = {status}, body = {} }}",
                            toml_string(body)
                        );
                    }
                    None => {
                        let _ = writeln!(out, "direct_response = {{ status = {status} }}");
                    }
                }
            }
            if let Some((status, location)) = &rule.redirect {
                match status {
                    Some(status) => {
                        let _ = writeln!(
                            out,
                            "redirect = {{ status = {status}, location = {} }}",
                            toml_string(location)
                        );
                    }
                    None => {
                        let _ =
                            writeln!(out, "redirect = {{ location = {} }}", toml_string(location));
                    }
                }
            }
        }
    }
    out
}

fn string_list(values: &[String]) -> String {
    let rendered: Vec<String> = values.iter().map(|value| toml_string(value)).collect();
    format!("[{}]", rendered.join(", "))
}

fn header_ops(ops: &[super::HeaderOp]) -> String {
    let rendered: Vec<String> = ops
        .iter()
        .map(|op| {
            format!(
                "{{ name = {}, value = {} }}",
                toml_string(&op.name),
                toml_string(&op.value)
            )
        })
        .collect();
    format!("[{}]", rendered.join(", "))
}

/// Renders the Markdown report. `input`/`output` are placeholders that
/// [`super::report_with_paths`] replaces with the real names.
pub fn render(source: Source, conv: &Conv, counts: Counts) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Informe de conversión {} → EQProxy\n",
        source_label(source)
    );
    let _ = writeln!(out, "- Entrada: `@input@`");
    let _ = writeln!(out, "- Salida: `@output@`");
    let _ = writeln!(
        out,
        "- Listeners generados: **{}** · Backends generados: **{}**",
        conv.listeners.len(),
        conv.backends.len()
    );
    let _ = writeln!(
        out,
        "- Directivas leídas: **{}** · clasificadas: **{}** — convertidas **{}** · a revisar **{}** · rechazadas **{}**",
        conv.walked,
        conv.notes.len(),
        counts.converted,
        counts.review,
        counts.rejected
    );
    out.push_str(
        "\n«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. \
         El fichero generado se ha parseado y validado con el propio parser de EQProxy \
         (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha \
         ejecutado nada de la configuración de origen ni se ha medido tráfico.\n",
    );

    let _ = writeln!(out, "\n## Conversión generada\n");
    out.push_str("| listener | escucha | modo | backend | TLS |\n|---|---|---|---|---|\n");
    for (name, listener) in &conv.listeners {
        let _ = writeln!(
            out,
            "| `{name}` | {} | {} | `{}` | {} |",
            listener.listen,
            listener.mode,
            listener.backend,
            if listener.tls.is_some() { "sí" } else { "no" }
        );
    }

    out.push_str("\n| backend | servidores (peso) | balance | health check | PROXY | TLS backend |\n|---|---|---|---|---|---|\n");
    for (name, backend) in &conv.backends {
        let servers = if backend.servers.is_empty() {
            "—".to_owned()
        } else {
            backend
                .servers
                .iter()
                .map(|server| {
                    let mut cell = format!("{} ({})", server.addr, server.weight);
                    if server.backup {
                        cell.push_str(" backup");
                    }
                    cell
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let health = backend.health_check.as_ref().map_or_else(
            || "—".to_owned(),
            |health| {
                let mut text = format!(
                    "{} {}/{}/fall {}/rise {}",
                    health.kind.unwrap_or("tcp").to_uppercase(),
                    health.interval,
                    health.timeout,
                    health.fall,
                    health.rise
                );
                if let Some(path) = &health.http_path
                    && health.kind == Some("http")
                {
                    let _ = write!(text, " {path}");
                }
                text
            },
        );
        let balance = if backend.balance.is_empty() {
            "roundrobin"
        } else {
            &backend.balance
        };
        let _ = writeln!(
            out,
            "| `{name}` | {servers} | {balance} | {health} | {} | {} |",
            if backend.proxy_protocol_v1 {
                "v1"
            } else {
                "none"
            },
            if backend.tls.is_some() { "sí" } else { "no" }
        );
    }

    let _ = writeln!(out, "\n## Detalle de la clasificación\n");
    for (severity, title) in [
        (Severity::Rejected, "❌ no traducible"),
        (Severity::Gap, "⛔ rechazado (sin equivalente en EQProxy)"),
        (Severity::Review, "⚠️ revisar"),
        (Severity::Info, "ℹ️ informativo"),
        (Severity::Done, "✅ convertido"),
    ] {
        let notes: Vec<_> = conv
            .notes
            .iter()
            .filter(|note| note.severity == severity)
            .collect();
        let _ = writeln!(out, "### {title} ({})\n", notes.len());
        for note in notes {
            let _ = writeln!(
                out,
                "- `{}` — *{}*: {}",
                note.directive, note.context, note.message
            );
        }
        out.push('\n');
    }

    out.push_str("## Qué no se ha traducido\n\n");
    let mut gaps: BTreeMap<&str, usize> = BTreeMap::new();
    for note in conv
        .notes
        .iter()
        .filter(|note| matches!(note.severity, Severity::Gap | Severity::Rejected))
    {
        *gaps.entry(note.message.as_str()).or_insert(0) += 1;
    }
    if gaps.is_empty() {
        out.push_str(
            "Ninguna: todas las directivas del origen tienen destino o son informativas.\n",
        );
    } else {
        for (message, count) in gaps {
            let _ = writeln!(out, "- {message} ({count})");
        }
        out.push_str(
            "\nCada uno de estos puntos es un cambio de comportamiento frente al proxy de origen. \
             Hasta que se resuelvan (o se acepten por escrito), la configuración **no es equivalente**.\n",
        );
    }

    let _ = writeln!(
        out,
        "\n## Siguiente paso\n\n1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.\n\
         2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.\n\
         3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`."
    );
    out
}

fn source_label(source: Source) -> &'static str {
    match source {
        Source::Nginx => "nginx",
        Source::Haproxy => "HAProxy",
        Source::Ingress => "ingress-nginx",
        Source::Envoy => "Envoy",
    }
}

/// Replaces the path placeholders of a report with the real file names.
#[must_use]
pub fn report_with_paths(report: &str, input: &str, output: &str) -> String {
    report
        .replacen("@input@", input, 1)
        .replacen("@output@", output, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_substituted_once_and_untouched_when_absent() {
        let report = "- Entrada: `@input@`\n- Salida: `@output@`\n";
        let rendered = report_with_paths(report, "a/nginx.conf", "out/eqproxy.toml");
        assert_eq!(
            rendered,
            "- Entrada: `a/nginx.conf`\n- Salida: `out/eqproxy.toml`\n"
        );
        assert_eq!(
            report_with_paths("sin marcadores", "x", "y"),
            "sin marcadores"
        );
    }
}
