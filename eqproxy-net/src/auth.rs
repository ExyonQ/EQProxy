//! Rule authentication gate (B-N9/B-I9): HTTP Basic against htpasswd
//! users and the external auth subrequest (nginx `auth_request` /
//! ingress-nginx `auth-url`).
//!
//! Fail closed, explicitly: a request that cannot be authorized is
//! rejected with a response the client can act on — never forwarded and
//! never silently dropped. The subrequest is `GET` with the client's
//! headers (minus framing) plus `X-Original-Method`/`X-Original-URL`,
//! bounded by `connect_timeout` (dial) and the caller's total timeout.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use eqproxy_core::auth::{AuthUrl, BasicUsers, basic_credentials};

use crate::http1::{HeadLimits, RequestHead, parse_response_head, read_head};
use crate::proxy::ResolvedAuth;

/// Maximum deny-response body read from the auth service (bounded like
/// local responses).
const MAX_AUTH_RESPONSE_BYTES: usize = 8 * 1024;

/// Headers of the auth service response that reach the client on deny
/// (OAuth2 flows need `www-authenticate`/`location`; the rest is dropped).
const FORWARDED_DENY_HEADERS: [&str; 4] =
    ["www-authenticate", "location", "set-cookie", "content-type"];

/// What the auth gate decided for one request.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Authorized: the request continues.
    Allow,
    /// Not authorized (wrong/missing credentials, or a 401/403 from the
    /// auth service): the client gets this response.
    Deny(DenyResponse),
    /// The auth service could not decide (down, timeout, malformed
    /// response, unexpected status): fail closed with an explicit error.
    Error(DenyResponse),
}

/// Response served instead of the request when auth rejects or errors.
#[derive(Debug)]
pub struct DenyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Runs the full gate: Basic first (local, cheap), then the external
/// subrequest. `connect_timeout` bounds the dial; `total_timeout` bounds
/// the whole subrequest.
pub async fn check(
    auth: &ResolvedAuth,
    request: &RequestHead,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> AuthOutcome {
    if let Some(basic) = &auth.basic
        && let Some(deny) = check_basic(basic, &request.headers, &auth.realm)
    {
        return AuthOutcome::Deny(deny);
    }
    match &auth.url {
        Some(target) => {
            match tokio::time::timeout(
                total_timeout,
                subrequest(target, request, connect_timeout, total_timeout),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(_) => AuthOutcome::Error(service_error()),
            }
        }
        None => AuthOutcome::Allow,
    }
}

/// Basic check (B-N9/B-I9): `Some(deny)` when credentials are missing or
/// wrong; `None` = authorized.
#[must_use]
pub fn check_basic(
    basic: &BasicUsers,
    headers: &[(String, String)],
    realm: &str,
) -> Option<DenyResponse> {
    let authorized =
        basic_credentials(headers).is_some_and(|(user, password)| basic.verify(&user, &password));
    if authorized {
        return None;
    }
    Some(DenyResponse {
        status: 401,
        headers: vec![(
            "www-authenticate".to_owned(),
            format!("Basic realm=\"{realm}\", charset=\"UTF-8\""),
        )],
        body: String::new(),
    })
}

/// The auth service failed to answer: explicit 502 (nginx parity: a
/// failed auth subrequest is a bad gateway, never a pass-through).
fn service_error() -> DenyResponse {
    DenyResponse {
        status: 502,
        headers: Vec::new(),
        body: "auth service unavailable".to_owned(),
    }
}

/// One external auth subrequest (nginx `auth_request` semantics):
/// 2xx allows, 401/403 denies (its response reaches the client), any
/// other status is an error (fail closed).
async fn subrequest(
    target: &AuthUrl,
    request: &RequestHead,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> AuthOutcome {
    // Hostnames resolve through the OS resolver per subrequest (async,
    // never on the boot path): a literal IP skips any lookup cost.
    let resolved = tokio::net::lookup_host((target.host.as_str(), target.port)).await;
    let addr = match resolved {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return AuthOutcome::Error(service_error()),
        },
        Err(_) => return AuthOutcome::Error(service_error()),
    };
    let connected =
        tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await;
    let mut stream = match connected {
        Ok(Ok(stream)) => stream,
        _ => return AuthOutcome::Error(service_error()),
    };
    let head = subrequest_head(target, request);
    if stream.write_all(head.as_bytes()).await.is_err() {
        return AuthOutcome::Error(service_error());
    }
    // The auth subrequest is internal and its answer is read into a fixed
    // budget: it uses the historical head bounds, not a listener's.
    let default_limits = HeadLimits::default();
    let (head, rest) =
        match read_head(&mut stream, total_timeout, default_limits.max_head_bytes).await {
            Ok(pair) => pair,
            Err(_) => return AuthOutcome::Error(service_error()),
        };
    let response = match parse_response_head(&head, false, default_limits) {
        Ok(response) => response,
        Err(_) => return AuthOutcome::Error(service_error()),
    };
    // Body (bounded): the connection was opened for this check only and
    // closes with it (`connection: close`), so framing is irrelevant.
    let mut body = rest;
    let mut chunk = [0u8; 2048];
    while body.len() < MAX_AUTH_RESPONSE_BYTES {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(MAX_AUTH_RESPONSE_BYTES);
    match response.status {
        200..=299 => AuthOutcome::Allow,
        401 | 403 => AuthOutcome::Deny(DenyResponse {
            status: response.status,
            headers: deny_response_headers(&head),
            body: String::from_utf8_lossy(&body).into_owned(),
        }),
        // A status outside {2xx, 401, 403} is not a decision (nginx
        // parity: an auth subrequest error is a 500).
        _ => AuthOutcome::Error(DenyResponse {
            status: 500,
            headers: Vec::new(),
            body: "auth check failed".to_owned(),
        }),
    }
}

/// Subrequest head: `GET` with the client's headers (minus framing and
/// hop-by-hop) plus the original method/URL, so the auth service can
/// authorize per path.
fn subrequest_head(target: &AuthUrl, request: &RequestHead) -> String {
    let mut head = format!("GET {} HTTP/1.1\r\n", target.path);
    head.push_str(&format!("host: {}:{}\r\n", target.host, target.port));
    head.push_str(&format!("x-original-method: {}\r\n", request.method));
    head.push_str(&format!("x-original-url: {}\r\n", request.target));
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "te"
                | "trailer"
                | "upgrade"
                | "expect"
                | "x-original-method"
                | "x-original-url"
        ) {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n\r\n");
    head
}

/// Allowlisted headers of the auth response that reach the client on
/// deny. Values with control characters are dropped (never injectable
/// into the response we generate).
fn deny_response_headers(head: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if FORWARDED_DENY_HEADERS.contains(&name.as_str())
            && !value.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            out.push((name, value.to_owned()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(authorization: Option<&str>) -> RequestHead {
        RequestHead {
            method: "GET".to_owned(),
            target: "/private/x".to_owned(),
            version: 11,
            framing: crate::http1::BodyFraming::None,
            wants_close: true,
            expect_continue: false,
            wants_upgrade: false,
            host: "svc.example".to_owned(),
            headers: authorization
                .map(|value| vec![("authorization".to_owned(), value.to_owned())])
                .unwrap_or_default(),
        }
    }

    #[test]
    fn basic_denies_without_credentials_and_allows_with_them() {
        use eqproxy_core::auth::BasicUsers;
        // `openssl passwd -apr1 -salt eqpr0xyS secret`.
        let basic = BasicUsers::parse(&["alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1".to_owned()])
            .expect("users parse");
        let deny = check_basic(&basic, &request_with(None).headers, "EQProxy")
            .expect("missing credentials are denied");
        assert_eq!(deny.status, 401);
        assert_eq!(
            deny.headers,
            vec![(
                "www-authenticate".to_owned(),
                "Basic realm=\"EQProxy\", charset=\"UTF-8\"".to_owned()
            )]
        );
        let blob =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:secret");
        assert!(
            check_basic(
                &basic,
                &request_with(Some(&format!("Basic {blob}"))).headers,
                "EQProxy"
            )
            .is_none(),
            "good credentials authorize"
        );
        let blob = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:nope");
        assert!(
            check_basic(
                &basic,
                &request_with(Some(&format!("Basic {blob}"))).headers,
                "EQProxy"
            )
            .is_some(),
            "wrong password is denied"
        );
    }

    #[test]
    fn subrequest_head_copies_client_headers_and_names_the_original() {
        let target = AuthUrl {
            host: "auth.example".to_owned(),
            port: 9000,
            path: "/verify".to_owned(),
        };
        let mut request = request_with(Some("Basic abc"));
        request
            .headers
            .push(("content-length".to_owned(), "5".to_owned()));
        request
            .headers
            .push(("cookie".to_owned(), "sid=1".to_owned()));
        let head = subrequest_head(&target, &request);
        assert!(head.starts_with("GET /verify HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("host: auth.example:9000\r\n"), "{head}");
        assert!(
            head.contains("x-original-method: GET\r\nx-original-url: /private/x\r\n"),
            "{head}"
        );
        assert!(head.contains("authorization: Basic abc\r\n"), "{head}");
        assert!(head.contains("cookie: sid=1\r\n"), "{head}");
        assert!(!head.contains("content-length"), "{head}");
        assert!(head.ends_with("connection: close\r\n\r\n"), "{head}");
    }

    #[test]
    fn deny_headers_drop_control_characters() {
        let head = b"HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Basic realm=\"x\"\r\nx-sneak: a\r\nlocation: /login\r\nbad: one\ntwo\r\n\r\n";
        let headers = deny_response_headers(head);
        assert_eq!(
            headers,
            vec![
                (
                    "www-authenticate".to_owned(),
                    "Basic realm=\"x\"".to_owned()
                ),
                ("location".to_owned(), "/login".to_owned()),
            ]
        );
    }
}
