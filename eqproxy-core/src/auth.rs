//! Rule authentication (B-N9/B-I9): HTTP Basic against htpasswd-format
//! users and the `auth-url` subrequest grammar.
//!
//! Semantics live here, once (Q8): the config gate and the dataplane
//! verify the same entries with the same code. Fail closed everywhere:
//! an entry with an unsupported hash scheme is a config error naming
//! the fix, never a silent "always deny" user.

use md5::{Digest, Md5};

/// Maximum salt length of `$apr1$` (Apache `htpasswd`).
const APR1_MAX_SALT: usize = 8;

/// Hash schemes htpasswd can generate but this build does not verify.
/// Each is rejected at the config gate with the fix (regenerate as
/// `$apr1$`), never treated as a literal password.
const UNSUPPORTED_SCHEMES: [(&str, &str); 7] = [
    ("$2y$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2a$", "bcrypt"),
    ("$2x$", "bcrypt"),
    ("$5$", "SHA-256 crypt"),
    ("$6$", "SHA-512 crypt"),
    ("$1$", "MD5 crypt"),
];

/// Parsed `auth-url` target (B-N9/B-I9; nginx `auth_request`, ingress
/// `auth-url`): `http://HOST[:PORT][/PATH[?QUERY]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUrl {
    /// Host to connect to and to send as `Host` (lowercased).
    pub host: String,
    /// Port (default 80).
    pub port: u16,
    /// Request target of the subrequest (path + query; default `/`).
    pub path: String,
}

/// Parses an `auth-url`. Only `http://` is accepted: an `https://` URL
/// is rejected naming the gap (the subrequest is plain http — put the
/// auth service on localhost or the service mesh).
pub fn parse_auth_url(raw: &str) -> Result<AuthUrl, String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("\"{raw}\" is not a URL (rule: http://HOST:PORT/PATH)"))?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(format!(
            "\"{raw}\": scheme \"{scheme}\" is not supported (rule: http:// only; https auth-url is a declared gap)"
        ));
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, tail)) => (authority, format!("/{tail}")),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() {
        return Err(format!(
            "\"{raw}\" has no host (rule: http://HOST:PORT/PATH)"
        ));
    }
    let parse_port = |port: &str| -> Result<u16, String> {
        port.parse().map_err(|_| {
            format!(
                "\"{raw}\": the port must be a number between 1 and 65535 (rule: http://HOST:PORT/PATH)"
            )
        })
    };
    let (host, port, bracketed) = if let Some(end) = authority.find(']') {
        // Bracketed IPv6 literal (`[::1]:PORT`).
        let Some(host) = authority.strip_prefix('[').map(|h| &h[..end - 1]) else {
            return Err(format!(
                "\"{raw}\": \"{authority}\" is not a valid host (rule: http://HOST:PORT/PATH)"
            ));
        };
        let rest = &authority[end + 1..];
        let port = if rest.is_empty() {
            80
        } else {
            parse_port(rest.strip_prefix(':').ok_or_else(|| {
                format!(
                    "\"{raw}\": \"{authority}\" is not a valid host (rule: http://HOST:PORT/PATH)"
                )
            })?)?
        };
        (host, port, true)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host, parse_port(port)?, false)
    } else {
        (authority, 80, false)
    };
    let valid_host = if bracketed {
        host.parse::<std::net::IpAddr>().is_ok()
    } else {
        !host.is_empty()
            && !host.contains(':')
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    if !valid_host {
        return Err(format!(
            "\"{raw}\": \"{host}\" is not a valid host (rule: http://HOST:PORT/PATH; an IPv6 literal must be [bracketed])"
        ));
    }
    Ok(AuthUrl {
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

/// htpasswd-format users of one rule (`user:hash` entries).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BasicUsers {
    entries: Vec<(String, String)>,
}

impl BasicUsers {
    /// Parses `user:hash` entries. Hash schemes: `$apr1$…` (Apache MD5,
    /// `openssl passwd -apr1`) and plain comparison (discouraged).
    /// Known-but-unsupported schemes are a config error naming the fix.
    pub fn parse(entries: &[String]) -> Result<BasicUsers, String> {
        let mut users = BasicUsers {
            entries: Vec::with_capacity(entries.len()),
        };
        for entry in entries {
            let (user, hash) = entry.split_once(':').ok_or_else(|| {
                format!(
                    "\"{entry}\" is missing the : between user and hash (rule: \"alice:$apr1$…\")"
                )
            })?;
            if user.is_empty() {
                return Err(format!(
                    "\"{entry}\" has an empty user (rule: \"alice:$apr1$…\")"
                ));
            }
            if hash.is_empty() {
                return Err(format!(
                    "\"{entry}\" has an empty hash (rule: \"alice:$apr1$…\")"
                ));
            }
            if let Some((scheme, name)) = UNSUPPORTED_SCHEMES
                .iter()
                .find(|(scheme, _)| hash.starts_with(scheme))
            {
                return Err(format!(
                    "\"{user}\" uses {name} ({scheme}…) which is not supported (fix: regenerate the entry with `openssl passwd -apr1`)"
                ));
            }
            if hash.starts_with("{") {
                return Err(format!(
                    "\"{user}\" uses an htpasswd brace scheme which is not supported (fix: regenerate the entry with `openssl passwd -apr1`)"
                ));
            }
            if hash.starts_with("$apr1$") {
                validate_apr1(hash).map_err(|why| format!("\"{user}\" {why}"))?;
            }
            if users.entries.iter().any(|(known, _)| known == user) {
                return Err(format!(
                    "user \"{user}\" is listed twice (rule: one entry per user)"
                ));
            }
            users.entries.push((user.to_owned(), hash.to_owned()));
        }
        Ok(users)
    }

    /// Verifies one credential pair in constant time per entry kind.
    #[must_use]
    pub fn verify(&self, user: &str, password: &str) -> bool {
        // An unknown user runs the same expensive path against a fixed
        // dummy hash (no enumeration oracle) and can never authorize:
        // the match is ANDed with `found`.
        const DUMMY_APR1: &str = "$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1";
        let found = self.entries.iter().find(|(known, _)| known == user);
        let hash = found.map_or(DUMMY_APR1, |(_, hash)| hash.as_str());
        let matched = if let Some(rest) = hash.strip_prefix("$apr1$") {
            let Some((salt, _digest)) = rest.split_once('$') else {
                return false;
            };
            ct_eq(
                apr1_hash(password.as_bytes(), salt.as_bytes()).as_bytes(),
                hash.as_bytes(),
            )
        } else {
            ct_eq(hash.as_bytes(), password.as_bytes())
        };
        matched && found.is_some()
    }
}

/// Extracts `Basic` credentials from request headers (the value is
/// `Basic base64(user:password)`). Missing, non-Basic, duplicated or
/// malformed input is `None` = no credentials.
#[must_use]
pub fn basic_credentials(headers: &[(String, String)]) -> Option<(String, String)> {
    let mut seen = None;
    for (name, value) in headers {
        if name == "authorization" {
            if seen.is_some() {
                return None;
            }
            seen = Some(value);
        }
    }
    let value = seen?;
    let (scheme, blob) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, blob.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    if user.is_empty() {
        return None;
    }
    Some((user.to_owned(), password.to_owned()))
}

/// Constant-time byte comparison (no early return on the first mismatch).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b) {
        diff |= usize::from(*x) ^ usize::from(*y);
    }
    diff == 0
}

/// `$apr1$salt$digest` shape: salt 1..=8 chars, digest 22 chars, both in
/// the crypt alphabet.
fn validate_apr1(hash: &str) -> Result<(), String> {
    let Some(rest) = hash.strip_prefix("$apr1$") else {
        return Err("is not a $apr1$hash (rule: \"$apr1$salt$22chars\")".to_owned());
    };
    let Some((salt, digest)) = rest.split_once('$') else {
        return Err("is not a complete $apr1$hash (rule: \"$apr1$salt$22chars\")".to_owned());
    };
    let alphabet = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '/';
    if salt.is_empty() || salt.len() > APR1_MAX_SALT || !salt.chars().all(alphabet) {
        return Err(format!(
            "has an invalid $apr1$ salt \"{salt}\" (rule: 1-8 letters, digits, '.' or '/')"
        ));
    }
    if digest.len() != 22 || !digest.chars().all(alphabet) {
        return Err(
            "has an invalid $apr1$ digest (rule: 22 chars of the crypt alphabet)".to_owned(),
        );
    }
    Ok(())
}

/// Verifies a password against a full `$apr1$salt$digest` string.
#[must_use]
pub fn apr1_verify(password: &str, hash: &str) -> bool {
    let Ok(()) = validate_apr1(hash) else {
        return false;
    };
    let Some(rest) = hash.strip_prefix("$apr1$") else {
        return false;
    };
    let Some((salt, _digest)) = rest.split_once('$') else {
        return false;
    };
    ct_eq(
        apr1_hash(password.as_bytes(), salt.as_bytes()).as_bytes(),
        hash.as_bytes(),
    )
}

/// Apache `$apr1$` (MD5-crypt with the `$apr1$` magic, 1000 rounds).
/// MD5 here is a password KDF, not a signature: collision resistance is
/// irrelevant to verifying a stored hash.
fn apr1_hash(password: &[u8], salt: &[u8]) -> String {
    let salt = &salt[..salt.len().min(APR1_MAX_SALT)];
    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(b"$apr1$");
    ctx.update(salt);

    let mut alt = Md5::new();
    alt.update(password);
    alt.update(salt);
    alt.update(password);
    let digest = alt.finalize().to_vec();

    let mut left = password.len();
    while left > 0 {
        ctx.update(&digest[..left.min(16)]);
        left = left.saturating_sub(16);
    }
    let mut left = password.len();
    while left > 0 {
        if left & 1 == 1 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[..1]);
        }
        left >>= 1;
    }
    let mut digest = ctx.finalize().to_vec();

    for round in 0..1000 {
        let mut ctx = Md5::new();
        if round & 1 == 1 {
            ctx.update(password);
        } else {
            ctx.update(&digest);
        }
        if round % 3 != 0 {
            ctx.update(salt);
        }
        if round % 7 != 0 {
            ctx.update(password);
        }
        if round & 1 == 1 {
            ctx.update(&digest);
        } else {
            ctx.update(password);
        }
        digest = ctx.finalize().to_vec();
    }

    let mut out = String::from("$apr1$");
    out.push_str(&String::from_utf8_lossy(salt));
    out.push('$');
    for &(b0, b1, b2, n) in &[
        (digest[0], digest[6], digest[12], 4usize),
        (digest[1], digest[7], digest[13], 4),
        (digest[2], digest[8], digest[14], 4),
        (digest[3], digest[9], digest[15], 4),
        (digest[4], digest[10], digest[5], 4),
        (0, 0, digest[11], 2),
    ] {
        let mut word = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for _ in 0..n {
            out.push(ITOA64[(word & 0x3f) as usize] as char);
            word >>= 6;
        }
    }
    out
}

/// crypt(3) base64 alphabet (least significant digit first).
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with `openssl passwd -apr1 -salt eqpr0xyS …` (OpenSSL 3.6).
    const SECRET_HASH: &str = "$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1";

    #[test]
    fn apr1_vectors_match_openssl() {
        assert!(apr1_verify("secret", SECRET_HASH), "openssl vector");
        assert!(!apr1_verify("wrongpass", SECRET_HASH), "wrong password");
        assert!(!apr1_verify("", SECRET_HASH), "empty password");
        let tampered = "$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo2";
        assert!(!apr1_verify("secret", tampered), "tampered digest");
        // The computed hash string is byte-for-byte the openssl one.
        assert_eq!(apr1_hash(b"secret", b"eqpr0xyS"), SECRET_HASH);
    }

    #[test]
    fn users_verify_htpasswd_entries() {
        let users = BasicUsers::parse(&[
            "alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1".to_owned(),
            "bob:plainpass".to_owned(),
        ])
        .expect("entries parse");
        assert!(users.verify("alice", "secret"), "apr1 user");
        assert!(!users.verify("alice", "nope"), "apr1 wrong password");
        assert!(users.verify("bob", "plainpass"), "plain user");
        assert!(!users.verify("bob", "plainpas"), "plain wrong password");
        assert!(!users.verify("carol", "secret"), "unknown user");
    }

    #[test]
    fn users_parse_rejects_unsupported_schemes_with_the_fix() {
        for entry in [
            "alice:$2y$05$abcdefghijklmnopqrstuv",
            "alice:$6$salt$hash",
            "alice:$1$salt$hash",
            "alice:{SHA}abcdef",
        ] {
            let err = BasicUsers::parse(&[entry.to_owned()])
                .expect_err("unsupported scheme must be rejected")
                .to_string();
            assert!(
                err.contains("openssl passwd -apr1"),
                "the error must name the fix: {err}"
            );
        }
    }

    #[test]
    fn users_parse_rejects_broken_entries_by_name() {
        for (entry, why) in [
            ("alice", "missing the :"),
            (":secret", "empty user"),
            ("alice:", "empty hash"),
            ("alice:$apr1$salt", "complete $apr1$hash"),
            ("alice:$apr1$toolongsalt$DDjQzF4.2qDil6v9iW4Xo1", "salt"),
            ("alice:$apr1$eqpr0xyS$short", "digest"),
        ] {
            let err = BasicUsers::parse(&[entry.to_owned()])
                .expect_err("broken entry must be rejected")
                .to_string();
            assert!(err.contains(why), "error must say {why:?}: {err}");
        }
        let err = BasicUsers::parse(&["alice:x".to_owned(), "alice:y".to_owned()])
            .expect_err("duplicate user")
            .to_string();
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn basic_credentials_parse_strictly() {
        let headers = |value: &str| vec![("authorization".to_owned(), value.to_owned())];
        let blob =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:secret");
        assert_eq!(
            basic_credentials(&headers(&format!("Basic {blob}"))),
            Some(("alice".to_owned(), "secret".to_owned()))
        );
        assert_eq!(
            basic_credentials(&headers(&format!("basic {blob}"))),
            Some(("alice".to_owned(), "secret".to_owned())),
            "the scheme is case-insensitive"
        );
        let with_colon =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:s:e:c");
        assert_eq!(
            basic_credentials(&headers(&format!("Basic {with_colon}"))),
            Some(("alice".to_owned(), "s:e:c".to_owned())),
            "the password may contain ':'"
        );
        assert_eq!(basic_credentials(&headers("Bearer token")), None);
        assert_eq!(basic_credentials(&headers("Basic !!!!")), None);
        assert_eq!(basic_credentials(&headers("Basic eA==")), None, "no ':'");
        assert_eq!(
            basic_credentials(&headers("Basic Og==")),
            None,
            "empty user"
        );
        assert_eq!(
            basic_credentials(&[
                ("authorization".to_owned(), format!("Basic {blob}")),
                ("authorization".to_owned(), format!("Basic {blob}")),
            ]),
            None,
            "duplicated authorization headers are ambiguous"
        );
        assert_eq!(basic_credentials(&[]), None);
    }

    #[test]
    fn auth_url_parsing_names_the_fix() {
        let url = parse_auth_url("http://Auth.Example:8080/verify?x=1").expect("url parses");
        assert_eq!(
            url,
            AuthUrl {
                host: "auth.example".to_owned(),
                port: 8080,
                path: "/verify?x=1".to_owned()
            }
        );
        assert_eq!(
            parse_auth_url("http://127.0.0.1/check").expect("url parses"),
            AuthUrl {
                host: "127.0.0.1".to_owned(),
                port: 80,
                path: "/check".to_owned()
            }
        );
        assert_eq!(
            parse_auth_url("http://[::1]:9000/").expect("url parses"),
            AuthUrl {
                host: "::1".to_owned(),
                port: 9000,
                path: "/".to_owned()
            }
        );
        let err = parse_auth_url("https://auth.example/verify")
            .expect_err("https is a declared gap")
            .to_string();
        assert!(err.contains("http:// only"), "{err}");
        for bad in [
            "auth.example:8080/x",
            "http://",
            "http://host:99999/",
            "http://::1:9000/",
            "http://host:port/",
            "",
        ] {
            parse_auth_url(bad).expect_err("must be rejected");
        }
    }
}
