//! Compression negotiation shared by the configuration gate and the
//! dataplane (B-N6/H6): media types and `Accept-Encoding` parsing live here so
//! the gate validates exactly the grammar the runtime applies.

/// Default media types: text and the structured types that dominate real
/// traffic. Binary formats (images, video, zip, wasm) are already compressed
/// and are not listed on purpose.
pub const DEFAULT_TYPES: [&str; 7] = [
    "text/*",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "image/svg+xml",
];

/// One allowed media type: `*/*`, `type/*` or `type/subtype`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaType {
    /// `*/*`
    Any,
    /// `type/*`
    Family(String),
    /// `type/subtype`
    Exact(String, String),
}

impl MediaType {
    /// Parses a configuration entry; the error names the accepted forms.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim().to_ascii_lowercase();
        if spec.is_empty() {
            return Err("an empty media type is not allowed".to_owned());
        }
        let mut parts = spec.split('/');
        let (Some(kind), Some(subtype), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!(
                "\"{spec}\" is not a media type: use `type/subtype`, `type/*` or `*/*`"
            ));
        };
        if !is_token(kind) || !is_token(subtype) {
            return Err(format!(
                "\"{spec}\" has characters outside the RFC 9110 token set"
            ));
        }
        if kind == "*" {
            return if subtype == "*" {
                Ok(Self::Any)
            } else {
                Err(format!("\"{spec}\" has an invalid wildcard: use `*/*`"))
            };
        }
        if subtype == "*" {
            return Ok(Self::Family(kind.to_owned()));
        }
        Ok(Self::Exact(kind.to_owned(), subtype.to_owned()))
    }

    /// Does this entry cover `content_type` (parameters ignored)?
    #[must_use]
    pub fn matches(&self, content_type: &str) -> bool {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let mut parts = essence.split('/');
        let (Some(kind), Some(subtype), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        match self {
            Self::Any => true,
            Self::Family(family) => kind == family,
            Self::Exact(entry_kind, entry_subtype) => {
                kind == entry_kind && subtype == entry_subtype
            }
        }
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str("*/*"),
            Self::Family(family) => write!(f, "{family}/*"),
            Self::Exact(kind, subtype) => write!(f, "{kind}/{subtype}"),
        }
    }
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A content coding this proxy can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `Content-Encoding: gzip` (RFC 1952), streamed with `flate2`.
    Gzip,
    /// `Content-Encoding: br` (RFC 7932), streamed with the pure-Rust
    /// `brotli` encoder.
    Brotli,
}

impl Encoding {
    /// The wire token used in `Content-Encoding` and `Accept-Encoding`.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
        }
    }
}

/// Codings enabled on one listener (resolved from the config block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnabledCodings {
    /// `gzip = true`
    pub gzip: bool,
    /// `brotli = true`
    pub brotli: bool,
}

impl EnabledCodings {
    /// Whether any coding is enabled at all.
    #[must_use]
    pub fn any(self) -> bool {
        self.gzip || self.brotli
    }
}

/// Quality (thousandths) the client assigned to `coding`, or `None` when the
/// header does not mention it and no wildcard applies. RFC 9110 §12.5.3
/// subset: the first explicit entry decides, `*` covers the rest, `q=0`
/// refuses, and malformed q-values are refusals.
fn coding_quality(header: &str, coding: &str) -> Option<u32> {
    let mut wildcard: Option<u32> = None;
    for part in header.split(',') {
        let mut pieces = part.split(';');
        let token = pieces.next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        let mut quality = 1000u32;
        for parameter in pieces {
            let parameter = parameter.trim();
            if let Some((name, value)) = parameter.split_once('=')
                && name.trim().eq_ignore_ascii_case("q")
            {
                quality = parse_quality(value.trim());
            }
        }
        if token.eq_ignore_ascii_case(coding) {
            return Some(quality);
        }
        if token == "*" {
            wildcard = Some(quality);
        }
    }
    wildcard
}

/// Chooses the coding to use for one response, or `None` for identity.
///
/// The highest q-value wins; on a tie Brotli is preferred (it is smaller for
/// the same body at a similar cost, and that is the whole point of offering
/// it). A coding the listener did not enable is never selected, even when the
/// client asks for it.
#[must_use]
pub fn choose_encoding(header: Option<&str>, enabled: EnabledCodings) -> Option<Encoding> {
    let header = header?;
    let quality = |coding: &str| coding_quality(header, coding).unwrap_or(0);
    let gzip = if enabled.gzip { quality("gzip") } else { 0 };
    let brotli = if enabled.brotli { quality("br") } else { 0 };
    match (brotli > 0, gzip > 0) {
        (true, true) if brotli >= gzip => Some(Encoding::Brotli),
        (true, true) => Some(Encoding::Gzip),
        (true, false) => Some(Encoding::Brotli),
        (false, true) => Some(Encoding::Gzip),
        (false, false) => None,
    }
}

/// Does the client accept `gzip`?
#[must_use]
pub fn accepts_gzip(header: Option<&str>) -> bool {
    choose_encoding(
        header,
        EnabledCodings {
            gzip: true,
            brotli: false,
        },
    )
    .is_some()
}

/// `qvalue` in thousandths; anything malformed is treated as "not acceptable"
/// (a client that sends nonsense is never served a coding it may not want).
fn parse_quality(value: &str) -> u32 {
    if value.is_empty() || value.len() > 5 {
        return 0;
    }
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if !whole.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    let whole: u32 = whole.parse().unwrap_or(0);
    if whole > 1 {
        return 0;
    }
    let mut thousandths = whole * 1000;
    if let Some(fraction) = fraction {
        if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return 0;
        }
        let mut digits = fraction.to_owned();
        while digits.len() < 3 {
            digits.push('0');
        }
        thousandths += digits.parse().unwrap_or(0);
        if thousandths > 1000 {
            return 0;
        }
    }
    thousandths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q_values_decide_like_rfc_9110() {
        for accepted in [
            "gzip",
            "gzip, deflate, br",
            "GZIP;Q=0.5",
            "deflate, gzip;q=0.001",
            "*",
            "*;q=0.2",
            "identity, *;q=0.1",
        ] {
            assert!(accepts_gzip(Some(accepted)), "{accepted} must accept gzip");
        }
        for refused in [
            "gzip;q=0",
            "gzip;q=0.000",
            "gzip;q=0, *",
            "gzip;q=0, gzip;q=1",
            "deflate, br",
            "",
            "gzip;q=bogus",
            "gzip;q=2",
            "gzip;q=0.1234",
        ] {
            assert!(!accepts_gzip(Some(refused)), "{refused} must refuse gzip");
        }
        assert!(!accepts_gzip(None), "no Accept-Encoding means identity");
    }

    #[test]
    fn brotli_wins_ties_and_q_values_order_the_choice() {
        let both = EnabledCodings {
            gzip: true,
            brotli: true,
        };
        let gzip_only = EnabledCodings {
            gzip: true,
            brotli: false,
        };
        let brotli_only = EnabledCodings {
            gzip: false,
            brotli: true,
        };
        assert_eq!(
            choose_encoding(Some("gzip, br"), both),
            Some(Encoding::Brotli)
        );
        assert_eq!(
            choose_encoding(Some("br;q=0.5, gzip;q=0.6"), both),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            choose_encoding(Some("br;q=0.9, gzip;q=0.5"), both),
            Some(Encoding::Brotli)
        );
        // An explicit refusal is stronger than a wildcard.
        assert_eq!(
            choose_encoding(Some("br;q=0, *"), both),
            Some(Encoding::Gzip)
        );
        // A coding the listener did not enable is never selected.
        assert_eq!(choose_encoding(Some("br"), gzip_only), None);
        assert_eq!(choose_encoding(Some("gzip"), brotli_only), None);
        assert_eq!(
            choose_encoding(Some("*"), brotli_only),
            Some(Encoding::Brotli)
        );
        assert_eq!(choose_encoding(Some("*"), gzip_only), Some(Encoding::Gzip));
        assert_eq!(choose_encoding(Some("identity"), both), None);
        assert_eq!(choose_encoding(Some("br;q=bogus"), both), None);
        assert_eq!(choose_encoding(None, both), None);
    }

    #[test]
    fn media_types_match_families_exact_and_any() {
        let text = MediaType::parse("text/*").unwrap();
        assert!(text.matches("text/html; charset=utf-8"));
        assert!(text.matches("TEXT/PLAIN"));
        assert!(!text.matches("application/json"));
        let json = MediaType::parse("application/json").unwrap();
        assert!(json.matches("application/json;charset=utf-8"));
        assert!(!json.matches("application/jsonx"));
        assert!(MediaType::parse("*/*").unwrap().matches("image/png"));
        assert!(MediaType::parse("text").is_err());
        assert!(MediaType::parse("text/").is_err());
        assert!(MediaType::parse("*/json").is_err());
        assert!(MediaType::parse("te xt/html").is_err());
    }
}
