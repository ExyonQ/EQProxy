//! Hot data maps (C10 / PP-02): named `key → value` tables that routing
//! rules can consult, loaded from a file and **swappable in hot** without
//! touching the running dataplane.
//!
//! Semantics are defined once here (Q8) and never silently changed:
//!
//! - A map entry matches by **literal key** (byte-for-byte; no
//!   normalization, no CIDR, no wildcards). The key is selected from the
//!   request with [`MapKey`]; a missing request header produces the
//!   empty key, which never matches an entry (keys are never empty).
//! - Lookup returns the mapped value, or the map's `default` when the
//!   key has no entry (like nginx `map`'s `default`). A map without a
//!   `default` has no value for absent keys.
//! - The file format is line oriented: `key value` separated by
//!   whitespace (the value is the rest of the line, trimmed — it may
//!   contain spaces), a bare `key` maps to `""`, blank lines are
//!   skipped and `#` starts a comment **at line start only** (values may
//!   contain `#`). Duplicate keys are an error naming both lines: never
//!   a silent last-wins (H4).
//! - Hot updates swap the whole table atomically ([`HotMap::replace`]):
//!   readers see either the old or the new data, never a mix. The rules
//!   and the rest of the dataplane state (counters, buckets, pools) are
//!   untouched — that is the whole point (PP-02).
//!
//! Budgets (ADR-0002 style, enforced here and in the config gate):
//! [`MAX_MAP_ENTRIES`] per map, [`MAX_MAP_KEY_BYTES`] per key,
//! [`MAX_MAP_VALUE_BYTES`] per value and [`MAX_MAP_FILE_BYTES`] per
//! file.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::rules::RequestFacts;

/// Resource budget: maximum entries in one map.
pub const MAX_MAP_ENTRIES: usize = 200_000;

/// Resource budget: maximum size of one key.
pub const MAX_MAP_KEY_BYTES: usize = 256;

/// Resource budget: maximum size of one value.
pub const MAX_MAP_VALUE_BYTES: usize = 4096;

/// Resource budget: maximum size of one map file.
pub const MAX_MAP_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Why a map could not be loaded (cause + example; the config layer adds
/// the field and the file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapError {
    /// 1-based line of the offending entry (None for inline entries).
    pub line: Option<usize>,
    /// Why it is invalid.
    pub cause: String,
    /// A concrete valid value (actionable errors, never a bare dump).
    pub example: String,
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.cause),
            None => f.write_str(&self.cause),
        }
    }
}

impl std::error::Error for MapError {}

fn map_err(line: Option<usize>, cause: impl Into<String>, example: impl Into<String>) -> MapError {
    MapError {
        line,
        cause: cause.into(),
        example: example.into(),
    }
}

/// Validates one map key (shared by the file parser and the config gate).
pub fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the key is empty (example key: \"acme\")".to_owned());
    }
    if key.len() > MAX_MAP_KEY_BYTES {
        return Err(format!(
            "key {key:?} is {} bytes (maximum {MAX_MAP_KEY_BYTES})",
            key.len()
        ));
    }
    if key.chars().any(char::is_whitespace) {
        return Err(format!(
            "key {key:?} contains whitespace (keys are single tokens)"
        ));
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("key {key:?} contains control characters"));
    }
    Ok(())
}

/// Validates one map value (shared by the file parser and the config
/// gate). Values may be empty (presence-style maps).
pub fn validate_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_MAP_VALUE_BYTES {
        return Err(format!(
            "value is {} bytes (maximum {MAX_MAP_VALUE_BYTES})",
            value.len()
        ));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("value contains control characters".to_owned());
    }
    Ok(())
}

/// One immutable snapshot of a map's data ([`HotMap`] swaps these in
/// hot). `hash` fingerprints the source bytes so the file watcher can
/// detect changes without re-parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapData {
    entries: HashMap<String, String>,
    default: Option<String>,
    hash: u64,
}

impl MapData {
    /// Parses map text: `key value` per line (see the module docs).
    pub fn parse(text: &str, default: Option<String>) -> Result<Self, MapError> {
        if let Some(value) = &default {
            validate_value(value).map_err(|why| map_err(None, why, "default = \"deny\""))?;
        }
        let body = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut entries: HashMap<String, String> = HashMap::new();
        let mut first_line: HashMap<String, usize> = HashMap::new();
        for (index, raw) in body.lines().enumerate() {
            let line_no = index + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (key, value) = match trimmed.split_once(char::is_whitespace) {
                Some((key, rest)) => (key, rest.trim()),
                None => (trimmed, ""),
            };
            validate_key(key).map_err(|why| map_err(Some(line_no), why, "acme premium"))?;
            validate_value(value)
                .map_err(|why| map_err(Some(line_no), why, "acme premium (value = one line)"))?;
            if let Some(prev) = first_line.get(key) {
                return Err(map_err(
                    Some(line_no),
                    format!("duplicate key {key:?} (first defined at line {prev})"),
                    "each key appears exactly once in the file",
                ));
            }
            first_line.insert(key.to_owned(), line_no);
            if entries.len() >= MAX_MAP_ENTRIES {
                return Err(map_err(
                    Some(line_no),
                    format!("too many entries (maximum {MAX_MAP_ENTRIES})"),
                    format!("split the data into at most {MAX_MAP_ENTRIES} entries per map"),
                ));
            }
            entries.insert(key.to_owned(), value.to_owned());
        }
        Ok(Self {
            entries,
            default,
            hash: fingerprint(text.as_bytes()),
        })
    }

    /// Parses raw file bytes (UTF-8; a leading BOM is ignored).
    pub fn parse_bytes(bytes: &[u8], default: Option<String>) -> Result<Self, MapError> {
        let text = std::str::from_utf8(bytes).map_err(|_| {
            map_err(
                None,
                "the file is not valid UTF-8",
                "save the map file as UTF-8 text",
            )
        })?;
        let mut data = Self::parse(text, default)?;
        data.hash = fingerprint(bytes);
        Ok(data)
    }

    /// Builds a map from inline `[maps.*.entries]` config (no file).
    pub fn from_entries(
        entries: &BTreeMap<String, String>,
        default: Option<String>,
    ) -> Result<Self, MapError> {
        if entries.len() > MAX_MAP_ENTRIES {
            return Err(map_err(
                None,
                format!(
                    "too many entries: {} (maximum {MAX_MAP_ENTRIES})",
                    entries.len()
                ),
                format!("split the data into at most {MAX_MAP_ENTRIES} entries per map"),
            ));
        }
        if let Some(value) = &default {
            validate_value(value).map_err(|why| map_err(None, why, "default = \"deny\""))?;
        }
        for (key, value) in entries {
            validate_key(key).map_err(|why| map_err(None, why, "acme = \"premium\""))?;
            validate_value(value).map_err(|why| map_err(None, why, "acme = \"premium\""))?;
        }
        Ok(Self {
            entries: entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            default,
            hash: 0,
        })
    }

    /// The mapped value, or `default` when the key has no entry.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&str> {
        self.entries
            .get(key)
            .map(String::as_str)
            .or(self.default.as_deref())
    }

    /// Number of explicit entries (the `default` is not counted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the map has no explicit entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The configured `default` (for re-parses after a file change).
    #[must_use]
    pub fn default_value(&self) -> Option<&String> {
        self.default.as_ref()
    }

    /// Fingerprint of the source bytes (change detection).
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.hash
    }
}

/// FNV-1a fingerprint of raw source bytes (change detection only —
/// never a security primitive).
#[must_use]
pub fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One named map with **hot-swappable** data (C10/PP-02): readers take
/// the current snapshot with [`Self::get`], the file watcher (or a
/// config reload) installs a new one with [`Self::replace`] — atomically
/// and without touching the rules or any other dataplane state.
#[derive(Debug)]
pub struct HotMap {
    name: String,
    file: Option<PathBuf>,
    reload_interval: Duration,
    data: RwLock<Arc<MapData>>,
}

impl HotMap {
    /// A map backed by `file` (watched every `reload_interval`;
    /// `ZERO` = load once) or by static inline data (`file = None`).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        data: MapData,
        file: Option<PathBuf>,
        reload_interval: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            file,
            reload_interval,
            data: RwLock::new(Arc::new(data)),
        })
    }

    /// The data in force right now (one consistent snapshot).
    #[must_use]
    pub fn get(&self) -> Arc<MapData> {
        Arc::clone(
            &self
                .data
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Installs new data atomically (hot update).
    pub fn replace(&self, data: MapData) {
        *self
            .data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(data);
    }

    /// Hot update from new source bytes (the file watcher's path):
    /// parses with the map's `default` and swaps atomically. On error
    /// the current data keeps serving untouched (C10: a bad update
    /// never breaks live traffic).
    pub fn update_bytes(&self, bytes: &[u8]) -> Result<(), MapError> {
        let default = self.get().default_value().cloned();
        let data = MapData::parse_bytes(bytes, default)?;
        self.replace(data);
        Ok(())
    }

    /// Map name (config key of `[maps.*]`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Source file to watch (None = inline, static data).
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// File re-read period (ZERO = load once, no watcher).
    #[must_use]
    pub fn reload_interval(&self) -> Duration {
        self.reload_interval
    }

    /// One-line summary for `config explain`.
    #[must_use]
    pub fn describe(&self) -> String {
        let data = self.get();
        let source = match &self.file {
            Some(file) => format!(
                "file {:?}, reload {}ms",
                file.display(),
                self.reload_interval.as_millis()
            ),
            None => "inline entries, static".to_owned(),
        };
        format!("{} entries ({source})", data.len())
    }
}

/// All named maps of one config generation: what rules consult by name
/// (empty is the common case — `MapRegistry::empty()`).
#[derive(Debug, Default)]
pub struct MapRegistry {
    maps: BTreeMap<String, Arc<HotMap>>,
}

impl MapRegistry {
    /// A registry without maps.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
        }
    }

    /// Shared empty registry for code paths without maps (tests, sims).
    #[must_use]
    pub fn empty() -> &'static MapRegistry {
        static EMPTY: MapRegistry = MapRegistry::new();
        &EMPTY
    }

    /// Registers a map under its name.
    pub fn insert(&mut self, map: Arc<HotMap>) {
        self.maps.insert(map.name().to_owned(), map);
    }

    /// The map with this name, if the config defines it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<HotMap>> {
        self.maps.get(name)
    }

    /// Every registered map (watchers and `explain` iterate them).
    pub fn iter(&self) -> impl Iterator<Item = &Arc<HotMap>> {
        self.maps.values()
    }

    /// True when the config defines no maps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// Number of defined maps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.maps.len()
    }
}

/// Where a rule's map condition takes its key from (B-I11 canary and
/// C10 lookups alike; the selectors are the request facts the engine
/// already exposes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapKey {
    /// Effective client address (the PROXY v1 claim when reception is on).
    Ip,
    /// Host header (lowercased, `:port` stripped — same as `host` rules).
    Host,
    /// Request path (query string excluded).
    Path,
    /// Request method.
    Method,
    /// First value of this request header (case-insensitive name).
    Header(String),
}

impl MapKey {
    /// Parses the `key = "…"` selector of a map condition.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "ip" => Ok(Self::Ip),
            "host" => Ok(Self::Host),
            "path" => Ok(Self::Path),
            "method" => Ok(Self::Method),
            _ => Err(format!(
                "{raw:?} is not a valid key source (valid: \"ip\", \"host\", \"path\", \"method\"; or set header = \"name\")"
            )),
        }
    }

    /// The map key for one request. A header selector without that
    /// header produces the empty key (which never matches an entry).
    #[must_use]
    pub fn select(&self, facts: &RequestFacts<'_>) -> String {
        match self {
            Self::Ip => facts.peer.to_string(),
            Self::Host => crate::rules::host_key(facts.host),
            Self::Path => facts.path.to_owned(),
            Self::Method => facts.method.to_owned(),
            Self::Header(name) => facts
                .headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_comments_bare_keys_and_default() {
        let data = MapData::parse(
            "\u{feff}# comment\n\nacme premium\nbare-key\nspaced   value with spaces  \n",
            Some("free".to_owned()),
        )
        .expect("parses");
        assert_eq!(data.lookup("acme"), Some("premium"));
        assert_eq!(data.lookup("bare-key"), Some(""));
        assert_eq!(data.lookup("spaced"), Some("value with spaces"));
        assert_eq!(
            data.lookup("absent"),
            Some("free"),
            "default fills absent keys"
        );
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn hash_fingerprints_the_source_bytes() {
        let one = MapData::parse_bytes(b"a 1\n", None).expect("parse");
        let same = MapData::parse_bytes(b"a 1\n", None).expect("parse");
        let other = MapData::parse_bytes(b"a 2\n", None).expect("parse");
        assert_eq!(one.hash(), same.hash());
        assert_ne!(one.hash(), other.hash());
    }

    #[test]
    fn duplicate_keys_error_names_both_lines() {
        let err = MapData::parse("a 1\nb 2\na 3\n", None).expect_err("dup");
        assert_eq!(err.line, Some(3));
        assert!(err.cause.contains("duplicate key \"a\""), "{err}");
        assert!(err.cause.contains("line 1"), "{err}");
    }

    #[test]
    fn bad_keys_and_values_name_the_line_and_the_fix() {
        let err = MapData::parse(&format!("{} v\n", "k".repeat(MAX_MAP_KEY_BYTES + 1)), None)
            .expect_err("long key");
        assert!(err.cause.contains("maximum"), "{err}");
        let err = MapData::parse(
            &format!("k {}\n", "v".repeat(MAX_MAP_VALUE_BYTES + 1)),
            None,
        )
        .expect_err("long value");
        assert!(err.cause.contains("maximum"), "{err}");
        let err = MapData::parse("k v\ttab\n", None).expect_err("control char");
        assert!(err.cause.contains("control"), "{err}");
        let err =
            MapData::parse("k v\n", Some("bad\tdefault".to_owned())).expect_err("bad default");
        assert!(err.line.is_none(), "the default is not a file line: {err}");
    }

    #[test]
    fn entry_budget_is_enforced() {
        let mut text = String::new();
        for i in 0..=MAX_MAP_ENTRIES {
            text.push_str(&format!("k{i} v\n"));
        }
        let err = MapData::parse(&text, None).expect_err("too many");
        assert!(err.cause.contains("too many entries"), "{err}");
    }

    #[test]
    fn inline_entries_validate_shapes_and_defaults() {
        let mut entries = BTreeMap::new();
        entries.insert("acme".to_owned(), "premium".to_owned());
        let data = MapData::from_entries(&entries, Some("free".to_owned())).expect("inline map");
        assert_eq!(data.lookup("acme"), Some("premium"));
        assert_eq!(data.lookup("other"), Some("free"));

        let mut bad = BTreeMap::new();
        bad.insert("has space".to_owned(), "x".to_owned());
        let err = MapData::from_entries(&bad, None).expect_err("bad key");
        assert!(err.cause.contains("whitespace"), "{err}");
    }

    #[test]
    fn hot_map_swaps_atomically_and_describes() {
        let map = HotMap::new(
            "tiers",
            MapData::parse("a 1\n", None).expect("parse"),
            Some(PathBuf::from("tiers.map")),
            Duration::from_millis(500),
        );
        assert_eq!(map.get().lookup("a"), Some("1"));
        map.replace(MapData::parse("a 2\nb 3\n", None).expect("parse"));
        let after = map.get();
        assert_eq!(after.lookup("a"), Some("2"));
        assert_eq!(after.lookup("b"), Some("3"));
        assert!(
            map.describe().starts_with("2 entries ("),
            "{}",
            map.describe()
        );
    }

    #[test]
    fn update_bytes_keeps_the_default_and_keeps_last_good_on_error() {
        let map = HotMap::new(
            "t",
            MapData::parse("a 1\n", Some("free".to_owned())).expect("parse"),
            Some(PathBuf::from("t.map")),
            Duration::from_secs(5),
        );
        map.update_bytes(b"a 2\nb 3\n").expect("hot update");
        assert_eq!(map.get().lookup("a"), Some("2"));
        assert_eq!(map.get().lookup("z"), Some("free"), "default survives");

        let bad = map.update_bytes(b"a 1\na 2\n");
        assert!(bad.is_err(), "duplicate keys must reject the update");
        assert_eq!(
            map.get().lookup("a"),
            Some("2"),
            "a bad update keeps the last good data"
        );
    }

    #[test]
    fn map_key_selects_from_request_facts() {
        let headers = vec![
            ("x-tenant".to_owned(), "acme".to_owned()),
            ("cookie".to_owned(), "sid=1".to_owned()),
        ];
        let facts = RequestFacts {
            method: "GET",
            host: "API.Example.com:8443",
            path: "/v1/x",
            headers: &headers,
            peer: "10.1.2.3".parse().expect("ip"),
            maps: MapRegistry::empty(),
        };
        assert_eq!(MapKey::Ip.select(&facts), "10.1.2.3");
        assert_eq!(MapKey::Host.select(&facts), "api.example.com");
        assert_eq!(MapKey::Path.select(&facts), "/v1/x");
        assert_eq!(MapKey::Method.select(&facts), "GET");
        assert_eq!(MapKey::Header("X-Tenant".to_owned()).select(&facts), "acme");
        assert_eq!(MapKey::Header("x-missing".to_owned()).select(&facts), "");
    }

    #[test]
    fn map_key_parse_names_the_valid_sources() {
        for good in ["ip", "host", "path", "method"] {
            assert!(MapKey::parse(good).is_ok(), "{good}");
        }
        let err = MapKey::parse("uri").expect_err("no uri selector");
        assert!(err.contains("\"ip\""), "{err}");
    }
}
