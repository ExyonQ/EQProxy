//! HTTP response cache (B-N7/H1) — ADR-0034.
//!
//! The honest-cache lesson from the HAProxy critique (H1): a cache that
//! stores session responses, keys on cookies or hides its content blocks
//! migrations instead of enabling them. Every guarantee below is a test:
//!
//! - only `GET` is stored (`HEAD` is served from a `GET` entry, headers
//!   only); anything else bypasses;
//! - a request carrying `Cookie`, `Authorization` or `Range`, or
//!   `Cache-Control: no-store`, never looks up nor stores;
//! - a response with `Set-Cookie` is never stored;
//! - the key never contains session material: method, scheme, host, target
//!   plus the values of the `Vary`-listed request headers. `Vary: *` or a
//!   `Vary` over `Cookie`/`Authorization` makes the response unstorable;
//! - backends with cookie affinity bypass the cache at runtime (a cached
//!   answer would steal the pinning cookie);
//! - stale entries revalidate with `If-None-Match`/`If-Modified-Since`; a
//!   `304` refreshes the headers without touching the body;
//! - one origin fetch per key at a time (cache-lock): concurrent requests
//!   for the same key wait on the in-flight fetch instead of stampeding;
//! - optional write-through disk persistence; expired or corrupt files are
//!   skipped and counted, never trusted;
//! - the content is visible: `GET /api/v1/cache` lists entries with age,
//!   TTL, hits and size, and every served response carries `X-Cache`.
//!
//! Deliberately out of v1 (documented, not silent): `stale-while-revalidate`
//! (a stale entry never serves while another task revalidates; waiters block
//! on the lock), `stale-if-error`, `only-if-cached`, `Pragma`, `Vary` value
//! folding beyond exact trimmed match, and client `If-Modified-Since`
//! evaluation (only `If-None-Match` earns a client-side `304`).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::Notify;

use eqproxy_core::Metrics;

use crate::http2::is_hop_by_hop;

/// Statuses a cache entry may hold. Anything else (notably `206` partial
/// replies and `302` session redirects) streams through uncached.
const STORABLE_STATUSES: [u16; 5] = [200, 301, 308, 404, 410];

/// Request headers that force a bypass: session identity (`cookie`,
/// `authorization`) can never be a cache key, and a byte range is never
/// coalesced with the full body.
const BYPASS_REQUEST_HEADERS: [&str; 3] = ["cookie", "authorization", "range"];

/// `Vary` names that make a response unstorable: the variant key would be
/// session identity.
const UNKEYABLE_VARY: [&str; 2] = ["cookie", "authorization"];

/// Response header that forbids storage outright (H1: nobody sees a session
/// that is not theirs).
const SET_COOKIE: &str = "set-cookie";

/// Headers the cache manages itself on serve and never stores: framing is
/// recomputed from the stored body, and `x-cache`/`age` describe the serve,
/// not the stored response (a stored `MISS` marker must never leak into a
/// later `HIT`).
const MANAGED_HEADERS: [&str; 4] = ["content-length", "transfer-encoding", "x-cache", "age"];

/// Maximum objects the admin snapshot lists per listener (bounded output).
const MAX_SNAPSHOT_OBJECTS: usize = 128;

/// Fixed per-entry memory overhead added to the accounting (struct fields
/// and allocator slack beyond the counted bytes).
const ENTRY_OVERHEAD_BYTES: usize = 256;

/// Disk format magic (`EQC1`).
const DISK_MAGIC: [u8; 4] = *b"EQC1";

/// Upper bound the loader reads from one file: the largest storable body
/// plus headroom for heads. Anything bigger is skipped, never trusted.
const DISK_READ_CAP: usize = 67_108_864 + 1_048_576;

/// `None` marker for optional strings in the disk format.
const DISK_NONE: u32 = u32::MAX;

/// Settings a listener cache is built from (validated bounds live in
/// `eqproxy-config`; this struct carries the already-gated values).
#[derive(Debug, Clone)]
pub struct CacheSettings {
    /// Listener name (admin reports and log lines).
    pub listener: String,
    /// Fresh lifetime when the origin gives no tighter bound.
    pub default_ttl: Duration,
    /// RAM budget for stored entries.
    pub max_memory_bytes: usize,
    /// Largest single response body kept.
    pub max_entry_bytes: usize,
    /// Persistence directory (`None` = memory only).
    pub disk_dir: Option<PathBuf>,
    /// How long a cache-lock waiter blocks before fetching on its own.
    pub lock_wait: Duration,
}

impl CacheSettings {
    /// Defaults for tests and callers that only override one knob.
    #[must_use]
    pub fn test_defaults() -> Self {
        Self {
            listener: "test".to_owned(),
            default_ttl: Duration::from_secs(60),
            max_memory_bytes: 64 * 1024 * 1024,
            max_entry_bytes: 1024 * 1024,
            disk_dir: None,
            lock_wait: Duration::from_secs(60),
        }
    }
}

/// Base cache key: everything that is not content negotiation. Variants of
/// one base key differ in their `Vary` values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Always `GET`: a `HEAD` is served from the `GET` entry, headers only.
    pub method: &'static str,
    pub scheme: String,
    pub host: String,
    pub target: String,
}

/// One stored response (the origin bytes, before per-request processing).
/// Public so the proxy engine can serve it; constructed only by [`Cache`].
pub struct StoredEntry {
    pub(crate) status: u16,
    /// Sanitized reason phrase (visible ASCII, capped).
    pub(crate) reason: String,
    /// End-to-end headers, lowercased names, hop-by-hop and framing headers
    /// already removed.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
    pub(crate) vary: Vec<String>,
    pub(crate) vary_values: Vec<String>,
    /// The origin response had no body framing (`BodyFraming::None`):
    /// compression eligibility must match the origin path exactly.
    pub(crate) framing_none: bool,
    /// The origin declared `Content-Length`: the assembled serve passes a
    /// known length to the compressor, like the origin path did.
    pub(crate) has_declared_len: bool,
    pub(crate) stored_at: Instant,
    pub(crate) stored_at_unix: u64,
    pub(crate) ttl: Duration,
    /// Times this entry was served to a client (incremented by the proxy,
    /// not by lookups, so the admin view counts serves).
    pub(crate) hits: AtomicU64,
    pub(crate) last_used: Mutex<Instant>,
}

impl StoredEntry {
    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.stored_at)
    }

    fn fresh(&self, now: Instant) -> bool {
        self.age(now) < self.ttl
    }

    /// Seconds since the entry was (re)stored, for the served `Age`.
    pub(crate) fn age_secs(&self) -> u64 {
        self.age(Instant::now()).as_secs()
    }

    /// Compression eligibility must match the origin path exactly.
    pub(crate) fn framing_none(&self) -> bool {
        self.framing_none
    }

    /// Known length for the compressor when the origin declared one.
    pub(crate) fn declared_len(&self) -> Option<u64> {
        self.has_declared_len.then_some(self.body.len() as u64)
    }

    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    fn note_use(&self, now: Instant) {
        if let Ok(mut used) = self.last_used.lock() {
            *used = now;
        }
    }

    fn weight(&self) -> usize {
        self.body.len()
            + self
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
            + self.vary.iter().map(String::len).sum::<usize>()
            + self.vary_values.iter().map(String::len).sum::<usize>()
            + ENTRY_OVERHEAD_BYTES
    }
}

/// What a lookup finds.
pub enum Lookup {
    /// Fresh entry: serve it without dialing.
    Hit(Arc<StoredEntry>),
    /// Nothing stored (or nothing matching): this caller owns the origin
    /// fetch and the key is now marked in-flight.
    Fetch,
    /// Stale entry with validators: this caller owns the conditional
    /// revalidation and the key is now marked in-flight.
    Revalidate(Arc<StoredEntry>),
    /// Another task owns the fetch: wait on the shared slot.
    Wait(Arc<SharedFetch>),
}

/// Shared slot of one in-flight origin fetch (cache-lock).
pub struct SharedFetch {
    notify: Notify,
    result: Mutex<Option<FetchResult>>,
}

/// What the fetch owner publishes to the waiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchResult {
    /// The store holds a fresh entry again: look it up (the waiter's own
    /// variant may differ from the owner's).
    Ready,
    /// The fetch failed or its response was unstorable: fetch directly.
    Gone,
}

/// Outcome the fetch owner reports back to the cache.
pub enum FetchOutcome {
    /// A storable response: insert, persist and publish `Ready`.
    Stored(StoredParts),
    /// Failure or unstorable response: drop the stale entry (if any) and
    /// publish `Gone`, so waiters fetch directly instead of revalidating a
    /// corpse in a loop.
    Gone,
}

/// Fields of a response the proxy hands to the store.
pub struct StoredParts {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub vary: Vec<String>,
    pub vary_values: Vec<String>,
    pub framing_none: bool,
    pub has_declared_len: bool,
    pub ttl: Duration,
    pub stored_at_unix: u64,
}

/// Why a request bypassed the cache (counted, never logged per request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bypass {
    Method,
    Body,
    SessionHeader,
    NoStore,
    CookieAffinity,
    UnparseableHead,
}

struct Store {
    /// Base key → variants (one per `Vary` combination).
    map: HashMap<CacheKey, Vec<Arc<StoredEntry>>>,
    inflight: HashMap<CacheKey, Arc<SharedFetch>>,
    bytes: usize,
}

/// The per-listener response cache.
pub struct Cache {
    settings: CacheSettings,
    metrics: Arc<Metrics>,
    inner: Mutex<Store>,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("listener", &self.settings.listener)
            .finish_non_exhaustive()
    }
}

impl Cache {
    /// Builds the cache and reloads the disk synchronously (like
    /// [`crate::plugin::PluginHost::load`]: a bad directory rejects the
    /// snapshot instead of failing per request). Expired or corrupt files
    /// are skipped and counted.
    pub fn load(settings: CacheSettings, metrics: Arc<Metrics>) -> std::io::Result<Arc<Self>> {
        if let Some(dir) = &settings.disk_dir {
            std::fs::create_dir_all(dir)?;
        }
        let cache = Arc::new(Self {
            settings,
            metrics,
            inner: Mutex::new(Store {
                map: HashMap::new(),
                inflight: HashMap::new(),
                bytes: 0,
            }),
        });
        cache.reload_disk();
        Ok(cache)
    }

    /// RAM budget for one stored body; larger bodies stream uncached.
    pub(crate) fn max_entry_bytes(&self) -> usize {
        self.settings.max_entry_bytes
    }

    /// Fresh lifetime when the origin gives no tighter bound.
    pub(crate) fn default_ttl(&self) -> Duration {
        self.settings.default_ttl
    }

    /// Looks a key up: fresh entries hit, stale entries with validators
    /// revalidate under the lock, everything else fetches under the lock.
    /// `force_revalidate` (a client `no-cache`) turns a fresh hit into a
    /// revalidation when validators exist, or a fetch when they do not.
    /// The request headers select the `Vary` variant, so the caller never
    /// needs to know the stored variant names.
    pub fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &[(String, String)],
        force_revalidate: bool,
    ) -> Lookup {
        let now = Instant::now();
        let mut inner = self.lock();
        let matched: Option<Arc<StoredEntry>> = inner.map.get(key).and_then(|variants| {
            variants
                .iter()
                .find(|entry| vary_values(req_headers, &entry.vary) == entry.vary_values)
                .cloned()
        });
        if let Some(entry) = matched {
            entry.note_use(now);
            if entry.fresh(now) && !force_revalidate {
                return Lookup::Hit(entry);
            }
            if entry.etag.is_some() || entry.last_modified.is_some() {
                if let Some(shared) = inner.inflight.get(key) {
                    return Lookup::Wait(Arc::clone(shared));
                }
                let shared = Arc::new(SharedFetch {
                    notify: Notify::new(),
                    result: Mutex::new(None),
                });
                inner.inflight.insert(key.clone(), Arc::clone(&shared));
                return Lookup::Revalidate(entry);
            }
        }
        if let Some(shared) = inner.inflight.get(key) {
            return Lookup::Wait(Arc::clone(shared));
        }
        let shared = Arc::new(SharedFetch {
            notify: Notify::new(),
            result: Mutex::new(None),
        });
        inner.inflight.insert(key.clone(), Arc::clone(&shared));
        Lookup::Fetch
    }

    /// Waits for the owner's fetch (cache-lock). `None` is a lock timeout:
    /// the waiter fetches on its own rather than piling up behind a stuck
    /// fetch. `Some(Gone)` is a failed or unstorable fetch: same fallback.
    pub async fn wait(&self, shared: &SharedFetch) -> Option<FetchResult> {
        let notified =
            tokio::time::timeout(self.settings.lock_wait, shared.notify.notified()).await;
        if notified.is_err() {
            return None;
        }
        let guard = shared
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard
    }

    /// Reports the fetch outcome: inserts (with eviction and write-through)
    /// or drops the stale entry, then wakes the waiters.
    pub async fn complete(&self, key: CacheKey, outcome: FetchOutcome) {
        let result = match &outcome {
            FetchOutcome::Stored(_) => FetchResult::Ready,
            FetchOutcome::Gone => FetchResult::Gone,
        };
        match outcome {
            FetchOutcome::Stored(parts) => self.insert(key.clone(), parts).await,
            FetchOutcome::Gone => self.remove(&key).await,
        }
        if let Some(shared) = self.take_inflight(&key) {
            *shared
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
            shared.notify.notify_waiters();
        }
    }

    /// Stores without touching the in-flight table: the fallback of a waiter
    /// whose owner published `Gone` (it fetches directly, never re-locks).
    pub async fn store_direct(&self, key: CacheKey, parts: StoredParts) {
        self.insert(key, parts).await;
    }

    /// Refreshes an entry after a `304`: the headers merge (`304` wins on
    /// conflicts, the body stays), the clock restarts, the serve count is
    /// kept. Replacement, not mutation: a concurrent serve holds the old
    /// `Arc` and stays byte-identical.
    pub async fn refresh(
        &self,
        key: CacheKey,
        old: &StoredEntry,
        head_304: &[(String, String)],
        ttl: Duration,
    ) {
        let now = Instant::now();
        let mut headers = old.headers.clone();
        for (name, value) in head_304 {
            if is_hop_by_hop(name)
                || MANAGED_HEADERS.contains(&name.as_str())
                || name == "content-length"
                || name == "connection"
            {
                continue;
            }
            if let Some(slot) = headers.iter_mut().find(|(n, _)| n == name) {
                slot.1.clone_from(value);
            } else {
                headers.push((name.clone(), value.clone()));
            }
        }
        let mut etag = None;
        let mut last_modified = None;
        for (name, value) in &headers {
            if name == "etag" {
                etag = Some(value.clone());
            } else if name == "last-modified" {
                last_modified = Some(value.clone());
            }
        }
        let entry = Arc::new(StoredEntry {
            status: old.status,
            reason: old.reason.clone(),
            headers,
            body: old.body.clone(),
            etag,
            last_modified,
            vary: old.vary.clone(),
            vary_values: old.vary_values.clone(),
            framing_none: old.framing_none,
            has_declared_len: old.has_declared_len,
            stored_at: now,
            stored_at_unix: unix_now(),
            ttl,
            hits: AtomicU64::new(old.hits.load(Ordering::Relaxed)),
            last_used: Mutex::new(now),
        });
        let weight = entry.weight();
        let old_weight = old.weight();
        let path = self.disk_file(&key, &entry.vary_values);
        let mut evicted_files = Vec::new();
        {
            let mut inner = self.lock();
            inner.bytes = inner.bytes.saturating_sub(old_weight);
            evict_locked(
                &self.settings,
                &mut inner,
                weight,
                &self.metrics,
                &mut evicted_files,
            );
            inner.bytes += weight;
            if let Some(variants) = inner.map.get_mut(&key) {
                variants.retain(|existing| existing.vary_values != entry.vary_values);
                variants.push(entry);
            }
        }
        if !evicted_files.is_empty() {
            tokio::task::spawn_blocking(move || {
                for stale in evicted_files {
                    let _ = std::fs::remove_file(stale);
                }
            })
            .await
            .ok();
        }
        self.metrics
            .cache_revalidations
            .fetch_add(1, Ordering::Relaxed);
        let stored = self.lock().map.get(&key).and_then(|variants| {
            variants
                .iter()
                .find(|existing| existing.vary_values == old.vary_values)
                .cloned()
        });
        if let Some(stored) = stored {
            self.persist_variant(&key, &stored, &path).await;
        }
        // The owner revalidated: waiters get a fresh entry, like a store.
        if let Some(shared) = self.take_inflight(&key) {
            *shared
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(FetchResult::Ready);
            shared.notify.notify_waiters();
        }
    }

    /// Live view for `GET /api/v1/cache` (H1 visibility).
    #[must_use]
    pub fn snapshot(&self) -> CacheSnapshot {
        let now = Instant::now();
        let inner = self.lock();
        let mut objects: Vec<CachedObjectView> = inner
            .map
            .iter()
            .flat_map(|(key, variants)| {
                variants.iter().map(|entry| CachedObjectView {
                    key: format!("GET {}://{}{}", key.scheme, key.host, key.target),
                    status: entry.status,
                    age_secs: entry.age(now).as_secs(),
                    ttl_secs: entry.ttl.as_secs(),
                    hits: entry.hits.load(Ordering::Relaxed),
                    bytes: entry.body.len(),
                    vary: entry.vary.clone(),
                    etag: entry.etag.is_some(),
                })
            })
            .collect();
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        objects.truncate(MAX_SNAPSHOT_OBJECTS);
        let entries = inner.map.values().map(Vec::len).sum();
        CacheSnapshot {
            listener: self.settings.listener.clone(),
            entries,
            bytes: inner.bytes,
            objects,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn insert(&self, key: CacheKey, parts: StoredParts) {
        let now = Instant::now();
        let vary_values = parts.vary_values.clone();
        let entry = Arc::new(StoredEntry {
            status: parts.status,
            reason: parts.reason,
            headers: parts.headers,
            body: parts.body,
            etag: parts.etag,
            last_modified: parts.last_modified,
            vary: parts.vary,
            vary_values,
            framing_none: parts.framing_none,
            has_declared_len: parts.has_declared_len,
            stored_at: now,
            stored_at_unix: parts.stored_at_unix,
            ttl: parts.ttl,
            hits: AtomicU64::new(0),
            last_used: Mutex::new(now),
        });
        let weight = entry.weight();
        // Disk files are per variant (key + `Vary` values), so evicting one
        // variant never resurrects it from another variant's file.
        let variant_file = self.disk_file(&key, &entry.vary_values);
        let mut evicted_files = Vec::new();
        {
            let mut inner = self.lock();
            evict_locked(
                &self.settings,
                &mut inner,
                weight,
                &self.metrics,
                &mut evicted_files,
            );
            // Same variant stored twice (owner + direct fallback racing):
            // keep the newest.
            let replaced = inner
                .map
                .get(&key)
                .map(|variants| {
                    variants
                        .iter()
                        .filter(|existing| existing.vary_values == entry.vary_values)
                        .map(|existing| existing.weight())
                        .sum()
                })
                .unwrap_or(0);
            inner.bytes = inner.bytes.saturating_sub(replaced) + weight;
            let variants = inner.map.entry(key.clone()).or_default();
            variants.retain(|existing| existing.vary_values != entry.vary_values);
            variants.push(Arc::clone(&entry));
        }
        if !evicted_files.is_empty() {
            tokio::task::spawn_blocking(move || {
                for stale in evicted_files {
                    let _ = std::fs::remove_file(stale);
                }
            })
            .await
            .ok();
        }
        self.metrics.cache_stores.fetch_add(1, Ordering::Relaxed);
        self.persist_variant(&key, &entry, &variant_file).await;
    }

    async fn remove(&self, key: &CacheKey) {
        let paths: Vec<PathBuf> = {
            let mut inner = self.lock();
            match inner.map.remove(key) {
                Some(variants) => {
                    let weight = variants.iter().map(|entry| entry.weight()).sum();
                    inner.bytes = inner.bytes.saturating_sub(weight);
                    self.metrics
                        .cache_evictions
                        .fetch_add(variants.len() as u64, Ordering::Relaxed);
                    variants
                        .iter()
                        .map(|entry| self.disk_file(key, &entry.vary_values))
                        .collect()
                }
                None => Vec::new(),
            }
        };
        if !paths.is_empty() {
            tokio::task::spawn_blocking(move || {
                for path in paths {
                    let _ = std::fs::remove_file(path);
                }
            })
            .await
            .ok();
        }
    }

    fn take_inflight(&self, key: &CacheKey) -> Option<Arc<SharedFetch>> {
        self.lock().inflight.remove(key)
    }

    fn disk_file(&self, key: &CacheKey, vary_values: &[String]) -> PathBuf {
        disk_file_for(&self.settings, key, vary_values)
    }

    async fn persist_variant(&self, key: &CacheKey, entry: &Arc<StoredEntry>, path: &Path) {
        if self.settings.disk_dir.is_none() {
            return;
        }
        let bytes = encode_entry(key, entry);
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        })
        .await
        .ok();
    }

    /// Best-effort reload at startup: expired, corrupt, oversized or
    /// hash-mismatched files are skipped and counted, never trusted.
    fn reload_disk(&self) {
        let Some(dir) = self.settings.disk_dir.clone() else {
            return;
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!(
                    "WARN [{}] cache directory {} is unreadable: {error}; starting empty",
                    self.settings.listener,
                    dir.display()
                );
                return;
            }
        };
        let now_unix = unix_now();
        let now = Instant::now();
        for file in entries.flatten() {
            let path = file.path();
            if path.extension().is_none_or(|ext| ext != "cache") {
                continue;
            }
            let skip = || {
                self.metrics
                    .cache_disk_skipped
                    .fetch_add(1, Ordering::Relaxed);
            };
            let bytes = match std::fs::read(&path) {
                Ok(bytes) if bytes.len() <= DISK_READ_CAP => bytes,
                _ => {
                    skip();
                    continue;
                }
            };
            let (key, entry) = match decode_entry(&bytes, self.settings.max_entry_bytes) {
                Some(pair) => pair,
                None => {
                    skip();
                    continue;
                }
            };
            if variant_fingerprint(&key, &entry.vary_values) != file_stem_hash(&path) {
                skip();
                continue;
            }
            let age = now_unix.saturating_sub(entry.stored_at_unix);
            if Duration::from_secs(age) >= entry.ttl {
                skip();
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let entry = Arc::new(StoredEntry {
                status: entry.status,
                reason: entry.reason,
                headers: entry.headers,
                body: entry.body,
                etag: entry.etag,
                last_modified: entry.last_modified,
                vary: entry.vary,
                vary_values: entry.vary_values,
                framing_none: entry.framing_none,
                has_declared_len: entry.has_declared_len,
                stored_at: now,
                stored_at_unix: entry.stored_at_unix,
                ttl: entry.ttl,
                hits: AtomicU64::new(0),
                last_used: Mutex::new(now),
            });
            let weight = entry.weight();
            let mut inner = self.lock();
            if inner.bytes + weight > self.settings.max_memory_bytes {
                drop(inner);
                skip();
                continue;
            }
            inner.bytes += weight;
            inner.map.entry(key).or_default().push(entry);
            self.metrics
                .cache_disk_loads
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Disk file of one variant (base key + `Vary` values): evicting a variant
/// deletes exactly its file, so it can never come back on reload.
fn disk_file_for(settings: &CacheSettings, key: &CacheKey, vary_values: &[String]) -> PathBuf {
    let mut path = settings.disk_dir.clone().unwrap_or_default();
    path.push(format!(
        "{:016x}.cache",
        variant_fingerprint(key, vary_values)
    ));
    path
}

fn variant_fingerprint(key: &CacheKey, vary_values: &[String]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in key.encode() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0xff;
    for value in vary_values {
        for byte in value.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0x1f;
    }
    hash
}

/// Makes room for `need` bytes: expired entries first, then
/// least-recently-used. Evicted disk files accumulate in `evicted_files`;
/// the caller deletes them after dropping the lock (no blocking I/O under
/// the mutex).
fn evict_locked(
    settings: &CacheSettings,
    inner: &mut Store,
    need: usize,
    metrics: &Metrics,
    evicted_files: &mut Vec<PathBuf>,
) {
    let now = Instant::now();
    let mut evict_one = |inner: &mut Store, key: &CacheKey, index: usize| {
        let entry = if inner.map.get(key).is_some_and(|v| v.len() == 1) {
            inner.map.remove(key).and_then(|mut v| v.pop())
        } else {
            inner.map.get_mut(key).map(|v| v.remove(index))
        };
        if let Some(entry) = entry {
            inner.bytes = inner.bytes.saturating_sub(entry.weight());
            if settings.disk_dir.is_some() {
                evicted_files.push(disk_file_for(settings, key, &entry.vary_values));
            }
            metrics.cache_evictions.fetch_add(1, Ordering::Relaxed);
        }
    };
    // Expired entries are dead weight: drop them before touching the LRU.
    loop {
        let expired = inner
            .map
            .iter()
            .find(|(_, variants)| variants.iter().all(|entry| !entry.fresh(now)))
            .map(|(key, _)| key.clone());
        let Some(key) = expired else {
            break;
        };
        let count = inner.map.get(&key).map_or(0, Vec::len);
        for _ in 0..count {
            evict_one(inner, &key, 0);
        }
    }
    // Then the least-recently-used entries until the newcomer fits.
    while inner.bytes + need > settings.max_memory_bytes {
        let mut oldest: Option<(CacheKey, usize, Instant)> = None;
        for (key, variants) in &inner.map {
            for (index, entry) in variants.iter().enumerate() {
                let used = entry
                    .last_used
                    .lock()
                    .map(|used| *used)
                    .unwrap_or_else(|poisoned| *poisoned.into_inner());
                let older = match oldest {
                    Some((_, _, at)) => used < at,
                    None => true,
                };
                if older {
                    oldest = Some((key.clone(), index, used));
                }
            }
        }
        let Some((key, index, _)) = oldest else {
            break;
        };
        evict_one(inner, &key, index);
    }
}

/// Decides whether a parsed client request may touch the cache. Runs after
/// routing and the plugin, before any backend byte: the key uses the
/// forwarded head (rules, rewrites and plugin mutations applied), so two
/// requests that reach the backend differently never share an entry.
pub fn decide(
    method: &str,
    framing_none: bool,
    headers: &[(String, String)],
    cookie_affinity: bool,
) -> Result<Decision, Bypass> {
    if method != "GET" && method != "HEAD" {
        return Err(Bypass::Method);
    }
    if !framing_none {
        return Err(Bypass::Body);
    }
    if cookie_affinity {
        return Err(Bypass::CookieAffinity);
    }
    let mut no_cache = false;
    for (name, value) in headers {
        if BYPASS_REQUEST_HEADERS.contains(&name.as_str()) {
            return Err(Bypass::SessionHeader);
        }
        if name == "cache-control" {
            for directive in value.split(',') {
                let directive = directive.trim();
                if directive.eq_ignore_ascii_case("no-store") {
                    return Err(Bypass::NoStore);
                }
                if directive.eq_ignore_ascii_case("no-cache") {
                    no_cache = true;
                }
            }
        }
    }
    Ok(Decision {
        force_revalidate: no_cache,
    })
}

/// A cacheable request: how to look it up.
#[derive(Debug)]
pub struct Decision {
    /// The client sent `Cache-Control: no-cache`: skip fresh hits and
    /// revalidate (or fetch when the entry has no validators).
    pub force_revalidate: bool,
}

/// Builds the lookup key from the forwarded head. `HEAD` shares the `GET`
/// entry (served headers-only); the host lowercases, the scheme and target
/// are taken verbatim.
#[must_use]
pub fn base_key(method: &str, scheme: &str, host: &str, target: &str) -> CacheKey {
    let _ = method;
    CacheKey {
        method: "GET",
        scheme: scheme.to_owned(),
        host: host.to_lowercase(),
        target: target.to_owned(),
    }
}

/// Values of the `Vary`-listed request headers (lowercased names).
#[must_use]
pub fn vary_values(headers: &[(String, String)], vary: &[String]) -> Vec<String> {
    vary.iter()
        .map(|name| {
            headers
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v.trim().to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect()
}

/// Facts the store needs from a raw origin response head.
pub struct ResponseFacts {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub cache_control: Vec<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub vary: Vec<String>,
    pub has_set_cookie: bool,
    pub storable_status: bool,
}

/// Parses the raw origin head (status line + headers, no terminator) into
/// storable facts. `None` is a malformed head: stream it, never store it.
#[must_use]
pub fn parse_origin_head(head: &[u8]) -> Option<ResponseFacts> {
    let mut lines = head.split(|b| *b == b'\n');
    let status_line = lines.next()?;
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);
    let status_line = std::str::from_utf8(status_line).ok()?;
    let mut parts = status_line.splitn(3, ' ');
    parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = sanitize_reason(parts.next().unwrap_or("Unknown"));
    let mut headers = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|b| *b == b':')?;
        let name = std::str::from_utf8(&line[..colon])
            .ok()?
            .trim()
            .to_lowercase();
        let value = std::str::from_utf8(&line[colon + 1..])
            .ok()?
            .trim()
            .to_owned();
        if name.is_empty() {
            return None;
        }
        headers.push((name, value));
    }
    Some(response_facts(status, reason, headers))
}

fn response_facts(status: u16, reason: String, headers: Vec<(String, String)>) -> ResponseFacts {
    let has_set_cookie = headers.iter().any(|(n, _)| n == SET_COOKIE);
    let mut etag = None;
    let mut last_modified = None;
    let mut vary = Vec::new();
    let mut cache_control = Vec::new();
    for (name, value) in &headers {
        match name.as_str() {
            "etag" => etag = Some(value.clone()),
            "last-modified" => last_modified = Some(value.clone()),
            "vary" => vary.extend(
                value
                    .split(',')
                    .map(|v| v.trim().to_lowercase())
                    .filter(|v| !v.is_empty()),
            ),
            "cache-control" => cache_control.push(value.clone()),
            _ => {}
        }
    }
    ResponseFacts {
        storable_status: STORABLE_STATUSES.contains(&status),
        cache_control,
        etag,
        last_modified,
        vary,
        has_set_cookie,
        headers,
        reason,
        status,
    }
}

/// Effective TTL: the configured default shortened by the origin's
/// `s-maxage`/`max-age`, forced to zero by response `no-cache`.
#[must_use]
pub fn effective_ttl(default: Duration, cache_control: &[String]) -> Duration {
    let mut ttl = default;
    let mut no_cache = false;
    let mut has_s_maxage = false;
    for value in cache_control {
        for directive in value.split(',') {
            let directive = directive.trim();
            if directive.eq_ignore_ascii_case("no-cache") {
                no_cache = true;
            } else if directive.to_lowercase().starts_with("s-maxage=")
                && let Some(seconds) = directive
                    .split('=')
                    .nth(1)
                    .and_then(|v| v.trim().trim_matches('"').parse::<u64>().ok())
            {
                has_s_maxage = true;
                ttl = ttl.min(Duration::from_secs(seconds));
            }
        }
    }
    if !has_s_maxage {
        for value in cache_control {
            for directive in value.split(',') {
                let directive = directive.trim();
                if directive.to_lowercase().starts_with("max-age=")
                    && let Some(seconds) = directive
                        .split('=')
                        .nth(1)
                        .and_then(|v| v.trim().trim_matches('"').parse::<u64>().ok())
                {
                    ttl = ttl.min(Duration::from_secs(seconds));
                }
            }
        }
    }
    if no_cache { Duration::ZERO } else { ttl }
}

/// Whether the parsed origin response may be stored. Every `None` names its
/// reason: unstorable responses stream through untouched. Returns the
/// `Vary` the entry is keyed on; the caller computes the TTL and drops
/// zero-TTL entries without validators (revalidating them would loop on
/// every request for no bandwidth saved).
#[must_use]
pub fn storable_vary(facts: &ResponseFacts) -> Option<Vec<String>> {
    // Only the configured statuses; partial and redirect-with-session
    // shapes stay out.
    if !facts.storable_status {
        return None;
    }
    // H1 core: session responses are never stored.
    if facts.has_set_cookie {
        return None;
    }
    // Explicit origin opt-outs.
    for value in &facts.cache_control {
        for directive in value.split(',') {
            let directive = directive.trim();
            if directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("private")
            {
                return None;
            }
        }
    }
    // `Vary: *` means "a different response per client": unstorable.
    if facts.vary.iter().any(|v| v == "*") {
        return None;
    }
    // A variant key on session identity would leak sessions across clients.
    if facts
        .vary
        .iter()
        .any(|v| UNKEYABLE_VARY.contains(&v.as_str()))
    {
        return None;
    }
    Some(facts.vary.clone())
}

/// End-to-end headers of a response: hop-by-hop, framing and cache-managed
/// headers removed (recomputed on serve).
#[must_use]
pub fn end_to_end(headers: &[(String, String)]) -> Vec<(String, String)> {
    let connection_listed: Vec<String> = headers
        .iter()
        .filter(|(n, _)| *n == "connection")
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_lowercase())
        .collect();
    headers
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name)
                && !MANAGED_HEADERS.contains(&name.as_str())
                && name != "content-length"
                && name != "connection"
                && !connection_listed.contains(name)
        })
        .cloned()
        .collect()
}

/// Renders a stored entry as an origin-style head (status line + headers +
/// `Content-Length`), ready for the rule/compression tail. No trailing
/// terminator, like every head the engine writes: the caller appends
/// `HEAD_END`.
#[must_use]
pub fn render_head(entry: &StoredEntry) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {} {}", entry.status, entry.reason).into_bytes();
    for (name, value) in &entry.headers {
        head.extend_from_slice(b"\r\n");
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
    }
    head.extend_from_slice(format!("\r\ncontent-length: {}", entry.body.len()).as_bytes());
    head
}

/// Client `If-None-Match` against a stored `ETag` (strong comparison with
/// `W/` tolerated on either side, `*` matches any current representation).
#[must_use]
pub fn client_fresh(if_none_match: &str, etag: Option<&str>) -> bool {
    let etag = etag.unwrap_or("");
    for tag in if_none_match.split(',') {
        let tag = tag.trim().trim_start_matches("W/").trim_matches('"');
        if tag == "*"
            || (!etag.is_empty() && tag == etag.trim_start_matches("W/").trim_matches('"'))
        {
            return true;
        }
    }
    false
}

fn sanitize_reason(reason: &str) -> String {
    let clean: String = reason
        .bytes()
        .filter(|b| (0x20..0x7f).contains(b))
        .take(64)
        .map(char::from)
        .collect();
    if clean.trim().is_empty() {
        "Unknown".to_owned()
    } else {
        clean
    }
}

/// Current Unix time, for disk timestamps (kept beside the monotonic
/// clock the TTL runs on).
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl CacheKey {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.scheme.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.host.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.target.as_bytes());
        out
    }
}

fn file_stem_hash(path: &Path) -> u64 {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| u64::from_str_radix(stem, 16).ok())
        .unwrap_or(0)
}

fn encode_entry(key: &CacheKey, entry: &StoredEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(entry.body.len() + 512);
    out.extend_from_slice(&DISK_MAGIC);
    let key_bytes = key.encode();
    push_u32(&mut out, key_bytes.len() as u32);
    out.extend_from_slice(&key_bytes);
    push_u16(&mut out, entry.status);
    push_str(&mut out, &entry.reason);
    push_u64(&mut out, entry.stored_at_unix);
    push_u64(&mut out, entry.ttl.as_secs());
    push_u32(&mut out, entry.headers.len() as u32);
    for (name, value) in &entry.headers {
        push_str(&mut out, name);
        push_str(&mut out, value);
    }
    push_opt_str(&mut out, entry.etag.as_deref());
    push_opt_str(&mut out, entry.last_modified.as_deref());
    push_u32(&mut out, entry.vary.len() as u32);
    for name in &entry.vary {
        push_str(&mut out, name);
    }
    push_u32(&mut out, entry.vary_values.len() as u32);
    for value in &entry.vary_values {
        push_str(&mut out, value);
    }
    let mut flags = 0u8;
    if entry.framing_none {
        flags |= 1;
    }
    if entry.has_declared_len {
        flags |= 2;
    }
    out.push(flags);
    push_u64(&mut out, entry.body.len() as u64);
    out.extend_from_slice(&entry.body);
    out
}

#[allow(clippy::too_many_lines)]
fn decode_entry(bytes: &[u8], max_body: usize) -> Option<(CacheKey, StoredParts)> {
    if bytes.get(..4)? != DISK_MAGIC {
        return None;
    }
    let mut pos = 4usize;
    let key_len = read_u32(bytes, &mut pos)? as usize;
    if key_len > 8192 {
        return None;
    }
    let key_bytes = read_bytes(bytes, &mut pos, key_len)?;
    let mut parts = key_bytes.split(|b| *b == b'\n');
    if parts.next()? != b"GET" {
        return None;
    }
    let scheme = std::str::from_utf8(parts.next()?).ok()?.to_owned();
    let host = std::str::from_utf8(parts.next()?).ok()?.to_owned();
    let target = std::str::from_utf8(parts.next()?).ok()?.to_owned();
    if parts.next().is_some() || scheme.is_empty() || host.is_empty() || target.is_empty() {
        return None;
    }
    let status = read_u16(bytes, &mut pos)?;
    if !STORABLE_STATUSES.contains(&status) {
        return None;
    }
    let reason = sanitize_reason(&read_str(bytes, &mut pos)?);
    let stored_at_unix = read_u64(bytes, &mut pos)?;
    let ttl = Duration::from_secs(read_u64(bytes, &mut pos)?);
    if ttl.is_zero() || ttl > Duration::from_secs(86_400) {
        return None;
    }
    let header_count = read_u32(bytes, &mut pos)? as usize;
    if header_count > 1000 {
        return None;
    }
    let mut headers = Vec::with_capacity(header_count.min(64));
    for _ in 0..header_count {
        headers.push((read_str(bytes, &mut pos)?, read_str(bytes, &mut pos)?));
    }
    let etag = read_opt_str(bytes, &mut pos)?;
    let last_modified = read_opt_str(bytes, &mut pos)?;
    let vary_count = read_u32(bytes, &mut pos)? as usize;
    if vary_count > 32 {
        return None;
    }
    let mut vary = Vec::with_capacity(vary_count);
    for _ in 0..vary_count {
        vary.push(read_str(bytes, &mut pos)?);
    }
    let values_count = read_u32(bytes, &mut pos)? as usize;
    if values_count != vary_count || values_count > 32 {
        return None;
    }
    let mut vary_values = Vec::with_capacity(values_count);
    for _ in 0..values_count {
        vary_values.push(read_str(bytes, &mut pos)?);
    }
    let flags = *read_bytes(bytes, &mut pos, 1)?.first()?;
    let body_len = read_u64(bytes, &mut pos)? as usize;
    if body_len > max_body {
        return None;
    }
    let body = read_bytes(bytes, &mut pos, body_len)?.to_vec();
    if pos != bytes.len() {
        return None;
    }
    Some((
        CacheKey {
            method: "GET",
            scheme,
            host,
            target,
        },
        StoredParts {
            status,
            reason,
            headers,
            body,
            etag,
            last_modified,
            vary,
            vary_values,
            framing_none: flags & 1 != 0,
            has_declared_len: flags & 2 != 0,
            stored_at_unix,
            ttl,
        },
    ))
}

fn read_bytes<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = (*pos).checked_add(len)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(slice)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let slice = read_bytes(bytes, pos, 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let slice = read_bytes(bytes, pos, 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let slice = read_bytes(bytes, pos, 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(slice);
    Some(u64::from_le_bytes(array))
}

fn read_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u32(bytes, pos)? as usize;
    if len > 1_048_576 {
        return None;
    }
    std::str::from_utf8(read_bytes(bytes, pos, len)?)
        .ok()?
        .to_owned()
        .into()
}

fn read_opt_str(bytes: &[u8], pos: &mut usize) -> Option<Option<String>> {
    let len = read_u32(bytes, pos)?;
    if len == DISK_NONE {
        return Some(None);
    }
    if len as usize > 1_048_576 {
        return None;
    }
    std::str::from_utf8(read_bytes(bytes, pos, len as usize)?)
        .ok()
        .map(|text| Some(text.to_owned()))
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn push_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(text) => push_str(out, text),
        None => push_u32(out, DISK_NONE),
    }
}

/// Live view of one listener's cache for `GET /api/v1/cache`.
#[derive(Debug, Clone, Serialize)]
pub struct CacheSnapshot {
    pub listener: String,
    pub entries: usize,
    pub bytes: usize,
    pub objects: Vec<CachedObjectView>,
}

/// One stored object, as the operator sees it (H1 visibility).
#[derive(Debug, Clone, Serialize)]
pub struct CachedObjectView {
    pub key: String,
    pub status: u16,
    pub age_secs: u64,
    pub ttl_secs: u64,
    pub hits: u64,
    pub bytes: usize,
    pub vary: Vec<String>,
    pub etag: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    fn settings() -> CacheSettings {
        CacheSettings::test_defaults()
    }

    fn key() -> CacheKey {
        base_key("GET", "http", "example.com", "/static/app.js")
    }

    fn parts(status: u16) -> StoredParts {
        StoredParts {
            status,
            reason: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body: b"hello".to_vec(),
            etag: None,
            last_modified: None,
            vary: Vec::new(),
            vary_values: Vec::new(),
            framing_none: false,
            has_declared_len: true,
            ttl: Duration::from_secs(60),
            stored_at_unix: unix_now(),
        }
    }

    #[tokio::test]
    async fn miss_then_hit() {
        let cache = Cache::load(settings(), metrics()).expect("builds");
        let key = key();
        assert!(matches!(cache.lookup(&key, &[], false), Lookup::Fetch));
        // A second lookup while in-flight waits instead of fetching twice.
        assert!(matches!(cache.lookup(&key, &[], false), Lookup::Wait(_)));
        cache
            .complete(key.clone(), FetchOutcome::Stored(parts(200)))
            .await;
        match cache.lookup(&key, &[], false) {
            Lookup::Hit(entry) => assert_eq!(entry.body, b"hello"),
            _ => panic!("stored entry must hit"),
        }
    }

    #[tokio::test]
    async fn failure_drops_the_stale_entry() {
        let cache = Cache::load(settings(), metrics()).expect("builds");
        let key = key();
        assert!(matches!(cache.lookup(&key, &[], false), Lookup::Fetch));
        cache
            .complete(
                key.clone(),
                FetchOutcome::Stored(StoredParts {
                    etag: Some("\"v1\"".to_owned()),
                    ..parts(200)
                }),
            )
            .await;
        assert!(matches!(
            cache.lookup(&key, &[], true),
            Lookup::Revalidate(_)
        ));
        cache.complete(key.clone(), FetchOutcome::Gone).await;
        assert!(matches!(cache.lookup(&key, &[], false), Lookup::Fetch));
    }

    #[test]
    fn session_headers_bypass() {
        let headers = vec![("cookie".to_owned(), "s=1".to_owned())];
        assert_eq!(
            decide("GET", true, &headers, false).unwrap_err(),
            Bypass::SessionHeader
        );
        assert_eq!(
            decide("POST", true, &[], false).unwrap_err(),
            Bypass::Method
        );
        assert_eq!(decide("GET", false, &[], false).unwrap_err(), Bypass::Body);
        assert_eq!(
            decide("GET", true, &[], true).unwrap_err(),
            Bypass::CookieAffinity
        );
        assert!(decide("GET", true, &[], false).is_ok());
        assert!(decide("HEAD", true, &[], false).is_ok());
    }

    #[test]
    fn set_cookie_is_never_storable() {
        let head = b"HTTP/1.1 200 OK\r\nset-cookie: s=1; Path=/\r\ncontent-length: 2\r\n";
        let facts = parse_origin_head(head).expect("parses");
        assert!(facts.has_set_cookie);
        assert!(storable_vary(&facts).is_none());
    }

    #[test]
    fn ttl_honors_the_origin_bound() {
        let minute = Duration::from_secs(60);
        assert_eq!(
            effective_ttl(minute, &["max-age=10".to_owned()]),
            Duration::from_secs(10)
        );
        assert_eq!(effective_ttl(minute, &["max-age=600".to_owned()]), minute);
        assert_eq!(
            effective_ttl(minute, &["s-maxage=5, max-age=600".to_owned()]),
            Duration::from_secs(5)
        );
        assert_eq!(
            effective_ttl(minute, &["no-cache".to_owned()]),
            Duration::ZERO
        );
    }

    #[test]
    fn client_304_on_etag_match() {
        assert!(client_fresh("\"abc\"", Some("\"abc\"")));
        assert!(client_fresh("W/\"abc\"", Some("\"abc\"")));
        assert!(client_fresh("*", Some("\"abc\"")));
        assert!(!client_fresh("\"other\"", Some("\"abc\"")));
    }

    #[test]
    fn disk_round_trip_restores_unexpired_entries() {
        let dir = std::env::temp_dir().join(format!("eqproxy-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let cache = Cache::load(
                CacheSettings {
                    disk_dir: Some(dir.clone()),
                    ..settings()
                },
                metrics(),
            )
            .expect("builds");
            let key = key();
            assert!(matches!(cache.lookup(&key, &[], false), Lookup::Fetch));
            cache.complete(key, FetchOutcome::Stored(parts(200))).await;
        });
        let reloaded = Cache::load(
            CacheSettings {
                disk_dir: Some(dir.clone()),
                ..settings()
            },
            metrics(),
        )
        .expect("reloads");
        match reloaded.lookup(&key(), &[], false) {
            Lookup::Hit(entry) => assert_eq!(entry.body, b"hello"),
            _ => panic!("disk entry must hit after reload"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
