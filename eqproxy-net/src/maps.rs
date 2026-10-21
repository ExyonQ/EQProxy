//! Hot map file watcher (C10 / PP-02): re-reads a map's source file
//! every `reload_interval` and swaps the data in hot — **without** a
//! config reload and without touching any other dataplane state (the
//! rules, counters, buckets and pools all survive; that is PP-02).
//!
//! Failure semantics (Q6, C10): a file that disappears, grows past the
//! budget or fails to parse keeps the **last good data** serving and
//! counts `map_reload_failures` with an explicit log line — never a
//! silent drop, never a break in live traffic.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use eqproxy_core::maps::{self, HotMap};
use eqproxy_core::{Metrics, Shutdown};

/// Watches one hot map until the shutdown signal (or until the map is
/// dropped by a config generation going away — the caller owns the
/// task). Inline maps and `reload_interval = "0s"` return immediately:
/// their data is static by config.
pub async fn run(map: Arc<HotMap>, metrics: Arc<Metrics>, mut shutdown: Shutdown) {
    let Some(file) = map.file().map(std::path::Path::to_path_buf) else {
        return;
    };
    let interval = map.reload_interval();
    if interval.is_zero() {
        return;
    }
    // Content already rejected once is not retried until it changes:
    // one failure line per bad edit, never one per tick.
    let mut known_bad: Option<u64> = None;
    loop {
        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(interval) => {}
        }
        // Change detection on the raw bytes: an untouched file costs
        // one read and one hash, never a re-parse or a swap. The read,
        // the hash and the parse all run off the async executor (a map
        // file may be megabytes; the executor must never stall on it).
        let read = tokio::task::spawn_blocking({
            let file = file.clone();
            move || {
                let bytes = std::fs::read(file)?;
                Ok::<_, std::io::Error>((maps::fingerprint(&bytes), bytes))
            }
        })
        .await;
        let (hash, bytes) = match read {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                failed(
                    &map,
                    &metrics,
                    &format!("could not read {}: {error}", file.display()),
                );
                continue;
            }
            Err(join_error) => {
                failed(
                    &map,
                    &metrics,
                    &format!("map read task failed: {join_error}"),
                );
                continue;
            }
        };
        if bytes.len() as u64 > maps::MAX_MAP_FILE_BYTES {
            failed(
                &map,
                &metrics,
                &format!(
                    "{} is {} bytes (maximum {})",
                    file.display(),
                    bytes.len(),
                    maps::MAX_MAP_FILE_BYTES
                ),
            );
            continue;
        }
        if map.get().hash() == hash || known_bad == Some(hash) {
            continue;
        }
        let update = tokio::task::spawn_blocking({
            let map = Arc::clone(&map);
            move || map.update_bytes(&bytes).map_err(|error| error.to_string())
        })
        .await;
        match update {
            Ok(Ok(())) => {
                known_bad = None;
                metrics.map_reloads.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "INFO map \"{}\" reloaded: {} entries ({})",
                    map.name(),
                    map.get().len(),
                    file.display()
                );
            }
            Ok(Err(error)) => {
                known_bad = Some(hash);
                failed(&map, &metrics, &error);
            }
            Err(join_error) => {
                failed(
                    &map,
                    &metrics,
                    &format!("map parse task failed: {join_error}"),
                );
            }
        }
    }
}

/// A reload that could not be applied: last good data keeps serving,
/// the operator gets an explicit line and the failure is counted.
fn failed(map: &HotMap, metrics: &Metrics, why: &str) {
    metrics.map_reload_failures.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "ERROR map \"{}\" reload kept the last good data: {why}",
        map.name()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use eqproxy_core::maps::MapData;
    use std::time::Duration;

    /// The watcher never panics on a missing file: it counts the
    /// failure and keeps the last good data (C10 failure semantics).
    #[tokio::test]
    async fn watcher_keeps_last_good_data_when_the_file_disappears() {
        let dir = std::env::temp_dir().join(format!("eqproxy-maps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("t.map");
        std::fs::write(&file, "a 1\n").expect("write map");
        let map = HotMap::new(
            "t",
            MapData::parse("a 0\n", None).expect("parse"),
            Some(file.clone()),
            Duration::from_millis(50),
        );
        let metrics = Arc::new(Metrics::default());
        let (stop, shutdown) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn(run(Arc::clone(&map), Arc::clone(&metrics), shutdown));

        // The change lands in hot and is counted as one reload. The map
        // publishes the new data before the counter increments, so wait for
        // both: asserting the counter as soon as the data appears is a race
        // that instrumented builds (llvm-cov) lose reliably.
        std::fs::write(&file, "a 2\n").expect("rewrite map");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while map.get().lookup("a") != Some("2") || metrics.snapshot().map_reloads == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the reload did not land and count in time"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(metrics.snapshot().map_reloads, 1);

        // The file vanishing counts a failure and keeps the data.
        std::fs::remove_file(&file).expect("remove map");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while metrics.snapshot().map_reload_failures == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the failure was not counted in time"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(map.get().lookup("a"), Some("2"), "last good data kept");

        stop.trigger();
        task.await.expect("watcher task");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
