//! Address reservations shared by the E2E binaries.
//!
//! Each file in `tests/` is its own binary and `cargo nextest` runs them
//! concurrently, so a port freed by one test is a shared resource: a
//! `TcpListener::bind("127.0.0.1:0")` proves the port was free at that
//! instant, never that it still is when the test later binds or connects.
//! Predicting a port breaks a test in two different ways, and each has its
//! own answer here.
//!
//! # An address nothing can answer: [`dead_addr`]
//!
//! The port `P` stays bound on `127.0.0.1` by the returned guard for as long
//! as the test needs it, so the kernel will not hand `P` to another
//! `127.0.0.1:0` bind. The address handed out is `127.0.0.2:P`, where nothing
//! listens. `127.0.0.2` is connectable through the loopback route but is
//! **not bindable on macOS**, so it is only ever a destination, never a
//! listener.
//!
//! A connect there never reaches an accepting socket, but it does not always
//! fail at once: where `127.0.0.2` is not a local address (macOS) the SYN is
//! dropped and the connect waits for its own timeout. Callers that need the
//! answer quickly must bound the connect themselves — the proxy dial and the
//! health check both already do — and must not read "closed port" as "instant
//! refusal".
//!
//! # An address the proxy must listen on
//!
//! Never predict it: configure the listener with port 0 and read the real
//! address back from `BoundProxy::local_addrs()`. The kernel assigned that
//! port to *this* socket, so no neighbour can hold it, and `proxy::apply`
//! matches a kept listener by its configured key (`:0` stays `:0`), so
//! reloads keep the socket. When a test needs a *different* configured
//! address (the swap key), `[::1]:0` is a distinct key with the same
//! guarantee; the bound `::1` address is read back the same way.
//!
//! # An address that is down now and is bound later: [`revivable_addr`]
//!
//! Recovery tests need the port closed first (checks fail) and bindable
//! afterwards (the origin comes up at the same address), so neither a guard
//! nor a read-back helps: the test rebinds it itself. The port comes from
//! outside the ephemeral range (`ip_local_port_range` is 32768–60999 on
//! Linux and 49152–65535 on macOS), so the kernel can never hand it to any
//! `:0` bind in the suite; only an explicit binder can take it, which fails
//! the test loudly instead of silently answering a "dead" origin.
//!
//! The claim itself is a **UDP** socket on the same port. UDP and TCP port
//! spaces are independent, so the claim does not open the TCP port the test
//! needs closed, and it is exclusive across test binaries: two of them
//! claiming at once get different ports instead of the same probe-and-release
//! answer (the 2026-10-28 load run hit exactly that with a bare probe). The
//! OS releases it when the guard drops, so there is no lock file to go stale.

// Each binary compiles this module and uses the subset of helpers it needs.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

/// An address no neighbour can answer, for as long as the guard lives.
///
/// The guard holds `127.0.0.1:<port>`, which keeps the port out of the
/// ephemeral pool for this host, and the returned address is
/// `127.0.0.2:<port>` — the same port on a loopback address nothing binds.
/// A connect there fails by refusal or by the caller's timeout; see the
/// module docs.
pub fn dead_addr() -> (SocketAddr, TcpListener) {
    let guard = TcpListener::bind("127.0.0.1:0").expect("bind dead guard");
    let port = guard.local_addr().expect("dead guard addr").port();
    (SocketAddr::from(([127, 0, 0, 2], port)), guard)
}

/// The first unclaimed port of a small explicit range, for a test that must
/// leave it closed now and bind it later at the same address.
///
/// The range sits below the ephemeral one, so no `:0` bind in the suite can
/// be handed these ports. The UDP guard claims the port across processes
/// without opening its TCP side.
pub fn revivable_addr() -> (SocketAddr, std::net::UdpSocket) {
    const BASE: u16 = 20_000;
    const TRIES: u16 = 10;
    for offset in 0..TRIES {
        let port = BASE + offset;
        if let Ok(guard) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
            return (SocketAddr::from(([127, 0, 0, 1], port)), guard);
        }
    }
    panic!("no free port in {BASE}..{}", BASE + TRIES);
}

/// Waits until `read()` returns `want`, with a deadline.
///
/// A counter incremented when the exchange **finishes** —
/// `http_requests_proxied` after the body copy, `connections_active` when the
/// task ends — can land after the client has read the last byte: the response
/// reaches the wire before the bookkeeping runs. Sampling once right after the
/// last head races the proxy (the 2026-10-28 control with a 300 ms delay made
/// `e2e_http1.rs:341` read 1 where it expected 2); this waits for the value
/// without changing the assertion. EOF-delimited exchanges do not need it:
/// the close happens after the increment.
pub async fn wait_for_counter(what: &str, want: u64, mut read: impl FnMut() -> u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = read();
        if got == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what} == {want} (last read: {got})"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[test]
fn dead_addr_never_answers_and_keeps_its_port_out_of_the_pool() {
    let (dead, guard) = dead_addr();
    assert!(
        std::net::TcpStream::connect_timeout(&dead, Duration::from_millis(200)).is_err(),
        "nothing may answer on the handed-out address"
    );
    assert!(
        TcpListener::bind(("127.0.0.1", dead.port())).is_err(),
        "the guard must keep the port bound for a neighbour's `:0` bind"
    );
    drop(guard);
}

#[test]
fn revivable_addr_is_closed_and_then_bindable() {
    let (addr, _guard) = revivable_addr();
    assert!(
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
        "the TCP side must be closed when handed out"
    );
    // A concurrent claim must not get the same port back, even from another
    // binary: the UDP guard is what makes that exclusive.
    let (other, _other_guard) = revivable_addr();
    assert_ne!(addr, other, "two claims must get two ports");
    let listener = TcpListener::bind(addr).expect("the test must be able to bind it later");
    assert_eq!(
        listener.local_addr().expect("bound addr"),
        addr,
        "it must come back at the same address"
    );
}
