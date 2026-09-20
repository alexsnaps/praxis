// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Readiness check utilities for integration tests.

use std::{
    net::TcpStream,
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Environment variable overriding the readiness deadline, in milliseconds.
///
/// When set to a positive integer it replaces the default deadline of every
/// `wait_for_*` utility. Coverage runs and heavily loaded CI runners set it so
/// slow server startup under instrumentation does not read as a test failure.
/// Unset, empty, zero, or unparseable values leave each utility on its default.
pub(crate) const READY_TIMEOUT_ENV_VAR: &str = "PRAXIS_TEST_READY_TIMEOUT_MS";

/// Default readiness deadline for a bare TCP connect.
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// Default readiness deadline for an HTTP or HTTP/2 handshake.
pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between readiness poll attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// HTTP/2 connection preface ([RFC 9113 Section 3.4]).
///
/// [RFC 9113 Section 3.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-3.4
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0.
const SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

/// SETTINGS ACK frame: length=0, type=0x04, flags=0x01 (ACK), stream=0.
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

/// GOAWAY frame: `length=8`, `type=0x07`, `flags=0`, `stream=0`,
/// `last_stream_id=0`, `error_code=0` (`NO_ERROR`).
const GOAWAY: &[u8] = &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// -----------------------------------------------------------------------------
// Deadline Resolution
// -----------------------------------------------------------------------------

/// Resolve the readiness deadline, honoring `READY_TIMEOUT_ENV_VAR`.
///
/// Returns the env-var override when it parses to a positive number of
/// milliseconds; otherwise returns `default`.
pub(crate) fn ready_timeout(default: Duration) -> Duration {
    resolve_ready_timeout(std::env::var(READY_TIMEOUT_ENV_VAR).ok().as_deref(), default)
}

/// Poll `is_ready` until it returns `true` or `timeout` elapses.
///
/// Returns `true` on readiness and `false` once the deadline passes. Always
/// makes at least one attempt, even when `timeout` is zero.
pub(crate) fn poll_until_ready(timeout: Duration, mut is_ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;

    loop {
        if is_ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Resolve a readiness deadline from a raw override string.
///
/// A value that trims to a positive integer becomes the deadline in
/// milliseconds; anything else (absent, empty, non-numeric, or zero) falls
/// back to `default`.
fn resolve_ready_timeout(raw: Option<&str>, default: Duration) -> Duration {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(default, Duration::from_millis)
}

// -----------------------------------------------------------------------------
// Readiness Checks
// -----------------------------------------------------------------------------

/// Block until a TCP connection to `addr` succeeds, or panic once the
/// readiness deadline (default 2 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_tcp(addr: &str) {
    let timeout = ready_timeout(DEFAULT_TCP_TIMEOUT);

    assert!(
        poll_until_ready(timeout, || TcpStream::connect(addr).is_ok()),
        "server at {addr} did not become ready within {timeout:?}"
    );
}

/// Block until an HTTP request to `addr` gets a valid response, or panic once
/// the readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_http(addr: &str) {
    use std::io::{Read as _, Write as _};

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);

    let ready = poll_until_ready(timeout, || {
        let Ok(mut stream) = TcpStream::connect(addr) else {
            return false;
        };
        drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
        drop(stream.set_write_timeout(Some(Duration::from_secs(2))));
        if stream.write_all(request).is_err() {
            return false;
        }
        let mut buf = [0_u8; 16];
        if let Ok(n) = stream.read(&mut buf)
            && n >= 5
            && buf.starts_with(b"HTTP/")
        {
            let mut drain = [0_u8; 4096];
            while stream.read(&mut drain).unwrap_or(0) > 0 {}
            return true;
        }
        false
    });

    assert!(ready, "HTTP server at {addr} did not become ready within {timeout:?}");
}

/// Block until a full HTTP/2 handshake with `addr` completes, or panic once
/// the readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `READY_TIMEOUT_ENV_VAR`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_http2(addr: &str) {
    use std::io::{Read as _, Write as _};

    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);

    let ready = poll_until_ready(timeout, || {
        let Ok(mut stream) = TcpStream::connect(addr) else {
            return false;
        };
        drop(stream.set_read_timeout(Some(Duration::from_secs(1))));
        drop(stream.set_write_timeout(Some(Duration::from_secs(1))));
        if stream.write_all(PREFACE).is_ok() && stream.write_all(SETTINGS).is_ok() {
            let mut buf = [0_u8; 64];
            if let Ok(n) = stream.read(&mut buf)
                && n >= 9
                && buf[3] == 0x04
            {
                let _ack = stream.write_all(SETTINGS_ACK);
                let _goaway = stream.write_all(GOAWAY);
                let mut drain = [0_u8; 256];
                while stream.read(&mut drain).unwrap_or(0) > 0 {}
                return true;
            }
        }
        false
    });

    assert!(ready, "HTTP/2 server at {addr} did not become ready within {timeout:?}");

    std::thread::sleep(Duration::from_millis(100));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ready_timeout_uses_default_when_absent() {
        assert_eq!(
            resolve_ready_timeout(None, DEFAULT_TCP_TIMEOUT),
            DEFAULT_TCP_TIMEOUT,
            "an absent override should keep the default deadline"
        );
    }

    #[test]
    fn resolve_ready_timeout_parses_positive_override() {
        assert_eq!(
            resolve_ready_timeout(Some("1500"), DEFAULT_TCP_TIMEOUT),
            Duration::from_millis(1500),
            "a positive override should replace the default deadline"
        );
    }

    #[test]
    fn resolve_ready_timeout_trims_surrounding_whitespace() {
        assert_eq!(
            resolve_ready_timeout(Some("  250  "), DEFAULT_HTTP_TIMEOUT),
            Duration::from_millis(250),
            "surrounding whitespace should be ignored"
        );
    }

    #[test]
    fn resolve_ready_timeout_rejects_empty_and_unparseable() {
        for raw in ["", "   ", "abc", "-5", "1.5", "12ms"] {
            assert_eq!(
                resolve_ready_timeout(Some(raw), DEFAULT_HTTP_TIMEOUT),
                DEFAULT_HTTP_TIMEOUT,
                "invalid override {raw:?} should fall back to the default"
            );
        }
    }

    #[test]
    fn resolve_ready_timeout_rejects_zero() {
        assert_eq!(
            resolve_ready_timeout(Some("0"), DEFAULT_TCP_TIMEOUT),
            DEFAULT_TCP_TIMEOUT,
            "a zero override is nonsensical and should fall back to the default"
        );
    }

    #[test]
    fn poll_until_ready_returns_true_on_first_success() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_secs(60), || {
            attempts += 1;
            true
        });

        assert!(ready, "an immediately-ready probe should succeed");
        assert_eq!(attempts, 1, "success on the first probe should not retry");
    }

    #[test]
    fn poll_until_ready_retries_until_success() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_secs(60), || {
            attempts += 1;
            attempts >= 3
        });

        assert!(ready, "the probe should eventually report ready");
        assert_eq!(attempts, 3, "the poller should retry until the probe succeeds");
    }

    #[test]
    fn poll_until_ready_attempts_once_even_with_zero_timeout() {
        let mut attempts = 0_u32;

        let ready = poll_until_ready(Duration::from_millis(0), || {
            attempts += 1;
            false
        });

        assert!(!ready, "a never-ready probe should report not ready");
        assert_eq!(attempts, 1, "even a zero deadline must probe at least once");
    }

    #[test]
    fn poll_until_ready_honors_wall_clock_deadline() {
        let start = Instant::now();

        let ready = poll_until_ready(Duration::from_millis(80), || false);
        let elapsed = start.elapsed();

        assert!(!ready, "a never-ready probe should time out");
        assert!(
            elapsed >= Duration::from_millis(80),
            "the poller must wait for the full deadline, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the poller must stop near the deadline, not run for the 2s/5s defaults, waited {elapsed:?}"
        );
    }
}
