// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Prometheus metrics for TCP connection lifecycle.

use metrics::{SharedString, counter, gauge, histogram};
use praxis_core::config::MetricLabel;

use crate::http::pingora::metrics::{is_recorder_installed, metric_labels};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Counter for total accepted TCP connections.
const TCP_CONNECTIONS_TOTAL: &str = "praxis_tcp_connections_total";

/// Histogram for TCP connection duration in seconds.
const TCP_CONNECTION_DURATION_SECONDS: &str = "praxis_tcp_connection_duration_seconds";

/// Counter for bytes written to downstream TCP clients.
const TCP_BYTES_SENT_TOTAL: &str = "praxis_tcp_bytes_sent_total";

/// Counter for bytes read from downstream TCP clients.
const TCP_BYTES_RECEIVED_TOTAL: &str = "praxis_tcp_bytes_received_total";

/// Gauge for currently open TCP connections per listener.
///
/// The HTTP counterpart is `praxis_http_active_requests`; each metric
/// carries only its own protocol so the two families are queryable on
/// their own.
const TCP_ACTIVE_CONNECTIONS: &str = "praxis_tcp_active_connections";

// -----------------------------------------------------------------------------
// Metric Recording
// -----------------------------------------------------------------------------

/// Increment the total TCP connections counter for the given listener.
///
/// No-op when the Prometheus recorder has not been installed
/// (i.e. when the admin interface is disabled).
pub(crate) fn record_tcp_connection_accepted(listener: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    if !metric_labels().is_enabled(MetricLabel::Listener) {
        counter!(TCP_CONNECTIONS_TOTAL).increment(1);
        return;
    }
    counter!(TCP_CONNECTIONS_TOTAL, "listener" => listener).increment(1);
}

/// Record TCP connection duration for a closed connection.
///
/// The `reason` label captures the disconnect cause. Sessions that reached
/// the forwarding phase report the `TcpCloseReason` they ended on
/// (`completed`, `error`, `shutdown`, `session_timeout`, `max_duration`);
/// early closes report `sni_timeout`, `filter_rejection`, `connect_failure`
/// or `peeked_write_error`.
///
/// No-op when the Prometheus recorder has not been installed
/// (i.e. when the admin interface is disabled).
pub(crate) fn record_tcp_connection_duration(listener: SharedString, reason: &'static str, duration_secs: f64) {
    if !is_recorder_installed() {
        return;
    }
    if !metric_labels().is_enabled(MetricLabel::Listener) {
        histogram!(TCP_CONNECTION_DURATION_SECONDS, "reason" => reason).record(duration_secs);
        return;
    }
    histogram!(
        TCP_CONNECTION_DURATION_SECONDS,
        "listener" => listener,
        "reason" => reason
    )
    .record(duration_secs);
}

/// Record bytes forwarded over a closed TCP connection.
///
/// `received` is the client-to-upstream direction and `sent` is the
/// upstream-to-client direction, both from the proxy's point of view.
/// Recorded once per connection, after forwarding ends, so the totals
/// cover cancelled sessions as well as clean closes.
///
/// No-op when the Prometheus recorder has not been installed
/// (i.e. when the admin interface is disabled).
pub(crate) fn record_tcp_bytes(listener: SharedString, received: u64, sent: u64) {
    if !is_recorder_installed() {
        return;
    }
    if !metric_labels().is_enabled(MetricLabel::Listener) {
        counter!(TCP_BYTES_RECEIVED_TOTAL).increment(received);
        counter!(TCP_BYTES_SENT_TOTAL).increment(sent);
        return;
    }
    counter!(TCP_BYTES_RECEIVED_TOTAL, "listener" => listener.clone()).increment(received);
    counter!(TCP_BYTES_SENT_TOTAL, "listener" => listener).increment(sent);
}

/// RAII guard that decrements `praxis_tcp_active_connections` on drop.
///
/// Acquired once per accepted TCP connection. Every early-close path
/// returns from the same session future, so the drop covers SNI timeouts,
/// filter rejections and connect failures as well as completed sessions.
///
/// Bind the guard to a named variable: `let _ = acquire(..)` drops it
/// immediately and pins the gauge at zero.
pub(crate) struct TcpActiveConnectionGuard {
    /// Listener name label.
    listener: SharedString,
}

impl TcpActiveConnectionGuard {
    /// Increment the gauge and return a guard that decrements on drop.
    pub(crate) fn acquire(listener: SharedString) -> Self {
        if is_recorder_installed() {
            if metric_labels().is_enabled(MetricLabel::Listener) {
                gauge!(TCP_ACTIVE_CONNECTIONS, "listener" => listener.clone()).increment(1.0);
            } else {
                gauge!(TCP_ACTIVE_CONNECTIONS).increment(1.0);
            }
        }
        Self { listener }
    }
}

impl Drop for TcpActiveConnectionGuard {
    fn drop(&mut self) {
        if is_recorder_installed() {
            if metric_labels().is_enabled(MetricLabel::Listener) {
                gauge!(TCP_ACTIVE_CONNECTIONS, "listener" => self.listener.clone()).decrement(1.0);
            } else {
                gauge!(TCP_ACTIVE_CONNECTIONS).decrement(1.0);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn record_accepted_without_recorder_does_not_panic() {
        record_tcp_connection_accepted(SharedString::const_str("test-listener"));
    }

    #[test]
    fn record_duration_without_recorder_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("test-listener"), "completed", 1.5);
    }

    #[test]
    fn record_zero_duration_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("test-listener"), "sni_timeout", 0.0);
    }

    #[test]
    fn record_large_duration_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("long-lived"), "completed", 86400.0);
    }

    #[test]
    fn record_bytes_without_recorder_does_not_panic() {
        record_tcp_bytes(SharedString::const_str("test-listener"), 1, 2);
    }

    #[test]
    fn record_bytes_accumulates_both_directions() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_bytes(SharedString::const_str("bytes-listener"), 100, 250);
        record_tcp_bytes(SharedString::const_str("bytes-listener"), 5, 7);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"bytes-listener\"} 105"),
            "received counter should sum both records:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"bytes-listener\"} 257"),
            "sent counter should sum both records:\n{body}"
        );
    }

    #[test]
    fn active_connection_guard_without_recorder_does_not_panic() {
        let _guard = TcpActiveConnectionGuard::acquire(SharedString::const_str("test-listener"));
    }

    #[test]
    fn active_connection_guard_returns_to_zero_on_drop() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let guard = TcpActiveConnectionGuard::acquire(SharedString::const_str("tcp-gauge-listener"));
        let held = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            held.contains("praxis_tcp_active_connections{listener=\"tcp-gauge-listener\"} 1"),
            "gauge should read 1 while the guard is held:\n{held}"
        );
        drop(guard);
        let released = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            released.contains("praxis_tcp_active_connections{listener=\"tcp-gauge-listener\"} 0"),
            "gauge should return to 0 once the guard drops:\n{released}"
        );
    }

    #[test]
    fn forwarding_phase_reasons_appear_in_scrape() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        for reason in ["error", "shutdown", "session_timeout", "max_duration"] {
            record_tcp_connection_duration(SharedString::const_str("reason-listener"), reason, 0.5);
        }
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        for reason in ["error", "shutdown", "session_timeout", "max_duration"] {
            let needle = format!("reason=\"{reason}\"");
            assert!(
                body.contains(&needle),
                "expected `{needle}` in scrape; forwarding-phase close reasons must not collapse to `completed`:\n{body}"
            );
        }
    }

    #[test]
    fn all_close_reasons_are_distinguishable() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let reasons = [
            "completed",
            "error",
            "shutdown",
            "session_timeout",
            "max_duration",
            "sni_timeout",
            "filter_rejection",
            "connect_failure",
            "peeked_write_error",
        ];
        for reason in reasons {
            record_tcp_connection_duration(SharedString::const_str("all-reasons"), reason, 1.0);
        }
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        for reason in reasons {
            let needle = format!("reason=\"{reason}\"");
            assert!(
                body.contains(&needle),
                "expected `{needle}` in scrape; all close reasons must be tracked separately:\n{body}"
            );
        }
    }

    #[test]
    fn connection_accepted_counter_accumulates() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_accepted(SharedString::const_str("counter-listener"));
        record_tcp_connection_accepted(SharedString::const_str("counter-listener"));
        record_tcp_connection_accepted(SharedString::const_str("counter-listener"));
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connections_total{listener=\"counter-listener\"} 3"),
            "connection counter should sum all accepted connections:\n{body}"
        );
    }

    #[test]
    fn zero_bytes_transfer_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_bytes(SharedString::const_str("zero-bytes"), 0, 0);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"zero-bytes\"} 0"),
            "zero received bytes should be recorded:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"zero-bytes\"} 0"),
            "zero sent bytes should be recorded:\n{body}"
        );
    }

    #[test]
    fn large_bytes_transfer_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let large = u64::MAX / 2;
        record_tcp_bytes(SharedString::const_str("large-bytes"), large, large);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        let expected_received = format!("praxis_tcp_bytes_received_total{{listener=\"large-bytes\"}} {large}");
        let expected_sent = format!("praxis_tcp_bytes_sent_total{{listener=\"large-bytes\"}} {large}");
        assert!(
            body.contains(&expected_received),
            "large received byte count should be recorded:\n{body}"
        );
        assert!(
            body.contains(&expected_sent),
            "large sent byte count should be recorded:\n{body}"
        );
    }

    #[test]
    fn asymmetric_traffic_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_bytes(SharedString::const_str("asymmetric"), 1000, 10);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"asymmetric\"} 1000"),
            "asymmetric traffic (upload-heavy) should record received separately:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"asymmetric\"} 10"),
            "asymmetric traffic (upload-heavy) should record sent separately:\n{body}"
        );
    }

    #[test]
    fn download_heavy_traffic_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_bytes(SharedString::const_str("download"), 50, 5000);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"download\"} 50"),
            "download-heavy traffic should record received separately:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"download\"} 5000"),
            "download-heavy traffic should record sent separately:\n{body}"
        );
    }

    #[test]
    fn duration_histogram_records_various_durations() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_duration(SharedString::const_str("hist"), "completed", 0.001);
        record_tcp_connection_duration(SharedString::const_str("hist"), "completed", 0.1);
        record_tcp_connection_duration(SharedString::const_str("hist"), "completed", 1.0);
        record_tcp_connection_duration(SharedString::const_str("hist"), "completed", 10.0);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connection_duration_seconds"),
            "histogram metric should be present:\n{body}"
        );
        assert!(
            body.contains("listener=\"hist\""),
            "histogram should include listener label:\n{body}"
        );
        assert!(
            body.contains("reason=\"completed\""),
            "histogram should include reason label:\n{body}"
        );
    }

    #[test]
    fn multiple_active_connection_guards_are_independent() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let guard1 = TcpActiveConnectionGuard::acquire(SharedString::const_str("multi"));
        let guard2 = TcpActiveConnectionGuard::acquire(SharedString::const_str("multi"));
        let guard3 = TcpActiveConnectionGuard::acquire(SharedString::const_str("multi"));
        let held = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            held.contains("praxis_tcp_active_connections{listener=\"multi\"} 3"),
            "gauge should sum all held guards:\n{held}"
        );
        drop(guard2);
        let after_one_drop = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            after_one_drop.contains("praxis_tcp_active_connections{listener=\"multi\"} 2"),
            "gauge should decrement by one after dropping one guard:\n{after_one_drop}"
        );
        drop(guard1);
        drop(guard3);
        let all_dropped = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            all_dropped.contains("praxis_tcp_active_connections{listener=\"multi\"} 0"),
            "gauge should return to zero after all guards drop:\n{all_dropped}"
        );
    }

    #[test]
    fn connection_accepted_different_listeners() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_accepted(SharedString::const_str("listener-a"));
        record_tcp_connection_accepted(SharedString::const_str("listener-a"));
        record_tcp_connection_accepted(SharedString::const_str("listener-b"));
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connections_total{listener=\"listener-a\"} 2"),
            "listener-a should have 2 connections:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_connections_total{listener=\"listener-b\"} 1"),
            "listener-b should have 1 connection:\n{body}"
        );
    }

    #[test]
    fn bytes_different_listeners() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_bytes(SharedString::const_str("listener-x"), 100, 200);
        record_tcp_bytes(SharedString::const_str("listener-y"), 300, 400);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"listener-x\"} 100"),
            "listener-x received should be separate:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"listener-x\"} 200"),
            "listener-x sent should be separate:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_received_total{listener=\"listener-y\"} 300"),
            "listener-y received should be separate:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total{listener=\"listener-y\"} 400"),
            "listener-y sent should be separate:\n{body}"
        );
    }

    #[test]
    fn duration_different_listeners() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_duration(SharedString::const_str("listener-1"), "completed", 1.5);
        record_tcp_connection_duration(SharedString::const_str("listener-2"), "error", 0.5);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("listener=\"listener-1\"") && body.contains("reason=\"completed\""),
            "listener-1 with completed reason should be recorded:\n{body}"
        );
        assert!(
            body.contains("listener=\"listener-2\"") && body.contains("reason=\"error\""),
            "listener-2 with error reason should be recorded:\n{body}"
        );
    }

    #[test]
    fn guard_across_different_listeners() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let guard_a = TcpActiveConnectionGuard::acquire(SharedString::const_str("guard-a"));
        let guard_b1 = TcpActiveConnectionGuard::acquire(SharedString::const_str("guard-b"));
        let guard_b2 = TcpActiveConnectionGuard::acquire(SharedString::const_str("guard-b"));
        let held = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            held.contains("praxis_tcp_active_connections{listener=\"guard-a\"} 1"),
            "guard-a should have 1 connection:\n{held}"
        );
        assert!(
            held.contains("praxis_tcp_active_connections{listener=\"guard-b\"} 2"),
            "guard-b should have 2 connections:\n{held}"
        );
        drop(guard_a);
        drop(guard_b1);
        drop(guard_b2);
    }

    #[test]
    fn negative_duration_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_duration(SharedString::const_str("negative"), "error", -1.0);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connection_duration_seconds"),
            "negative duration should not panic and metric should exist:\n{body}"
        );
    }

    #[test]
    fn very_long_duration_is_recorded() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        let one_week = 7.0 * 24.0 * 3600.0;
        record_tcp_connection_duration(SharedString::const_str("week-long"), "completed", one_week);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connection_duration_seconds"),
            "week-long duration should be recorded:\n{body}"
        );
    }

    #[test]
    fn metric_names_are_correct() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_accepted(SharedString::const_str("check-names"));
        record_tcp_connection_duration(SharedString::const_str("check-names"), "completed", 1.0);
        record_tcp_bytes(SharedString::const_str("check-names"), 100, 200);
        let _guard = TcpActiveConnectionGuard::acquire(SharedString::const_str("check-names"));
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(
            body.contains("praxis_tcp_connections_total"),
            "connections counter metric name should be correct:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_connection_duration_seconds"),
            "duration histogram metric name should be correct:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_sent_total"),
            "bytes sent counter metric name should be correct:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_bytes_received_total"),
            "bytes received counter metric name should be correct:\n{body}"
        );
        assert!(
            body.contains("praxis_tcp_active_connections"),
            "active connections gauge metric name should be correct:\n{body}"
        );
    }

    #[test]
    fn listener_label_name_is_correct() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_accepted(SharedString::const_str("label-test"));
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(body.contains("listener="), "listener label should be present:\n{body}");
    }

    #[test]
    fn reason_label_name_is_correct() {
        crate::http::pingora::metrics::install_prometheus_recorder();
        record_tcp_connection_duration(SharedString::const_str("reason-label"), "completed", 1.0);
        let body = crate::http::pingora::metrics::render_prometheus().expect("recorder should render");
        assert!(body.contains("reason="), "reason label should be present:\n{body}");
    }
}
