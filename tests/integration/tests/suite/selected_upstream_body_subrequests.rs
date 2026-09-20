// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the selected-upstream request-body phase in the
//! filtered-subrequest / iterative_request_router path (#1138): the phase runs
//! after each step selects an upstream, its adapted body is what the step
//! forwards and frames, adaptation runs exactly once per step (no compounding),
//! rejections short-circuit before dialing, and selected-cluster metadata is
//! isolated across steps.

use std::sync::Arc;

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
    Rejection, SelectedUpstreamBodyOutcome,
};
use praxis_test_utils::{
    free_port, http_post, http_send, parse_body, parse_status, start_echo_backend, start_full_proxy_with_registry,
    start_header_echo_backend,
};

// -----------------------------------------------------------------------------
// Test Participant Filters (public API only)
// -----------------------------------------------------------------------------

/// Appends a fixed non-idempotent marker to the request body during the
/// selected-upstream phase (mirrors the #1191 append-marker participant).
struct AppendMarkerFilter;

#[async_trait::async_trait]
impl HttpFilter for AppendMarkerFilter {
    fn name(&self) -> &'static str {
        "test_su_append_marker"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        let mut bytes = body.as_ref().map_or_else(Vec::new, |b| b.to_vec());
        bytes.extend_from_slice(b"|adapted");
        *body = Some(Bytes::from(bytes));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Replaces the body with an oversized payload, exceeding a 64-byte StreamBuffer.
struct ExpandFilter;

#[async_trait::async_trait]
impl HttpFilter for ExpandFilter {
    fn name(&self) -> &'static str {
        "test_su_expand"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(64) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        *body = Some(Bytes::from_static(
            b"OVERSIZED_OUTPUT_THAT_IS_DELIBERATELY_LONGER_THAN_THE_SIXTY_FOUR_BYTE_STREAM_BUFFER_LIMIT_XXXX",
        ));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Rejects with 403 during the selected-upstream phase (read-only participant).
struct RejectFilter;

#[async_trait::async_trait]
impl HttpFilter for RejectFilter {
    fn name(&self) -> &'static str {
        "test_su_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        Ok(SelectedUpstreamBodyOutcome::Reject(Rejection::status(403)))
    }
}

/// Rejects with 409 during the selected-upstream phase iff a selected-application
/// provider is visible — turning a cross-step metadata leak into an observable
/// status so a test can assert isolation through the public reader.
struct ProviderLeakGuardFilter;

#[async_trait::async_trait]
impl HttpFilter for ProviderLeakGuardFilter {
    fn name(&self) -> &'static str {
        "test_su_provider_leak_guard"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        if ctx.selected_application_provider().is_some() {
            return Ok(SelectedUpstreamBodyOutcome::Reject(Rejection::status(409)));
        }
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

// `irr_yaml` in iterative_request_router.rs is private to that module; integration
// modules do not share private utilities, so this file builds its own IRR config
// strings inline (mirroring the config shapes in iterative_request_router.rs).

fn register(name: &'static str, make: fn() -> Box<dyn HttpFilter>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(name, FilterFactory::Http(Arc::new(move |_config| Ok(make()))))
        .unwrap();
    registry
}

#[test]
fn irr_step_adapts_body_and_forwards_adapted_bytes() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(status, 200);
    // Exactly one marker proves the phase ran once in the step and its adapted
    // output is what the step forwarded upstream.
    assert_eq!(body, "hello|adapted", "the step forwards the adapted body");
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the phase runs exactly once per step"
    );
}

#[test]
fn irr_step_recomputes_content_length_and_strips_transfer_encoding() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    // Canonical "hello" is 5 bytes; adapted "hello|adapted" is 13 bytes.
    let raw = http_send(
        proxy.addr(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "chunked request with adapted body succeeds");
    let echoed = parse_body(&raw);
    let lines: Vec<&str> = echoed
        .lines()
        .filter(|l| l.trim_start().to_ascii_lowercase().starts_with("content-length:"))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one content-length upstream, got:\n{echoed}");
    assert!(
        lines[0].to_ascii_lowercase().contains("13"),
        "content-length must reflect the adapted length (13), got {:?}",
        lines[0]
    );
    assert!(
        !echoed
            .to_ascii_lowercase()
            .lines()
            .any(|l| l.trim_start().starts_with("transfer-encoding:")),
        "transfer-encoding must not survive alongside the stamped content-length:\n{echoed}"
    );
}

#[test]
fn irr_adapts_each_step_input_exactly_once_without_compounding() {
    let backend_a = start_echo_backend();
    let backend_b = start_echo_backend();
    let proxy_port = free_port();
    // Step `primary` transitions to `secondary`; each step appends the marker to
    // its OWN input. `secondary`'s input is the original request body (the IRR
    // defaults the next iteration body to the original when no filter sets a next
    // body), so a correct implementation appends one marker per step and never
    // feeds a step's adapted output into the next. The final response is
    // `secondary`'s echoed body: exactly one marker proves no compounding.
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: a
              - filter: load_balancer
                clusters:
                  - name: a
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                next: secondary
          - name: secondary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: b
              - filter: load_balancer
                clusters:
                  - name: b
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_append_marker
            on_result:
              - default: true
                done: true
"#,
        backend_a.port(),
        backend_b.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_append_marker", || Box::new(AppendMarkerFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(status, 200);
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "each step adapts its own input exactly once; adaptation must not compound across steps (got {body:?})"
    );
}

#[test]
fn irr_step_does_not_observe_prior_step_provider() {
    let backend_a = start_echo_backend();
    let backend_b = start_echo_backend();
    let proxy_port = free_port();
    // `primary` selects a provider-tagged cluster; `secondary` selects an
    // untagged cluster and guards against observing any provider. If the tagged
    // provider leaked across the step boundary, `secondary` would reject with
    // 409. A 200 proves per-step isolation (the leak guard saw no provider).
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: a
              - filter: load_balancer
                clusters:
                  - name: a
                    endpoints: ["127.0.0.1:{}"]
                    http:
                      application_provider: prova
            on_result:
              - default: true
                next: secondary
          - name: secondary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: b
              - filter: load_balancer
                clusters:
                  - name: b
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_provider_leak_guard
            on_result:
              - default: true
                done: true
"#,
        backend_a.port(),
        backend_b.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_provider_leak_guard", || Box::new(ProviderLeakGuardFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "hello");

    assert_eq!(
        status, 200,
        "the second step must not observe the first step's selected-application provider"
    );
}

#[test]
fn irr_step_reject_short_circuits_before_dialing() {
    let dead_backend = free_port();
    let proxy_port = free_port();
    // No backend on `dead_backend`: a dial would surface as 5xx. The phase
    // rejection returns 403 locally, proving it short-circuits before dialing.
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{dead_backend}"]
              - filter: test_su_reject
            on_result:
              - default: true
                done: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_reject", || Box::new(RejectFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "blocked");

    assert_eq!(status, 403, "the phase rejection returns 403, not a 5xx from a dial");
}

#[test]
fn irr_step_oversized_adapted_output_is_rejected_with_413() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        initial_step: primary
        steps:
          - name: primary
            filters:
              - filter: router
                routes:
                  - path_prefix: "/"
                    cluster: backend
              - filter: load_balancer
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{}"]
              - filter: test_su_expand
            on_result:
              - default: true
                done: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = register("test_su_expand", || Box::new(ExpandFilter));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "tiny");

    assert_eq!(
        status, 413,
        "adapted output over the effective limit is rejected with 413"
    );
}
