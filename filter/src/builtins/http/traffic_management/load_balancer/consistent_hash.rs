//! Consistent-hash endpoint selection for session affinity.

use crate::filter::HttpFilterContext;

// -----------------------------------------------------------------------------
// ConsistentHash
// -----------------------------------------------------------------------------

/// Routes each request to the same endpoint by hashing a stable request
/// attribute.  Useful for session-affinity scenarios.
pub(super) struct ConsistentHash {
    /// Expanded endpoint list (weights applied via repetition).
    endpoints: Vec<String>,

    /// Header whose value is hashed.  Falls back to the URI path when `None`
    /// or when the header is absent from the request.
    header: Option<String>,
}

impl ConsistentHash {
    /// Create a consistent-hash selector with an optional hash-key header.
    pub(super) fn new(endpoints: Vec<String>, header: Option<String>) -> Self {
        Self { endpoints, header }
    }

    /// Hash the request key and return the corresponding endpoint.
    pub(super) fn select(&self, ctx: &HttpFilterContext<'_>) -> &str {
        debug_assert!(
            !self.endpoints.is_empty(),
            "consistent-hash requires at least one endpoint"
        );
        let key: &str = self
            .header
            .as_deref()
            .and_then(|h| ctx.request.headers.get(h))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| ctx.request.uri.path());

        let idx = fnv1a(key) as usize % self.endpoints.len();

        &self.endpoints[idx]
    }
}

/// FNV-1a 64-bit hash (fast)
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_same_endpoint() {
        let ch = ConsistentHash::new(vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()], None);
        let req = crate::test_utils::make_request(http::Method::GET, "/stable-path");
        let ctx = crate::test_utils::make_filter_context(&req);

        let first = ch.select(&ctx).to_owned();
        let second = ch.select(&ctx).to_owned();
        assert_eq!(first, second, "same key should always select same endpoint");
    }

    #[test]
    fn different_keys_select_different_endpoints() {
        let ch = ConsistentHash::new(vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()], None);
        let req_a = crate::test_utils::make_request(http::Method::GET, "/path-a");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = crate::test_utils::make_request(http::Method::GET, "/path-b");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);

        let ep_a = ch.select(&ctx_a);
        let ep_b = ch.select(&ctx_b);
        assert_ne!(
            ep_a, ep_b,
            "FNV-1a of /path-a and /path-b should not collide with only 2 endpoints"
        );
    }

    #[test]
    fn header_based_hashing_different_values_route_differently() {
        let endpoints: Vec<String> = (0..10).map(|i| format!("10.0.0.{i}:80")).collect();
        let ch = ConsistentHash::new(endpoints, Some("X-User-Id".to_string()));
        let req_a = make_request_with_header("/same", "X-User-Id", "user-alice");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = make_request_with_header("/same", "X-User-Id", "user-bob");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);
        let ep_a = ch.select(&ctx_a);
        let ep_b = ch.select(&ctx_b);
        assert_ne!(ep_a, ep_b, "different header values should map to different endpoints");
    }

    #[test]
    fn header_based_hashing_same_value_same_endpoint() {
        let endpoints = vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()];
        let ch = ConsistentHash::new(endpoints, Some("X-User-Id".to_string()));
        let req_a = make_request_with_header("/a", "X-User-Id", "user-42");
        let ctx_a = crate::test_utils::make_filter_context(&req_a);
        let req_b = make_request_with_header("/b", "X-User-Id", "user-42");
        let ctx_b = crate::test_utils::make_filter_context(&req_b);
        assert_eq!(
            ch.select(&ctx_a),
            ch.select(&ctx_b),
            "same header value should always route to same endpoint"
        );
    }

    #[test]
    fn missing_header_falls_back_to_uri_path() {
        let endpoints = vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()];
        let ch = ConsistentHash::new(endpoints.clone(), Some("X-User-Id".to_string()));
        let ch_path = ConsistentHash::new(endpoints, None);
        let req = crate::test_utils::make_request(http::Method::GET, "/fallback-path");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ch.select(&ctx),
            ch_path.select(&ctx),
            "missing header should fall back to URI path hashing"
        );
    }

    #[test]
    fn stability_across_repeated_calls() {
        let endpoints: Vec<String> = (0..5).map(|i| format!("10.0.0.{i}:80")).collect();
        let ch = ConsistentHash::new(endpoints, None);

        let paths = ["/api/v1/users", "/checkout", "/search?q=rust", "/", "/health"];
        for path in &paths {
            let req = crate::test_utils::make_request(http::Method::GET, path);
            let ctx = crate::test_utils::make_filter_context(&req);
            let first = ch.select(&ctx).to_owned();
            for call in 1..=100 {
                let ctx = crate::test_utils::make_filter_context(&req);
                assert_eq!(
                    ch.select(&ctx),
                    first,
                    "path {path} must map to the same endpoint on call {call}"
                );
            }
        }
    }

    #[test]
    fn add_endpoint_redistribution() {
        let original: Vec<String> = (0..3).map(|i| format!("10.0.0.{i}:80")).collect();
        let mut expanded = original.clone();
        expanded.push("10.0.0.3:80".to_string());

        let ch_original = ConsistentHash::new(original.clone(), None);
        let ch_expanded = ConsistentHash::new(expanded, None);

        let keys: Vec<String> = (0..200).map(|i| format!("/key-{i}")).collect();

        let mut stable_count = 0usize;
        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let before = ch_original.select(&ctx);
            let ctx = crate::test_utils::make_filter_context(&req);
            let after = ch_expanded.select(&ctx);
            if before == after {
                stable_count += 1;
            }
        }

        assert!(
            stable_count > 0,
            "at least some keys should remain on the same endpoint after adding one"
        );
        assert!(
            stable_count < keys.len(),
            "not all keys should stay on the same endpoint when the modulus changes from {} to {}",
            original.len(),
            original.len() + 1
        );

        let disruption_ratio = 1.0 - (stable_count as f64 / keys.len() as f64);
        assert!(
            disruption_ratio > 0.5,
            "modulo-based hashing should disrupt most keys when adding an endpoint \
             (disruption={disruption_ratio:.3}, stable={stable_count}/{})",
            keys.len()
        );
    }

    #[test]
    fn remove_endpoint_redistribution() {
        let original: Vec<String> = (0..4).map(|i| format!("10.0.0.{i}:80")).collect();
        let reduced: Vec<String> = original[..3].to_vec();

        let ch_original = ConsistentHash::new(original.clone(), None);
        let ch_reduced = ConsistentHash::new(reduced.clone(), None);

        let keys: Vec<String> = (0..200).map(|i| format!("/path-{i}")).collect();

        let mut stable_count = 0usize;
        let mut moved_to_valid = 0usize;
        let removed = &original[3];

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let before = ch_original.select(&ctx);
            let ctx = crate::test_utils::make_filter_context(&req);
            let after = ch_reduced.select(&ctx);

            assert_ne!(after, removed, "key {key} must not map to removed endpoint {removed}");

            if before == after {
                stable_count += 1;
            }

            if reduced.contains(&after.to_string()) {
                moved_to_valid += 1;
            }
        }

        assert_eq!(moved_to_valid, keys.len(), "every key must map to a surviving endpoint");
        assert!(
            stable_count > 0,
            "at least some keys should remain stable after removing an endpoint"
        );
        assert!(
            stable_count < keys.len(),
            "not all keys can stay on the same endpoint when modulus shrinks from {} to {}",
            original.len(),
            reduced.len()
        );
    }

    #[test]
    fn weight_stability() {
        let endpoints = vec![
            "10.0.0.1:80".to_string(),
            "10.0.0.1:80".to_string(),
            "10.0.0.1:80".to_string(),
            "10.0.0.2:80".to_string(),
        ];
        let ch = ConsistentHash::new(endpoints.clone(), None);

        let keys: Vec<String> = (0..300).map(|i| format!("/weighted-{i}")).collect();

        let mut ep1_count = 0usize;
        let mut ep2_count = 0usize;

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            let selected = ch.select(&ctx);

            let req2 = crate::test_utils::make_request(http::Method::GET, key);
            let ctx2 = crate::test_utils::make_filter_context(&req2);
            assert_eq!(
                ch.select(&ctx2),
                selected,
                "weighted hashing must be deterministic for key {key}"
            );

            match selected {
                "10.0.0.1:80" => ep1_count += 1,
                "10.0.0.2:80" => ep2_count += 1,
                other => panic!("unexpected endpoint {other}"),
            }
        }

        let ep1_ratio = ep1_count as f64 / keys.len() as f64;
        let expected_ep1_ratio = 0.75;
        let tolerance = 0.10;
        assert!(
            (ep1_ratio - expected_ep1_ratio).abs() < tolerance,
            "endpoint 10.0.0.1 ratio {ep1_ratio:.3} should be near {expected_ep1_ratio} \
             (ep1={ep1_count}, ep2={ep2_count}, tolerance={tolerance})"
        );
    }

    #[test]
    fn weight_stability_selection_unchanged_across_calls() {
        let endpoints = vec![
            "10.0.0.1:80".to_string(),
            "10.0.0.1:80".to_string(),
            "10.0.0.2:80".to_string(),
            "10.0.0.2:80".to_string(),
            "10.0.0.3:80".to_string(),
        ];
        let ch = ConsistentHash::new(endpoints, None);

        let keys: Vec<String> = (0..50).map(|i| format!("/stable-weight-{i}")).collect();
        let mut selections: Vec<String> = Vec::with_capacity(keys.len());

        for key in &keys {
            let req = crate::test_utils::make_request(http::Method::GET, key);
            let ctx = crate::test_utils::make_filter_context(&req);
            selections.push(ch.select(&ctx).to_owned());
        }

        for round in 1..=10 {
            for (i, key) in keys.iter().enumerate() {
                let req = crate::test_utils::make_request(http::Method::GET, key);
                let ctx = crate::test_utils::make_filter_context(&req);
                assert_eq!(
                    ch.select(&ctx),
                    selections[i],
                    "key {key} changed endpoint on round {round}"
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`Request`] with a single custom header attached.
    ///
    /// [`Request`]: crate::Request
    fn make_request_with_header(path: &str, header: &str, value: &str) -> crate::Request {
        let mut req = crate::test_utils::make_request(http::Method::GET, path);
        req.headers.insert(
            http::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(value).unwrap(),
        );
        req
    }
}
