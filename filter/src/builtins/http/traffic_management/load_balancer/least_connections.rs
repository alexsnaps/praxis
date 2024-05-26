//! Least-connections endpoint selection with in-flight tracking.

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

// -----------------------------------------------------------------------------
// LeastConnections
// -----------------------------------------------------------------------------

/// Picks the endpoint with the fewest active in-flight requests.
pub(super) struct LeastConnections {
    /// Ordered list of unique endpoint addresses (for deterministic tie-breaking).
    endpoints: Vec<String>,

    /// Per-endpoint active-request counter.
    pub(super) counters: HashMap<String, AtomicUsize>,

    /// Serializes `select` calls so the find-min and increment
    /// are atomic with respect to each other.
    select_lock: Mutex<()>,
}

impl LeastConnections {
    /// Create a least-connections selector.
    pub(super) fn new(endpoints: Vec<String>) -> Self {
        let mut seen = std::collections::HashSet::new();
        let mut unique: Vec<String> = Vec::new();
        let mut counters: HashMap<String, AtomicUsize> = HashMap::new();

        for addr in endpoints {
            if seen.insert(addr.clone()) {
                counters.insert(addr.clone(), AtomicUsize::new(0));
                unique.push(addr);
            }
        }

        Self {
            endpoints: unique,
            counters,
            select_lock: Mutex::new(()),
        }
    }

    /// Pick the endpoint with the fewest in-flight requests.
    pub(super) fn select(&self) -> &str {
        let _guard = self.select_lock.lock().expect("select lock poisoned");

        let addr = self
            .endpoints
            .iter()
            .min_by_key(|a| self.counters[a.as_str()].load(Ordering::Relaxed))
            .expect("endpoints must be non-empty");

        self.counters[addr.as_str()].fetch_add(1, Ordering::Relaxed);

        addr
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(super) fn release(&self, addr: &str) {
        if let Some(counter) = self.counters.get(addr) {
            // Saturating decrement: prevents underflow if `release` is called
            // without a matching `select` (e.g. for rejected requests).
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn selects_min() {
        let lc = LeastConnections::new(vec![
            "10.0.0.1:80".to_string(),
            "10.0.0.2:80".to_string(),
            "10.0.0.3:80".to_string(),
        ]);

        assert_eq!(
            lc.select(),
            "10.0.0.1:80",
            "first selection should go to first endpoint"
        );
        assert_eq!(lc.select(), "10.0.0.2:80", "second selection should pick least-loaded");
        lc.release("10.0.0.1:80");
        assert_eq!(lc.select(), "10.0.0.1:80", "released endpoint should be selected again");
    }

    #[test]
    fn release_does_not_underflow() {
        let lc = LeastConnections::new(vec!["10.0.0.1:80".to_string()]);

        lc.release("10.0.0.1:80");
        assert_eq!(
            lc.counters["10.0.0.1:80"].load(Ordering::Relaxed),
            0,
            "release without select should not underflow"
        );
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let lc = LeastConnections::new(vec!["10.0.0.1:80".to_string()]);

        lc.release("10.0.0.99:80");
    }
}
