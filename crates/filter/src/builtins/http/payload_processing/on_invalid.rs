// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared invalid-input behavior for classifier filters.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// OnInvalidBehavior
// -----------------------------------------------------------------------------

/// Behavior when the request body is not a recognized protocol format.
///
/// Used by classifier filters (e.g. JSON-RPC) to control what happens
/// when parsing fails.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OnInvalidBehavior {
    /// Continue processing without classifier metadata.
    Continue,

    /// Reject the request with HTTP 400.
    Reject,

    /// Return a filter error (pipeline failure). Only used
    /// by the JSON-RPC filter.
    Error,
}

impl OnInvalidBehavior {
    /// Default for filters that pass through unrecognized input.
    pub const fn default_continue() -> Self {
        Self::Continue
    }

    /// Default for filters that reject unrecognized input.
    pub const fn default_reject() -> Self {
        Self::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let continue_variant = OnInvalidBehavior::Continue;
        let reject_variant = OnInvalidBehavior::Reject;
        let error_variant = OnInvalidBehavior::Error;

        assert_eq!(continue_variant, OnInvalidBehavior::Continue);
        assert_eq!(reject_variant, OnInvalidBehavior::Reject);
        assert_eq!(error_variant, OnInvalidBehavior::Error);
    }

    #[test]
    fn default_continue_returns_continue() {
        assert_eq!(OnInvalidBehavior::default_continue(), OnInvalidBehavior::Continue);
    }

    #[test]
    fn default_reject_returns_reject() {
        assert_eq!(OnInvalidBehavior::default_reject(), OnInvalidBehavior::Reject);
    }

    #[test]
    fn deserialize_continue() {
        let yaml = "continue";
        let result: Result<OnInvalidBehavior, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(OnInvalidBehavior::Continue));
    }

    #[test]
    fn deserialize_reject() {
        let yaml = "reject";
        let result: Result<OnInvalidBehavior, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(OnInvalidBehavior::Reject));
    }

    #[test]
    fn deserialize_error() {
        let yaml = "error";
        let result: Result<OnInvalidBehavior, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(OnInvalidBehavior::Error));
    }

    #[test]
    fn deserialize_invalid_value() {
        let yaml = "invalid_option";
        let result: Result<OnInvalidBehavior, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "should reject invalid OnInvalidBehavior value");
    }

    #[test]
    fn debug_impl() {
        let continue_str = format!("{:?}", OnInvalidBehavior::Continue);
        let reject_str = format!("{:?}", OnInvalidBehavior::Reject);
        let error_str = format!("{:?}", OnInvalidBehavior::Error);

        assert!(continue_str.contains("Continue"));
        assert!(reject_str.contains("Reject"));
        assert!(error_str.contains("Error"));
    }

    #[test]
    fn clone_impl() {
        let original = OnInvalidBehavior::Reject;
        let cloned = original;
        assert_eq!(original, cloned);

        let continue_val = OnInvalidBehavior::Continue;
        assert_eq!(continue_val, OnInvalidBehavior::Continue);

        let error_val = OnInvalidBehavior::Error;
        assert_eq!(error_val, OnInvalidBehavior::Error);
    }

    #[test]
    fn copy_impl() {
        let original = OnInvalidBehavior::Continue;
        let copied = original;
        assert_eq!(original, copied);
        assert_eq!(original, OnInvalidBehavior::Continue);
    }

    #[test]
    fn equality_and_inequality() {
        assert_eq!(OnInvalidBehavior::Continue, OnInvalidBehavior::Continue);
        assert_eq!(OnInvalidBehavior::Reject, OnInvalidBehavior::Reject);
        assert_eq!(OnInvalidBehavior::Error, OnInvalidBehavior::Error);

        assert_ne!(OnInvalidBehavior::Continue, OnInvalidBehavior::Reject);
        assert_ne!(OnInvalidBehavior::Continue, OnInvalidBehavior::Error);
        assert_ne!(OnInvalidBehavior::Reject, OnInvalidBehavior::Error);
    }
}
