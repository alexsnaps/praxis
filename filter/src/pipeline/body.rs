//! Body capabilities computation for filter pipelines.

use super::ConditionalFilter;
use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
};

// -----------------------------------------------------------------------------
// Body Capabilities
// -----------------------------------------------------------------------------

/// Merge two optional size limits, keeping the smallest `Some` value.
pub(super) fn merge_optional_limits(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Merge all filters' body access declarations into a single capability set.
pub(super) fn compute_body_capabilities(filters: &[ConditionalFilter]) -> BodyCapabilities {
    let mut caps = BodyCapabilities::default();

    for (filter, _conditions, _resp_conditions) in filters {
        let http_filter = match filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };

        let req_access = http_filter.request_body_access();
        let resp_access = http_filter.response_body_access();

        if req_access != BodyAccess::None {
            caps.needs_request_body = true;
            if req_access == BodyAccess::ReadWrite {
                caps.any_request_body_writer = true;
            }
            match http_filter.request_body_mode() {
                BodyMode::Buffer { max_bytes } => {
                    caps.request_body_mode = match caps.request_body_mode {
                        BodyMode::Stream | BodyMode::StreamBuffer { .. } => BodyMode::Buffer { max_bytes },
                        BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                            max_bytes: existing.min(max_bytes),
                        },
                    };
                },
                BodyMode::StreamBuffer { max_bytes } => {
                    caps.request_body_mode = match caps.request_body_mode {
                        BodyMode::Stream => BodyMode::StreamBuffer { max_bytes },
                        BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                            max_bytes: merge_optional_limits(existing, max_bytes),
                        },
                        BodyMode::Buffer { .. } => caps.request_body_mode,
                    };
                },
                BodyMode::Stream => {},
            }
        }

        if resp_access != BodyAccess::None {
            caps.needs_response_body = true;
            if resp_access == BodyAccess::ReadWrite {
                caps.any_response_body_writer = true;
            }
            match http_filter.response_body_mode() {
                BodyMode::Buffer { max_bytes } => {
                    caps.response_body_mode = match caps.response_body_mode {
                        BodyMode::Stream | BodyMode::StreamBuffer { .. } => BodyMode::Buffer { max_bytes },
                        BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                            max_bytes: existing.min(max_bytes),
                        },
                    };
                },
                BodyMode::StreamBuffer { max_bytes } => {
                    caps.response_body_mode = match caps.response_body_mode {
                        BodyMode::Stream => BodyMode::StreamBuffer { max_bytes },
                        BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                            max_bytes: merge_optional_limits(existing, max_bytes),
                        },
                        BodyMode::Buffer { .. } => caps.response_body_mode,
                    };
                },
                BodyMode::Stream => {},
            }
        }

        if http_filter.needs_request_context() {
            caps.needs_request_context = true;
        }
    }

    caps
}
