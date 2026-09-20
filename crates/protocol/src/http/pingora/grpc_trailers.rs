// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Trailers-Only responses for proxy-generated gRPC errors.

use pingora_core::protocols::http::HttpTask;
use pingora_proxy::Session;
use praxis_core::grpc::{GrpcStatusCode, encode_grpc_message};
use praxis_filter::GrpcErrorMapping;
use tracing::debug;

// -----------------------------------------------------------------------------
// Writer
// -----------------------------------------------------------------------------

/// Send a gRPC Trailers-Only response and end the downstream stream.
///
/// gRPC reports a failed call as HTTP `200` with a `grpc-status`, sent
/// as one header block and nothing else. On HTTP/2 that is a `HEADERS`
/// frame with `END_STREAM`; on HTTP/1.1 it is a header block with an
/// explicit `content-length: 0`, since HTTP/1.1 has no `END_STREAM` and a
/// keepalive client would otherwise read the body until an EOF that
/// never comes.
///
/// Written through `response_duplex_vec` rather than
/// `write_response_header`, because the latter hardcodes
/// `end_of_stream: false` for HTTP/2 and would emit `HEADERS` without
/// `END_STREAM` followed by a stray empty `DATA` frame. gRPC clients report
/// that as "server closed the stream without sending trailers" and lose
/// the status entirely.
pub(crate) async fn send_trailers_only(
    session: &mut Session,
    mapping: &GrpcErrorMapping,
    http_status: u16,
    message: &str,
) {
    let grpc_status = GrpcStatusCode::from_http_status(http_status);
    let Some(header) = build_header(session, mapping, grpc_status, message) else {
        return;
    };
    debug!(
        http_status,
        grpc_status = grpc_status.as_u32(),
        "sending gRPC trailers-only response"
    );
    write_header_only(session, header).await;
}

/// Send a rejection that already carries its own gRPC headers.
///
/// Used for statuses Praxis chooses itself, such as the deadline
/// filter's `DEADLINE_EXCEEDED`, which no HTTP status maps to. Framing
/// still has to go through the `END_STREAM` path, or an HTTP/2 client
/// loses the status.
pub(crate) async fn send_grpc_rejection(session: &mut Session, rejection: &praxis_filter::Rejection) {
    let mut header = match pingora_http::ResponseHeader::build(rejection.status, Some(rejection.headers.len())) {
        Ok(header) => header,
        Err(error) => {
            debug!(%error, "could not build a gRPC rejection header");
            return;
        },
    };
    for (name, value) in &rejection.headers {
        // An HTTP/2 response carries no content-length: END_STREAM on the
        // header block already says the body is empty.
        if session.req_header().version == http::Version::HTTP_2 && name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Err(error) = header.append_header(name.clone(), value.clone()) {
            debug!(%error, name, "dropping unencodable gRPC rejection header");
        }
    }
    debug!("sending gRPC rejection as a trailers-only response");
    write_header_only(session, header).await;
}

/// Write a header block that ends the downstream stream.
async fn write_header_only(session: &mut Session, header: pingora_http::ResponseHeader) {
    if let Err(error) = session
        .as_downstream_mut()
        .response_duplex_vec(vec![HttpTask::Header(Box::new(header), true)])
        .await
    {
        debug!(%error, "failed to write gRPC trailers-only response");
    }
}

/// Build the Trailers-Only header block.
fn build_header(
    session: &Session,
    mapping: &GrpcErrorMapping,
    grpc_status: GrpcStatusCode,
    message: &str,
) -> Option<pingora_http::ResponseHeader> {
    // content-type, grpc-status, grpc-message, content-length.
    let mut header = pingora_http::ResponseHeader::build(200, Some(4))
        .inspect_err(|error| debug!(%error, "could not build a gRPC error response header"))
        .ok()?;
    let _insert = header.insert_header(http::header::CONTENT_TYPE, mapping.content_type().clone());
    let _insert = header.insert_header("grpc-status", grpc_status.as_header_value());

    if mapping.include_message() && !message.is_empty() {
        // Percent-encoding is what keeps a control character in the
        // proxy's error text from splitting the header.
        let encoded = encode_grpc_message(message);
        match http::HeaderValue::from_str(&encoded) {
            Ok(value) => {
                let _insert = header.insert_header("grpc-message", value);
            },
            Err(error) => debug!(%error, "dropping unencodable grpc-message"),
        }
    }

    if session.req_header().version != http::Version::HTTP_2 {
        let _insert = header.insert_header(http::header::CONTENT_LENGTH, "0");
    }
    Some(header)
}

// Tested via integration tests in tests/integration/tests/suite/examples/grpc_status_errors.rs
// and related files, which verify the HTTP/2 END_STREAM behavior and protocol-level details
// that require a full Session context.

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    clippy::redundant_test_prefix,
    clippy::string_add,
    reason = "tests"
)]
mod tests {
    use praxis_core::grpc::GrpcKind;

    use super::*;

    fn make_test_mapping_with_message() -> GrpcErrorMapping {
        GrpcErrorMapping::new(GrpcKind::Grpc, true)
    }

    fn make_test_mapping_without_message() -> GrpcErrorMapping {
        GrpcErrorMapping::new(GrpcKind::GrpcProto, false)
    }

    #[test]
    fn test_grpc_error_mapping_include_message() {
        let mapping_with = make_test_mapping_with_message();
        assert!(mapping_with.include_message());

        let mapping_without = make_test_mapping_without_message();
        assert!(!mapping_without.include_message());
    }

    #[test]
    fn test_grpc_status_as_header_value() {
        let codes = vec![
            GrpcStatusCode::Ok,
            GrpcStatusCode::Cancelled,
            GrpcStatusCode::Unknown,
            GrpcStatusCode::InvalidArgument,
            GrpcStatusCode::DeadlineExceeded,
            GrpcStatusCode::NotFound,
            GrpcStatusCode::AlreadyExists,
            GrpcStatusCode::PermissionDenied,
            GrpcStatusCode::ResourceExhausted,
            GrpcStatusCode::FailedPrecondition,
            GrpcStatusCode::Aborted,
            GrpcStatusCode::OutOfRange,
            GrpcStatusCode::Unimplemented,
            GrpcStatusCode::Internal,
            GrpcStatusCode::Unavailable,
            GrpcStatusCode::DataLoss,
            GrpcStatusCode::Unauthenticated,
        ];

        for code in codes {
            let header_val = code.as_header_value();
            assert!(header_val.to_str().is_ok());

            let val_str = header_val.to_str().unwrap();
            assert!(val_str.parse::<u32>().is_ok(), "Invalid gRPC status: {}", val_str);
        }
    }

    #[test]
    fn test_edge_case_http_status_codes() {
        // These should all complete without panicking
        let _grpc_status = GrpcStatusCode::from_http_status(0);
        let _grpc_status = GrpcStatusCode::from_http_status(100);
        let _grpc_status = GrpcStatusCode::from_http_status(301);
        let _grpc_status = GrpcStatusCode::from_http_status(999);
    }

    #[test]
    fn test_message_encoding_edge_cases() {
        // Very long message
        let long_message = "Error: ".to_string() + &"x".repeat(1000);
        let encoded = encode_grpc_message(&long_message);
        assert!(encoded.len() >= long_message.len());

        // Message with only special characters
        let special_only = "\n\r\t";
        let encoded = encode_grpc_message(special_only);
        assert!(!encoded.is_empty());
        assert!(encoded.starts_with('%'));

        // Message with null bytes
        let with_null = "Error\0Details";
        let encoded = encode_grpc_message(with_null);
        assert!(encoded.contains("%00"));

        // Already percent-encoded message
        let already_encoded = "Error%20message";
        let encoded = encode_grpc_message(already_encoded);
        assert!(encoded.contains("%25")); // % itself gets encoded
    }

    #[test]
    fn test_content_type_variations() {
        let kinds = vec![
            (GrpcKind::Grpc, "application/grpc"),
            (GrpcKind::GrpcProto, "application/grpc+proto"),
            (GrpcKind::GrpcJson, "application/grpc+json"),
        ];

        for (kind, expected_ct) in kinds {
            let mapping = GrpcErrorMapping::new(kind, true);
            assert_eq!(mapping.content_type().to_str().unwrap(), expected_ct);
        }
    }
}
