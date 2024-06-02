//! Admin health-check HTTP service (`/ready`, `/healthy`).

use async_trait::async_trait;
use http::Response;
use pingora_core::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, server::Server, services::listening::Service,
};
use tracing::info;

use super::json::json_response;

// -----------------------------------------------------------------------------
// HealthService
// -----------------------------------------------------------------------------

/// HTTP service for health check endpoints.
///
/// `/ready` and `/healthy` both return 200 once the server is accepting connections.
///
/// ```no_run
/// use praxis_protocol::http::pingora::health::HealthService;
///
/// let _svc = HealthService;
/// ```
pub struct HealthService;

/// Add the health check endpoints to a Pingora server.
///
/// Binds a [`HealthService`] to `admin_addr`, exposing `/ready` and `/healthy` endpoints.
///
/// ```no_run
/// use pingora_core::server::Server;
/// use praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server;
///
/// let mut server = Server::new(None).unwrap();
/// server.bootstrap();
/// add_health_endpoint_to_pingora_server(&mut server, "127.0.0.1:9090");
/// ```
pub fn add_health_endpoint_to_pingora_server(server: &mut Server, admin_addr: &str) {
    let mut health_service = Service::new("health".to_owned(), HealthService);
    health_service.add_tcp(admin_addr);
    info!(address = %admin_addr, "health endpoints enabled");
    server.add_service(health_service);
}

#[async_trait]
impl ServeHttp for HealthService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path().to_owned();

        match path.as_str() {
            "/ready" | "/healthy" => json_response(200, br#"{"status":"ok"}"#),
            _ => json_response(404, br#"{"error":"not found"}"#),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_response_200() {
        let resp = json_response(200, b"{}");
        assert_eq!(resp.status(), 200, "status should be 200");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be JSON"
        );
        assert_eq!(resp.body(), b"{}", "body should match input");
    }

    #[test]
    fn json_response_404() {
        let resp = json_response(404, br#"{"error":"not found"}"#);
        assert_eq!(resp.status(), 404, "status should be 404");
        assert_eq!(resp.body(), br#"{"error":"not found"}"#, "body should match input");
    }

    #[test]
    fn ready_response_body_matches() {
        let body = br#"{"status":"ok"}"#;
        let resp = json_response(200, body);
        assert_eq!(resp.body().as_slice(), body, "ready body should match input");
    }

    #[test]
    fn not_found_response_body_matches() {
        let body = br#"{"error":"not found"}"#;
        let resp = json_response(404, body);
        assert_eq!(resp.body().as_slice(), body, "not-found body should match input");
    }

    #[test]
    fn json_response_content_type_is_application_json() {
        let resp = json_response(503, b"{}");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be application/json"
        );
    }

    #[test]
    fn json_response_body_matches_input() {
        let body = br#"{"ready":true,"version":"1.0"}"#;
        let resp = json_response(200, body);
        assert_eq!(resp.body().as_slice(), body, "body should match provided input bytes");
    }
}
