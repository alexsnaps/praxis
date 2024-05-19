//! YAML configuration parsing, defaults, and validation.

use std::path::Path;

use serde::Deserialize;

use crate::errors::ProxyError;

mod cluster;
mod condition;
mod filter_chain;
mod listener;
mod pipeline;
mod route;
mod runtime;
mod validate;

pub use cluster::{Cluster, ConsistentHashOpts, Endpoint, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy};
pub use condition::{Condition, ConditionMatch, ResponseCondition, ResponseConditionMatch};
pub use filter_chain::FilterChainConfig;
pub use listener::{Listener, ProtocolKind, TlsConfig};
pub use pipeline::FilterEntry;
pub use route::Route;
pub use runtime::RuntimeConfig;

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Top-level proxy configuration.
///
/// ```
/// use praxis_core::config::Config;
///
/// let config = Config::from_yaml(r#"
/// listeners:
///   - name: web
///     address: "127.0.0.1:8080"
/// routes:
///   - path_prefix: "/"
///     cluster: "web"
/// clusters:
///   - name: "web"
///     endpoints: ["10.0.0.1:8080"]
/// "#).unwrap();
/// assert_eq!(config.listeners[0].address, "127.0.0.1:8080");
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct Config {
    /// Optional admin listener for health check endpoints (e.g. `/ready`, `/healthy`).
    #[serde(default)]
    pub admin_address: Option<String>,

    /// Cluster definitions referenced by filters.
    #[serde(default)]
    pub clusters: Vec<Cluster>,

    /// Named filter chains.
    #[serde(default)]
    pub filter_chains: Vec<FilterChainConfig>,

    /// Proxy listeners to bind.
    pub listeners: Vec<Listener>,

    /// Legacy filter pipeline entries (executed in order).
    ///
    /// Populated by [`apply_defaults`] from top-level `routes`/`clusters`
    /// when no explicit pipeline or filter chains are configured.
    ///
    /// [`apply_defaults`]: Config::apply_defaults
    #[serde(default)]
    pub pipeline: Vec<FilterEntry>,

    /// Top-level routes.
    #[serde(default)]
    pub routes: Vec<Route>,

    /// Runtime configuration knobs.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Hard ceiling on request body size in bytes. No filter can override this limit.
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,

    /// Hard ceiling on response body size in bytes. No filter can override this limit.
    #[serde(default)]
    pub max_response_body_bytes: Option<usize>,

    /// Drain time for graceful shutdown.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

impl Config {
    /// Parse config from a YAML string.
    ///
    /// ```
    /// use praxis_core::config::Config;
    ///
    /// let cfg = Config::from_yaml(r#"
    /// listeners:
    ///   - name: web
    ///     address: "127.0.0.1:8080"
    /// routes:
    ///   - path_prefix: "/"
    ///     cluster: web
    /// clusters:
    ///   - name: web
    ///     endpoints: ["10.0.0.1:80"]
    /// "#).unwrap();
    /// assert_eq!(cfg.listeners[0].address, "127.0.0.1:8080");
    /// ```
    pub fn from_yaml(s: &str) -> Result<Self, ProxyError> {
        const MAX_YAML_BYTES: usize = 4 * 1024 * 1024; // 4 MiB (no yaml bombs, thx)

        if s.len() > MAX_YAML_BYTES {
            return Err(ProxyError::Config(format!(
                "YAML input too large ({} bytes, max {MAX_YAML_BYTES})",
                s.len()
            )));
        }

        let mut config: Config =
            serde_yaml::from_str(s).map_err(|e| ProxyError::Config(format!("invalid YAML: {e}")))?;

        config.apply_defaults();
        config.validate()?;

        Ok(config)
    }

    /// Load and validate config from a YAML file.
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use praxis_core::config::Config;
    ///
    /// let cfg = Config::from_file(Path::new("praxis.yaml")).unwrap();
    /// println!("listeners: {}", cfg.listeners.len());
    /// ```
    pub fn from_file(path: &Path) -> Result<Self, ProxyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(format!("failed to read {}: {e}", path.display())))?;

        Self::from_yaml(&content)
    }

    /// Resolve configuration file. Fall back to `praxis.yaml` in the working directory, then `fallback_yaml`.
    ///
    /// ```no_run
    /// use praxis_core::config::Config;
    ///
    /// let yaml = "listeners: [{name: w, address: '0:80'}]";
    /// let cfg = Config::load(None, yaml).unwrap();
    /// ```
    pub fn load(explicit_path: Option<&str>, fallback_yaml: &str) -> Result<Self, ProxyError> {
        match explicit_path {
            Some(path) => Self::from_file(Path::new(path)),
            None => {
                let default_path = Path::new("praxis.yaml");
                if default_path.exists() {
                    Self::from_file(default_path)
                } else {
                    tracing::info!("no config file found, using built-in default");
                    Self::from_yaml(fallback_yaml)
                }
            },
        }
    }

    /// If no pipeline is configured but legacy routes are present,
    /// generate a default pipeline of [`router`, `load_balancer`].
    pub(crate) fn apply_defaults(&mut self) {
        tracing::debug!("converting legacy routes to pipeline format");
        if self.pipeline.is_empty() && !self.routes.is_empty() {
            self.pipeline = vec![
                pipeline::build_router_entry(&self.routes),
                pipeline::build_lb_entry(&self.clusters),
            ];
        }

        tracing::debug!("converting legacy pipeline to default filter chain");
        if !self.pipeline.is_empty() && self.filter_chains.is_empty() {
            self.filter_chains.push(filter_chain::FilterChainConfig {
                name: "default".to_owned(),
                filters: self.pipeline.clone(),
            });
            for listener in &mut self.listeners {
                if listener.protocol == ProtocolKind::Http && listener.filter_chains.is_empty() {
                    listener.filter_chains.push("default".to_owned());
                }
            }
        }
    }
}

/// Serde default for [`Config::shutdown_timeout_secs`].
fn default_shutdown_timeout_secs() -> u64 {
    30
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        Cluster, Config, Route,
        pipeline::{build_lb_entry, build_router_entry},
    };

    const VALID_YAML: &str = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: "backend"
clusters:
  - name: "backend"
    endpoints:
      - "127.0.0.1:3000"
"#;

    #[test]
    fn parse_valid_config() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(config.listeners.len(), 1, "should have 1 listener");
        assert_eq!(
            config.listeners[0].address, "127.0.0.1:8080",
            "listener address mismatch"
        );
        assert_eq!(config.routes.len(), 1, "should have 1 route");
        assert_eq!(config.routes[0].path_prefix, "/", "route prefix mismatch");
        assert_eq!(&*config.routes[0].cluster, "backend", "route cluster mismatch");
        assert_eq!(config.clusters.len(), 1, "should have 1 cluster");
        assert_eq!(
            config.clusters[0].endpoints[0].address(),
            "127.0.0.1:3000",
            "endpoint mismatch"
        );
    }

    #[test]
    fn legacy_config_generates_pipeline() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(config.pipeline.len(), 2, "legacy should generate 2-stage pipeline");
        assert_eq!(config.pipeline[0].filter_type, "router", "first entry should be router");
        assert_eq!(
            config.pipeline[1].filter_type, "load_balancer",
            "second should be load_balancer"
        );
    }

    #[test]
    fn parse_pipeline_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "web"
  - filter: load_balancer
    clusters:
      - name: "web"
        endpoints: ["10.0.0.1:8080"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.pipeline.len(), 2, "pipeline should have 2 entries");
        assert_eq!(config.pipeline[0].filter_type, "router", "first should be router");
        assert_eq!(
            config.pipeline[1].filter_type, "load_balancer",
            "second should be load_balancer"
        );
    }

    #[test]
    fn parse_config_with_tls() {
        let yaml = r#"
listeners:
  - name: secure
    address: "0.0.0.0:443"
    tls:
      cert_path: "/etc/ssl/cert.pem"
      key_path: "/etc/ssl/key.pem"
routes:
  - path_prefix: "/"
    cluster: "web"
clusters:
  - name: "web"
    endpoints: ["10.0.0.1:8080"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        assert_eq!(tls.cert_path, "/etc/ssl/cert.pem", "cert_path mismatch");
    }

    #[test]
    fn parse_config_with_host_routing() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    host: "api.example.com"
    cluster: "api"
  - path_prefix: "/"
    cluster: "web"
clusters:
  - name: "api"
    endpoints: ["10.0.0.1:8080"]
  - name: "web"
    endpoints: ["10.0.0.2:8080"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.routes.len(), 2, "should have 2 routes");
        assert_eq!(
            config.routes[0].host.as_deref(),
            Some("api.example.com"),
            "first route host mismatch"
        );
        assert!(config.routes[1].host.is_none(), "second route should have no host");
    }

    #[test]
    fn load_from_file() {
        let dir = std::env::temp_dir().join("praxis-config-test");
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.yaml");
        std::fs::write(&path, VALID_YAML).unwrap();

        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.listeners.len(), 1, "file-loaded config should have 1 listener");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_from_missing_file() {
        let err = Config::from_file(Path::new("/nonexistent/config.yaml")).unwrap_err();
        assert!(
            err.to_string().contains("failed to read"),
            "should report file read failure"
        );
    }

    #[test]
    fn build_router_entry_creates_router_filter() {
        let routes = vec![Route {
            path_prefix: "/api/".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }];
        let entry = build_router_entry(&routes);
        assert_eq!(entry.filter_type, "router", "entry filter_type should be router");
        let routes_value = entry.config.get("routes").unwrap();
        assert!(routes_value.is_sequence(), "routes config should be a sequence");
    }

    #[test]
    fn build_lb_entry_creates_load_balancer_filter() {
        let clusters = vec![Cluster {
            name: "web".into(),
            endpoints: vec!["10.0.0.1:80".into()],
            connection_timeout_ms: None,
            idle_timeout_ms: None,
            load_balancer_strategy: Default::default(),
            read_timeout_ms: None,
            total_connection_timeout_ms: None,
            upstream_sni: None,
            upstream_tls: false,
            write_timeout_ms: None,
        }];
        let entry = build_lb_entry(&clusters);
        assert_eq!(
            entry.filter_type, "load_balancer",
            "entry filter_type should be load_balancer"
        );
        let clusters_value = entry.config.get("clusters").unwrap();
        assert!(clusters_value.is_sequence(), "clusters config should be a sequence");
    }

    #[test]
    fn default_shutdown_timeout_is_30() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
routes:
  - path_prefix: "/"
    cluster: "web"
clusters:
  - name: "web"
    endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.shutdown_timeout_secs, 30,
            "default shutdown timeout should be 30s"
        );
    }

    #[test]
    fn default_runtime_config() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(config.runtime.threads, 0, "default threads should be 0");
        assert!(config.runtime.work_stealing, "default work_stealing should be true");
    }

    #[test]
    fn max_body_bytes_defaults_to_none() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert!(
            config.max_request_body_bytes.is_none(),
            "max_request_body_bytes should default to None"
        );
        assert!(
            config.max_response_body_bytes.is_none(),
            "max_response_body_bytes should default to None"
        );
    }

    #[test]
    fn reject_oversized_yaml() {
        let huge = "x".repeat(5 * 1024 * 1024);
        let err = Config::from_yaml(&huge).unwrap_err();
        assert!(err.to_string().contains("too large"), "should reject oversized YAML");
    }

    #[test]
    fn parse_max_body_bytes() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
max_request_body_bytes: 10485760
max_response_body_bytes: 5242880
routes:
  - path_prefix: "/"
    cluster: "web"
clusters:
  - name: "web"
    endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.max_request_body_bytes,
            Some(10_485_760),
            "request body limit mismatch"
        );
        assert_eq!(
            config.max_response_body_bytes,
            Some(5_242_880),
            "response body limit mismatch"
        );
    }

    #[test]
    fn parse_runtime_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
runtime:
  threads: 8
  work_stealing: false
routes:
  - path_prefix: "/"
    cluster: "web"
clusters:
  - name: "web"
    endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.runtime.threads, 8, "threads should be 8");
        assert!(!config.runtime.work_stealing, "work_stealing should be false");
    }

    #[test]
    fn load_returns_err_for_missing_explicit_path() {
        let err = Config::load(Some("/nonexistent/config.yaml"), "").unwrap_err();
        assert!(
            err.to_string().contains("failed to read"),
            "should report file read failure"
        );
    }

    #[test]
    fn load_uses_fallback_yaml() {
        let fallback = r#"
listeners:
  - name: fallback
    address: "127.0.0.1:9999"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let config = Config::load(None, fallback).unwrap();
        assert_eq!(config.listeners[0].name, "fallback", "should use fallback config");
    }

    #[test]
    fn apply_defaults_creates_filter_chain_from_legacy_pipeline() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "web"
  - filter: load_balancer
    clusters:
      - name: "web"
        endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.filter_chains.len(), 1, "should create one default chain");
        assert_eq!(
            config.filter_chains[0].name, "default",
            "auto-chain should be named 'default'"
        );
        assert_eq!(
            config.filter_chains[0].filters.len(),
            2,
            "default chain should have 2 filters"
        );
        assert_eq!(
            config.listeners[0].filter_chains,
            vec!["default"],
            "listener should reference default chain"
        );
    }

    #[test]
    fn downstream_read_timeout_per_listener_isolation() {
        let yaml = r#"
listeners:
  - name: fast
    address: "127.0.0.1:8080"
    downstream_read_timeout_ms: 500
    filter_chains: [main]
  - name: slow
    address: "127.0.0.1:8081"
    downstream_read_timeout_ms: 30000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].downstream_read_timeout_ms,
            Some(500),
            "fast listener should have 500ms timeout"
        );
        assert_eq!(
            config.listeners[1].downstream_read_timeout_ms,
            Some(30000),
            "slow listener should have 30000ms timeout"
        );
    }

    #[test]
    fn all_example_configs_parse() {
        let root = format!("{}/../examples/configs", env!("CARGO_MANIFEST_DIR"));
        let mut count = 0;
        for entry in walkdir(&root) {
            Config::from_file(&entry).unwrap_or_else(|e| panic!("{}: {e}", entry.display()));
            count += 1;
        }
        assert!(count > 0, "no YAML files found in {root}");
    }

    #[test]
    fn parse_named_filter_chains() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains:
      - observability
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.filter_chains.len(), 2, "should have 2 named chains");
        assert_eq!(
            config.filter_chains[0].name, "observability",
            "first chain name mismatch"
        );
        assert_eq!(config.filter_chains[1].name, "routing", "second chain name mismatch");
        assert_eq!(
            config.listeners[0].filter_chains,
            vec!["observability", "routing"],
            "listener chain references mismatch"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Recursively collect all `.yaml` files under `root`.
    fn walkdir(root: &str) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "yaml") {
                    files.push(path);
                }
            }
        }
        files
    }
}
