// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Proxy configuration builders and Docker image management for benchmark runs.

use std::path::{Path, PathBuf};

use praxis_proxy_benchmarks::proxy::{EnvoyConfig, HaproxyConfig, NginxConfig, PraxisConfig, ProxyConfig};

use super::cli::Args;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Docker image tag used when building Praxis for benchmarks.
const PRAXIS_BENCH_IMAGE: &str = "praxis-bench:latest";

/// Directory (relative to the repo root) holding the comparison proxy configs
/// retained in the praxis tree after the benchmark harness moved to its own
/// repository. The `praxis-proxy-benchmarks` library resolves config paths via
/// `PRAXIS_BENCH_CONFIG_DIR`, but xtask sets each config path explicitly so the
/// runner works from a plain `cargo xtask benchmark` with no extra environment.
const COMPARISON_CONFIG_DIR: &str = "xtask/comparison/configs";

/// Resolve a comparison config file to its path under [`COMPARISON_CONFIG_DIR`].
fn comparison_config(file: &str) -> PathBuf {
    Path::new(COMPARISON_CONFIG_DIR).join(file)
}

// -----------------------------------------------------------------------------
// Docker Build
// -----------------------------------------------------------------------------

/// Build the Praxis Docker image from the repo root
/// Containerfile. Returns the image tag.
pub(crate) fn build_praxis_image() -> String {
    let status = std::process::Command::new("docker")
        .args(["build", "-t", PRAXIS_BENCH_IMAGE, "-f", "Containerfile", "."])
        .status();

    match status {
        Ok(s) if s.success() => PRAXIS_BENCH_IMAGE.into(),
        Ok(s) => {
            eprintln!("error: docker build failed (exit {})", s.code().unwrap_or(-1));
            std::process::exit(1);
        },
        Err(e) => {
            eprintln!("error: failed to run docker build: {e}");
            std::process::exit(1);
        },
    }
}

// -----------------------------------------------------------------------------
// Proxy Config Factory
// -----------------------------------------------------------------------------

/// Build a boxed [`ProxyConfig`] for the named proxy.
///
/// All proxies run containerized with identical resource constraints.
///
/// [`ProxyConfig`]: praxis_proxy_benchmarks::proxy::ProxyConfig
pub(crate) fn build_proxy_config(name: &str, args: &Args, praxis_image: &str) -> Box<dyn ProxyConfig> {
    match name {
        "praxis" => {
            let mut config = PraxisConfig::new(praxis_image.to_owned());
            config.config = comparison_config("praxis.yaml");
            Box::new(config)
        },
        "envoy" => Box::new(EnvoyConfig {
            image: Some(args.envoy_image.clone()),
            config: comparison_config("envoy.yaml"),
            ..Default::default()
        }),
        "nginx" => Box::new(NginxConfig {
            image: Some(args.nginx_image.clone()),
            config: comparison_config("nginx.conf"),
            ..Default::default()
        }),
        "haproxy" => Box::new(HaproxyConfig {
            image: Some(args.haproxy_image.clone()),
            config: comparison_config("haproxy.cfg"),
            ..Default::default()
        }),
        other => {
            tracing::error!(proxy = other, "unknown proxy");
            std::process::exit(1);
        },
    }
}
