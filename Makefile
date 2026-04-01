# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

VERSION ?= $(shell perl -ne 'print $$1 if /^version\s*=\s*"(.+)"/' Cargo.toml)
IMAGE   ?= praxis
V       ?=

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: build release check clean \
	test test-unit \
	test-config test-integration test-conformance test-performance test-microbenchmarks \
	test-fuzzing test-security test-resilience test-smoke \
	bench \
	lint fmt audit coverage coverage-check \
	container container-run \
	run-echo run-debug \
	tools clean-tools \
	help

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace

release:
	cargo build --workspace --release

check:
	cargo check --workspace

clean:
	cargo clean

# -------------------------------------------------------------------
# Container
# -------------------------------------------------------------------

container:
	podman build -t $(IMAGE):$(VERSION) -f Containerfile . || \
	docker build -t $(IMAGE):$(VERSION) -f Containerfile .

container-run:
	podman run --rm --network=host \
		-v $(CURDIR)/examples:/etc/praxis/examples:ro \
		$(IMAGE):$(VERSION) -c examples/configs/pipeline/default.yaml 2>&1 || \
	docker run --rm --network=host \
		-v $(CURDIR)/examples:/etc/praxis/examples:ro \
		$(IMAGE):$(VERSION) -c examples/configs/pipeline/default.yaml 2>&1

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test: $(H2SPEC)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test --workspace $(_NOCAPTURE)

test-unit:
	cargo test -p praxis-proxy-core $(_NOCAPTURE)
	cargo test -p praxis-proxy-filter $(_NOCAPTURE)
	cargo test -p praxis-proxy-protocol $(_NOCAPTURE)
	cargo test -p praxis-proxy-server $(_NOCAPTURE)

test-config:
	cargo test -p praxis-tests-config $(_NOCAPTURE)

test-integration:
	cargo test -p praxis-tests-integration $(_NOCAPTURE)

test-conformance: $(H2SPEC)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test -p praxis-tests-conformance $(_NOCAPTURE)

test-performance:
	cargo test -p praxis-tests-performance $(_NOCAPTURE)

test-microbenchmarks:
	cargo bench -p benchmarks --no-run

test-fuzzing:
	cargo test -p praxis-tests-fuzzing $(_NOCAPTURE)

test-security:
	cargo test -p praxis-tests-security $(_NOCAPTURE)

test-resilience:
	cargo test -p praxis-tests-resilience $(_NOCAPTURE)

test-config-validation:
	cargo test -p praxis-tests-config $(_NOCAPTURE)

test-smoke:
	cargo test -p praxis-tests-smoke $(_NOCAPTURE)

# -------------------------------------------------------------------
# Bench
# -------------------------------------------------------------------

bench: $(VEGETA) $(FORTIO)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo bench -p benchmarks

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace -- -D warnings
	cargo +nightly fmt --all -- --check

fmt:
	cargo +nightly fmt --all

audit:
	cargo audit
	cargo deny check

coverage:
	cargo llvm-cov --workspace --html --output-dir target/coverage \
		--exclude praxis-tests-conformance \
		--ignore-filename-regex '(target/|tests/|xtask/)' \
		--fail-under-lines 90

# -------------------------------------------------------------------
# Dev tools
# -------------------------------------------------------------------

run-echo:
	cargo xtask echo

run-debug:
	cargo xtask debug

# -------------------------------------------------------------------
# Binutils
# -------------------------------------------------------------------

BINUTILS_DIR   := target/praxis-binutils
BINUTILS_PATH  := $(CURDIR)/$(BINUTILS_DIR)

H2SPEC_VERSION := 2.6.0
VEGETA_VERSION := 12.13.0
FORTIO_VERSION := 1.75.1

H2SPEC := $(BINUTILS_DIR)/h2spec
VEGETA := $(BINUTILS_DIR)/vegeta
FORTIO := $(BINUTILS_DIR)/fortio

UNAME_S := $(shell uname -s | tr A-Z a-z)
UNAME_M := $(shell uname -m)

# Map architecture names
ifeq ($(UNAME_M),x86_64)
  ARCH_GO    := amd64
  ARCH_VEGETA := 64bit
else ifeq ($(UNAME_M),aarch64)
  ARCH_GO    := arm64
  ARCH_VEGETA := arm64
else
  ARCH_GO    := $(UNAME_M)
  ARCH_VEGETA := $(UNAME_M)
endif

# Capitalize OS for Vegeta archive naming
ifeq ($(UNAME_S),linux)
  OS_VEGETA := Linux
else ifeq ($(UNAME_S),darwin)
  OS_VEGETA := Darwin
else
  OS_VEGETA := $(UNAME_S)
endif

$(BINUTILS_DIR):
	mkdir -p $(BINUTILS_DIR)

$(H2SPEC): | $(BINUTILS_DIR)
	curl -sSfL https://github.com/summerwind/h2spec/releases/download/v$(H2SPEC_VERSION)/h2spec_$(UNAME_S)_$(ARCH_GO).tar.gz \
		| tar xz -C $(BINUTILS_DIR) h2spec

$(VEGETA): | $(BINUTILS_DIR)
	curl -sSfL https://github.com/tsenart/vegeta/releases/download/v$(VEGETA_VERSION)/vegeta_$(VEGETA_VERSION)_$(OS_VEGETA)_$(ARCH_VEGETA).tar.gz \
		| tar xz -C $(BINUTILS_DIR) vegeta

$(FORTIO): | $(BINUTILS_DIR)
	curl -sSfL https://github.com/fortio/fortio/releases/download/v$(FORTIO_VERSION)/fortio_$(UNAME_S)_$(ARCH_GO).tgz \
		| tar xz -C $(BINUTILS_DIR) usr/bin/fortio --strip-components=2

tools: $(H2SPEC) $(VEGETA) $(FORTIO)

clean-tools:
	rm -rf $(BINUTILS_DIR)

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1                  show test output (--nocapture)"
	@echo ""
	@echo "Build:"
	@echo "  build                cargo build --workspace"
	@echo "  release              cargo build --workspace --release"
	@echo "  check                cargo check --workspace"
	@echo "  clean                cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test                 run all tests"
	@echo "  test-unit            unit tests (core, filter, protocol, praxis)"
	@echo "  test-config          config validation + example tests"
	@echo "  test-integration     integration tests only"
	@echo "  test-conformance     conformance tests only"
	@echo "  test-performance     performance tests only"
	@echo "  test-microbenchmarks compile-check microbenchmarks"
	@echo "  test-fuzzing         fuzzing tests only"
	@echo "  test-security        security tests only"
	@echo "  test-resilience      resilience tests only"
	@echo "  test-config-validation  alias for test-config"
	@echo "  test-smoke           smoke tests only"
	@echo ""
	@echo "Bench:"
	@echo "  bench                Criterion micro-benchmarks"
	@echo ""
	@echo "Quality:"
	@echo "  lint                 clippy + rustfmt check"
	@echo "  fmt                  format with nightly rustfmt"
	@echo "  audit                cargo audit + cargo deny"
	@echo "  coverage             HTML coverage report"
	@echo "  coverage-check       fail if line coverage < 90%%"
	@echo ""
	@echo "Container:"
	@echo "  container            build container image"
	@echo "  container-run        run container in foreground (host network)"
	@echo ""
	@echo "Binutils (target/praxis-binutils/):"
	@echo "  tools                download all external CLI tools"
	@echo "  clean-tools          remove downloaded tools"
	@echo ""
	@echo "Dev tools:"
	@echo "  run-echo             start echo server (xtask)"
	@echo "  run-debug            start debug server (xtask)"
