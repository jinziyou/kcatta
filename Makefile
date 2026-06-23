# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check openapi-check contracts-check \
	test-agent test-analyzer test-admin test-admin-e2e \
	lint-agent lint-analyzer lint-admin \
	fmt-agent fmt-analyzer migrate-storage compose-up compose-down \
	build-agent-deploy build-agent-deploy-arm64

help:
	@grep -E '^[a-zA-Z0-9_-]+:' Makefile | sed 's/:.*//'

test-all: test-agent test-analyzer test-admin

lint-all: lint-agent lint-analyzer lint-admin

fmt-all: fmt-agent fmt-analyzer

schema-check: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/python scripts/export_schemas.py
	@git diff --exit-code analyzer/schemas-json/ || ( \
		echo "schemas-json/ is out of sync — run 'make schema-check' locally and commit"; \
		exit 1 \
	)

openapi-check: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/python scripts/export_openapi.py
	@git diff --exit-code analyzer/openapi.json || ( \
		echo "openapi.json is out of sync — run 'make openapi-check' locally and commit"; \
		exit 1 \
	)

contracts-check:
	cd admin && pnpm generate:contracts
	@git diff --exit-code admin/src/lib/schemas/ || ( \
		echo "admin schemas/ out of sync — run 'make contracts-check' locally and commit"; \
		exit 1 \
	)

migrate-storage: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/analyzer-migrate-storage

compose-up:
	docker compose up --build

compose-down:
	docker compose down

# Static (musl) deploy build — the binaries analyzer ships to remote targets.
# musl = statically linked → runs on any Linux regardless of glibc. Produces the
# three artifacts analyzer's deploy/trigger layer ships (ANALYZER_AGENT_TARGET_DIR):
#   agent/target/x86_64-unknown-linux-musl/release/{agent-host,agent-trace,agentd}
# The `agentd` umbrella is built with onaccess/network/ids so `agentd guard` ships the
# full sensor set (pcap is omitted on purpose — it needs a dynamic libpcap).
# Needs a musl C toolchain for the bundled SQLite (agent-host) and ring (TLS):
#   Debian/Ubuntu: sudo apt-get install -y musl-tools   (CI installs it)
DEPLOY_TARGET := x86_64-unknown-linux-musl
build-agent-deploy:
	rustup target add $(DEPLOY_TARGET)
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p agent-host -p agent-trace
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p agentd --features onaccess,network,ids
	@echo "deploy binaries → agent/target/$(DEPLOY_TARGET)/release/{agent-host,agent-trace,agentd}"

# Same, for aarch64 (ARM64) targets. Uses `cross` (docker-based toolchain) so the
# bundled-SQLite / ring C deps cross-compile cleanly. Install once: cargo install cross.
# analyzer picks x86_64 vs aarch64 binaries automatically per the target's `uname -m`.
DEPLOY_TARGET_ARM64 := aarch64-unknown-linux-musl
build-agent-deploy-arm64:
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p agent-host -p agent-trace
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p agentd --features onaccess,network,ids
	@echo "arm64 deploy binaries → agent/target/$(DEPLOY_TARGET_ARM64)/release/{agent-host,agent-trace,agentd}"

test-agent:
	cd agent && cargo test --locked --all-targets
	# Full guard engine: onaccess/network/ids compile (none need root/system deps).
	# The pcap feature additionally needs libpcap-dev; CI runs --all-features.
	cd agent && cargo test --locked -p agent-guard --features all
	# Independence + lean-build smoke: each capability binary builds standalone, minimal.
	cd agent && cargo build --locked -p agent-host
	cd agent && cargo build --locked -p agent-trace --no-default-features
	cd agent && cargo build --locked -p agent-guard --no-default-features --features fim

# Bootstrap the analyzer dev venv. Prefer `uv` (fast, and works on hosts whose
# `python3 -m venv` ships without pip/ensurepip); fall back to the stdlib
# venv + pip otherwise.
analyzer/.venv/bin/pytest: analyzer/pyproject.toml
	cd analyzer && if command -v uv >/dev/null 2>&1; then \
		uv venv .venv && uv pip install -p .venv -e ".[dev]"; \
	else \
		python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"; \
	fi

test-analyzer: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/pytest

test-admin:
	cd admin && pnpm install --frozen-lockfile && pnpm lint && pnpm build

test-admin-e2e:
	cd admin && pnpm install --frozen-lockfile && pnpm generate:contracts && pnpm build && pnpm exec playwright install chromium && pnpm test:e2e

lint-agent:
	cd agent && cargo fmt --all -- --check
	cd agent && cargo clippy --locked --all-targets -- -D warnings

lint-analyzer: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/ruff check src tests scripts

lint-admin:
	cd admin && pnpm install --frozen-lockfile && pnpm lint

fmt-agent:
	cd agent && cargo fmt --all

fmt-analyzer: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/ruff format src tests scripts
