# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check contracts-check \
	test-agent test-fusion test-portal test-portal-e2e \
	lint-agent lint-fusion lint-portal \
	fmt-agent fmt-fusion migrate-storage compose-up compose-down \
	build-agent-deploy build-agent-deploy-arm64

help:
	@grep -E '^[a-zA-Z0-9_-]+:' Makefile | sed 's/:.*//'

test-all: test-agent test-fusion test-portal

lint-all: lint-agent lint-fusion lint-portal

fmt-all: fmt-agent fmt-fusion

schema-check: fusion/.venv/bin/pytest
	cd fusion && .venv/bin/python scripts/export_schemas.py
	@git diff --exit-code fusion/schemas-json/ || ( \
		echo "schemas-json/ is out of sync — run 'make schema-check' locally and commit"; \
		exit 1 \
	)

contracts-check:
	cd portal && pnpm generate:contracts
	@git diff --exit-code portal/src/lib/schemas/ || ( \
		echo "portal schemas/ out of sync — run 'make contracts-check' locally and commit"; \
		exit 1 \
	)

migrate-storage: fusion/.venv/bin/pytest
	cd fusion && .venv/bin/fusion-migrate-storage

compose-up:
	docker compose up --build

compose-down:
	docker compose down

# Static (musl) deploy build — the binaries fusion ships to remote targets.
# musl = statically linked → runs on any Linux regardless of glibc. Produces the
# three artifacts fusion's deploy/trigger layer ships (FUSION_AGENT_TARGET_DIR):
#   agent/target/x86_64-unknown-linux-musl/release/{posture-host,posture-flow,agent}
# The `agent` umbrella is built with onaccess/network/ids so `agent guard` ships the
# full sensor set (pcap is omitted on purpose — it needs a dynamic libpcap).
# Needs a musl C toolchain for the bundled SQLite (posture-host) and ring (TLS):
#   Debian/Ubuntu: sudo apt-get install -y musl-tools   (CI installs it)
DEPLOY_TARGET := x86_64-unknown-linux-musl
build-agent-deploy:
	rustup target add $(DEPLOY_TARGET)
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p posture-host -p posture-flow
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p posture-agent --features onaccess,network,ids
	@echo "deploy binaries → agent/target/$(DEPLOY_TARGET)/release/{posture-host,posture-flow,agent}"

# Same, for aarch64 (ARM64) targets. Uses `cross` (docker-based toolchain) so the
# bundled-SQLite / ring C deps cross-compile cleanly. Install once: cargo install cross.
# fusion picks x86_64 vs aarch64 binaries automatically per the target's `uname -m`.
DEPLOY_TARGET_ARM64 := aarch64-unknown-linux-musl
build-agent-deploy-arm64:
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p posture-host -p posture-flow
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p posture-agent --features onaccess,network,ids
	@echo "arm64 deploy binaries → agent/target/$(DEPLOY_TARGET_ARM64)/release/{posture-host,posture-flow,agent}"

test-agent:
	cd agent && cargo test --locked --all-targets
	# Full guard engine: onaccess/network/ids compile (none need root/system deps).
	# The pcap feature additionally needs libpcap-dev; CI runs --all-features.
	cd agent && cargo test --locked -p posture-guard --features all
	# Independence + lean-build smoke: each capability binary builds standalone, minimal.
	cd agent && cargo build --locked -p posture-host
	cd agent && cargo build --locked -p posture-flow --no-default-features
	cd agent && cargo build --locked -p posture-guard --no-default-features --features fim

# Bootstrap the fusion dev venv. Prefer `uv` (fast, and works on hosts whose
# `python3 -m venv` ships without pip/ensurepip); fall back to the stdlib
# venv + pip otherwise.
fusion/.venv/bin/pytest: fusion/pyproject.toml
	cd fusion && if command -v uv >/dev/null 2>&1; then \
		uv venv .venv && uv pip install -p .venv -e ".[dev]"; \
	else \
		python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"; \
	fi

test-fusion: fusion/.venv/bin/pytest
	cd fusion && .venv/bin/pytest

test-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint && pnpm build

test-portal-e2e:
	cd portal && pnpm install --frozen-lockfile && pnpm generate:contracts && pnpm build && pnpm exec playwright install chromium && pnpm test:e2e

lint-agent:
	cd agent && cargo fmt --all -- --check
	cd agent && cargo clippy --locked --all-targets -- -D warnings

lint-fusion: fusion/.venv/bin/pytest
	cd fusion && .venv/bin/ruff check src tests scripts

lint-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint

fmt-agent:
	cd agent && cargo fmt --all

fmt-fusion: fusion/.venv/bin/pytest
	cd fusion && .venv/bin/ruff format src tests scripts
