# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check openapi-check contracts-check component-boundaries \
	test-agent test-analyzer test-form test-admin test-admin-e2e \
	lint-agent lint-analyzer lint-form lint-admin \
	fmt-agent fmt-analyzer fmt-form migrate-storage migrate-control-state \
	compose-config compose-up compose-down \
	branch-protection-dry-run branch-protection-verify \
	build-agent-deploy build-agent-deploy-arm64 build-agent-deploy-windows

help:
	@grep -E '^[a-zA-Z0-9_-]+:' Makefile | sed 's/:.*//'

test-all: test-agent test-analyzer test-form test-admin

lint-all: lint-agent lint-analyzer lint-form lint-admin component-boundaries

fmt-all: fmt-agent fmt-analyzer fmt-form

schema-check: analyzer/.venv/bin/pytest form/.venv/bin/pytest
	cd analyzer && .venv/bin/python scripts/export_schemas.py
	cd form && .venv/bin/python scripts/export_schemas.py
	@git diff --exit-code analyzer/schemas-json/ form/schemas-json/ || ( \
		echo "public schemas are out of sync — run 'make schema-check' locally and commit"; \
		exit 1 \
	)

openapi-check: analyzer/.venv/bin/pytest form/.venv/bin/pytest
	cd analyzer && .venv/bin/python scripts/export_openapi.py
	cd form && .venv/bin/python scripts/export_openapi.py
	@git diff --exit-code analyzer/openapi.json form/openapi.json || ( \
		echo "OpenAPI artifacts are out of sync — run 'make openapi-check' locally and commit"; \
		exit 1 \
	)

contracts-check:
	cd admin && pnpm generate:contracts
	@git diff --exit-code admin/src/lib/schemas/ || ( \
		echo "admin schemas/ out of sync — run 'make contracts-check' locally and commit"; \
		exit 1 \
	)

component-boundaries:
	bash scripts/check-component-boundaries.sh

migrate-storage: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/analyzer-migrate-storage

# One-time, offline upgrade from the former Analyzer-owned target/job stores.
# Example: make migrate-control-state OLD_ANALYZER_DATA_DIR=analyzer/data \
#            FORM_DATA_DIR=form/data OLD_ANALYZER_STORAGE=auto FORM_STORAGE=jsonl
migrate-control-state: form/.venv/bin/pytest
	@test -n "$(OLD_ANALYZER_DATA_DIR)" || ( \
		echo "OLD_ANALYZER_DATA_DIR is required"; exit 2 \
	)
	cd form && .venv/bin/form-migrate-control-state \
		--analyzer-data-dir "$(abspath $(OLD_ANALYZER_DATA_DIR))" \
		--form-data-dir "$(if $(FORM_DATA_DIR),$(abspath $(FORM_DATA_DIR)),$(CURDIR)/form/data)" \
		--source-storage "$(if $(OLD_ANALYZER_STORAGE),$(OLD_ANALYZER_STORAGE),auto)" \
		--form-storage "$(if $(FORM_STORAGE),$(FORM_STORAGE),jsonl)"

compose-config:
	docker compose config >/dev/null

compose-up:
	docker compose up --build

compose-down:
	docker compose down

branch-protection-dry-run:
	./scripts/setup-branch-protection.sh --dry-run

branch-protection-verify:
	./scripts/verify-branch-protection.sh

# Static (musl) deploy build — the binaries Form ships to remote targets.
# musl = statically linked → runs on any Linux regardless of glibc. Produces the
# three artifacts Form's deploy layer ships (`FORM_AGENT_TARGET_DIR`):
#   agent/target/x86_64-unknown-linux-musl/release/{agent-collect-host,agent-collect-trace,agentd}
# The `agentd` umbrella is built with onaccess/network/ids so `agentd respond` ships the
# full sensor set (pcap is omitted on purpose — it needs a dynamic libpcap).
# Needs a musl C toolchain for the bundled SQLite (agent-collect-host) and ring (TLS):
#   Debian/Ubuntu: sudo apt-get install -y musl-tools   (CI installs it)
DEPLOY_TARGET := x86_64-unknown-linux-musl
build-agent-deploy:
	rustup target add $(DEPLOY_TARGET)
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p agent-collect-host
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p agent-collect-trace --features winnet
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET) -p agentd --features onaccess,network,ids
	@echo "Form deploy binaries → agent/target/$(DEPLOY_TARGET)/release/{agent-collect-host,agent-collect-trace,agentd}"

# Same, for aarch64 (ARM64) targets. Uses `cross` (docker-based toolchain) so the
# bundled-SQLite / ring C deps cross-compile cleanly. Install once: cargo install cross.
# Form picks x86_64 vs aarch64 binaries automatically per the target's `uname -m`.
DEPLOY_TARGET_ARM64 := aarch64-unknown-linux-musl
build-agent-deploy-arm64:
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p agent-collect-host
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p agent-collect-trace --features winnet
	cd agent && cross build --locked --release --target $(DEPLOY_TARGET_ARM64) -p agentd --features onaccess,network,ids
	@echo "arm64 deploy binaries → agent/target/$(DEPLOY_TARGET_ARM64)/release/{agent-collect-host,agent-collect-trace,agentd}"

# Windows host inventory binary shipped by Form over WinRM. GNU makes this
# cross-buildable on Linux; install `gcc-mingw-w64-x86-64` first.
DEPLOY_TARGET_WINDOWS := x86_64-pc-windows-gnu
build-agent-deploy-windows:
	rustup target add $(DEPLOY_TARGET_WINDOWS)
	cd agent && cargo build --locked --release --target $(DEPLOY_TARGET_WINDOWS) -p agent-collect-host
	@echo "WinRM deploy binary → agent/target/$(DEPLOY_TARGET_WINDOWS)/release/agent-collect-host.exe"

test-agent:
	cd agent && cargo test --locked --all-targets
	# Full guard engine: onaccess/network/ids compile (none need root/system deps).
	# The pcap feature additionally needs libpcap-dev; CI runs --all-features.
	cd agent && cargo test --locked -p agent-respond --features all
	# Independence + lean-build smoke: each capability binary builds standalone, minimal.
	cd agent && cargo build --locked -p agent-collect-host
	cd agent && cargo build --locked -p agent-collect-trace --no-default-features
	cd agent && cargo build --locked -p agent-respond --no-default-features --features fim

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

# Form imports the analyzer's neutral wire models/storage library while all
# runtime communication remains HTTP through the Form→Analyzer client.
form/.venv/bin/pytest: form/pyproject.toml analyzer/pyproject.toml
	cd form && if command -v uv >/dev/null 2>&1; then \
		uv sync --locked --extra dev; \
	else \
		python3 -m venv .venv && .venv/bin/pip install -q -e ../analyzer -e ".[dev]"; \
	fi

test-form: form/.venv/bin/pytest
	cd form && .venv/bin/pytest

test-admin:
	cd admin && pnpm install --frozen-lockfile && pnpm typecheck && pnpm lint && pnpm build

test-admin-e2e:
	cd admin && pnpm install --frozen-lockfile && pnpm generate:contracts && pnpm build && pnpm exec playwright install chromium && pnpm test:e2e

lint-agent:
	cd agent && cargo fmt --all -- --check
	cd agent && cargo clippy --locked --all-targets -- -D warnings

lint-analyzer: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/ruff check src tests scripts

lint-form: form/.venv/bin/pytest
	cd form && .venv/bin/ruff check src tests scripts

lint-admin:
	cd admin && pnpm install --frozen-lockfile && pnpm lint

fmt-agent:
	cd agent && cargo fmt --all

fmt-analyzer: analyzer/.venv/bin/pytest
	cd analyzer && .venv/bin/ruff format src tests scripts

fmt-form: form/.venv/bin/pytest
	cd form && .venv/bin/ruff format src tests scripts
