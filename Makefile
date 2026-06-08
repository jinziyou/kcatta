# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check contracts-check \
	test-agent test-fusion test-portal test-portal-e2e \
	lint-agent lint-fusion lint-portal \
	fmt-agent fmt-fusion migrate-storage compose-up compose-down

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

test-agent:
	cd agent && cargo test --locked --all-targets
	# Also exercise the ClamAV malware tests (no system deps). The pcap feature
	# additionally needs libpcap-dev; CI runs the full --all-features matrix.
	cd agent && cargo test --locked --all-targets --features malware

# Bootstrap the fusion dev venv. Prefer `uv` (fast, and works on hosts whose
# `python3 -m venv` ships without pip/ensurepip — same convention as
# att7ck/install-dev.sh); fall back to the stdlib venv + pip otherwise.
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
