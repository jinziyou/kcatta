# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check contracts-check \
	test-probe test-form test-portal test-portal-e2e \
	lint-probe lint-form lint-portal \
	fmt-probe migrate-storage compose-up compose-down

help:
	@grep -E '^[a-zA-Z_-]+:' Makefile | sed 's/:.*//'

test-all: test-probe test-form test-portal

lint-all: lint-probe lint-form lint-portal

fmt-all: fmt-probe

schema-check: form/.venv/bin/pytest
	cd form && .venv/bin/python scripts/export_schemas.py
	@git diff --exit-code form/schemas-json/ || ( \
		echo "schemas-json/ is out of sync — run 'make schema-check' locally and commit"; \
		exit 1 \
	)

contracts-check:
	cd portal && pnpm generate:contracts
	@git diff --exit-code portal/src/lib/schemas/ || ( \
		echo "portal schemas/ out of sync — run 'make contracts-check' locally and commit"; \
		exit 1 \
	)

migrate-storage: form/.venv/bin/pytest
	cd form && .venv/bin/form-migrate-storage

compose-up:
	docker compose up --build

compose-down:
	docker compose down

test-probe:
	cd probe && cargo test --all-targets

# Bootstrap the form dev venv. Prefer `uv` (fast, and works on hosts whose
# `python3 -m venv` ships without pip/ensurepip — same convention as
# att7ck/install-dev.sh); fall back to the stdlib venv + pip otherwise.
form/.venv/bin/pytest: form/pyproject.toml
	cd form && if command -v uv >/dev/null 2>&1; then \
		uv venv .venv && uv pip install -p .venv -e ".[dev]"; \
	else \
		python3 -m venv .venv && .venv/bin/pip install -q -e ".[dev]"; \
	fi

test-form: form/.venv/bin/pytest
	cd form && .venv/bin/pytest

test-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint && pnpm build

test-portal-e2e:
	cd portal && pnpm install --frozen-lockfile && pnpm generate:contracts && pnpm build && pnpm exec playwright install chromium && pnpm test:e2e

lint-probe:
	cd probe && cargo fmt --all -- --check
	cd probe && cargo clippy --all-targets -- -D warnings

lint-form: form/.venv/bin/pytest
	cd form && .venv/bin/ruff check src tests

lint-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint

fmt-probe:
	cd probe && cargo fmt --all
