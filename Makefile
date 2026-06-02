# Monorepo task shortcuts — see README.md for per-component docs.
#
#   make test-all      run all component test suites
#   make lint-all      run all linters (no tests)
#   make schema-check  regenerate JSON Schema and fail on drift

.PHONY: help test-all lint-all fmt-all schema-check contracts-check \
	test-scanner test-collector test-form test-portal test-portal-e2e \
	lint-scanner lint-collector lint-form lint-portal \
	fmt-scanner fmt-collector compose-up compose-down

help:
	@grep -E '^[a-zA-Z_-]+:' Makefile | sed 's/:.*//'

test-all: test-scanner test-collector test-form test-portal

lint-all: lint-scanner lint-collector lint-form lint-portal

fmt-all: fmt-scanner fmt-collector

schema-check:
	cd form && PYTHONPATH=src python3 scripts/export_schemas.py
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

migrate-storage:
	cd form && PYTHONPATH=src python3 -c "import sys; sys.argv=['form-migrate-storage']; from form.cli import migrate_storage_main; migrate_storage_main()"

compose-up:
	docker compose up --build

compose-down:
	docker compose down

test-scanner:
	cd scanner && cargo test --all-targets

test-collector:
	cd collector && cargo test --all-targets

form/.venv/bin/pytest: form/pyproject.toml
	cd form && python3 -m venv .venv
	cd form && .venv/bin/pip install -q -e ".[dev]"

test-form: form/.venv/bin/pytest
	cd form && .venv/bin/pytest

test-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint && pnpm build

test-portal-e2e:
	cd portal && pnpm install --frozen-lockfile && pnpm generate:contracts && pnpm build && pnpm exec playwright install chromium && pnpm test:e2e

lint-scanner:
	cd scanner && cargo fmt --all -- --check
	cd scanner && cargo clippy --all-targets -- -D warnings

lint-collector:
	cd collector && cargo fmt --all -- --check
	cd collector && cargo clippy --all-targets -- -D warnings

lint-form: form/.venv/bin/pytest
	cd form && .venv/bin/ruff check src tests

lint-portal:
	cd portal && pnpm install --frozen-lockfile && pnpm lint

fmt-scanner:
	cd scanner && cargo fmt --all

fmt-collector:
	cd collector && cargo fmt --all
