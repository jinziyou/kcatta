# Base image (G4). Pin to a patch-level tag for reproducibility; for full
# supply-chain integrity this SHOULD be pinned to a digest, e.g.
#   FROM python:3.11.11-slim@sha256:<digest>
# The digest is intentionally omitted here because it cannot be resolved in this
# offline build environment. Dependabot's `docker` ecosystem (see
# .github/dependabot.yml) tracks updates to this base image.
FROM python:3.11.11-slim

WORKDIR /app

# Install dependencies from the committed lockfile (G2). `uv sync --locked` fails
# if uv.lock is out of date vs pyproject.toml, so the image is reproducible and
# pinned (no silent resolution of newer/compromised transitive deps at build
# time) — parity with the Rust (--locked) and admin (--frozen-lockfile) builds.
RUN pip install --no-cache-dir uv==0.11.6

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --locked --no-dev

RUN useradd --create-home analyzer
# Create + own the data dir BEFORE switching user, so the non-root `analyzer` user can
# write /data/analyzer.db (the VOLUME mountpoint would otherwise be root-owned).
RUN mkdir -p /data && chown analyzer:analyzer /data
USER analyzer

ENV ANALYZER_DATA_DIR=/data
ENV ANALYZER_STORAGE=sqlite
VOLUME /data

EXPOSE 10068

CMD [".venv/bin/analyzer-api", "--host", "0.0.0.0", "--port", "10068"]
