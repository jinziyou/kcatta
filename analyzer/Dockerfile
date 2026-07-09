# syntax=docker/dockerfile:1
#
# Multi-stage: build the agent's static-musl deploy binary, then bundle it into
# the analyzer runtime so the dockerized deployment can scan targets out of the
# box (the deploy layer ships this binary to a target over SSH and runs it).

# ---- Stage 1: build the agent deploy binary (static musl → runs on any Linux) ----
# rust:1-bookworm is glibc-based, but we cross-build the static `x86_64-unknown-
# linux-musl` target so the produced binary has NO runtime libc dependency and
# runs on any target distro/arch-matching host. `rustup update stable` bumps the
# bundled toolchain to satisfy the workspace's `rust-version = 1.96`.
FROM rust:1-bookworm AS agent-builder
RUN rustup update stable \
 && rustup default stable \
 && rustup target add x86_64-unknown-linux-musl \
 && apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Agent source comes from the `agent_src` additional build context (see
# docker-compose.yml). agent/.dockerignore keeps the host target/ dirs out.
COPY --from=agent_src . ./agent
RUN cd agent && cargo build --locked --release \
      --target x86_64-unknown-linux-musl -p agent-collect-host

# ---- Stage 2: analyzer runtime ----
# Base image (G4). Pin to a patch-level tag for reproducibility; for full
# supply-chain integrity this SHOULD be pinned to a digest, e.g.
#   FROM python:3.11.11-slim@sha256:<digest>
# The digest is intentionally omitted here because it cannot be resolved in this
# offline build environment. Dependabot's `docker` ecosystem (see
# .github/dependabot.yml) tracks updates to this base image.
FROM python:3.14.6-slim

WORKDIR /app

# openssh-client provides `ssh-keygen`, which the deploy layer uses to bootstrap
# a managed SSH key on a target (managed_key credential mode). Without it,
# `POST /targets` with a one-time password fails.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Install dependencies from the committed lockfile (G2). `uv sync --locked` fails
# if uv.lock is out of date vs pyproject.toml, so the image is reproducible and
# pinned (no silent resolution of newer/compromised transitive deps at build
# time) — parity with the Rust (--locked) and admin (--frozen-lockfile) builds.
RUN pip install --no-cache-dir uv==0.11.6

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --locked --no-dev

# Bundle the agent deploy binary where the deploy layer resolves it:
# ANALYZER_AGENT_TARGET_DIR/<musl-triple>/release/agent-collect-host.
ENV ANALYZER_AGENT_TARGET_DIR=/opt/kcatta/agent-bins
COPY --from=agent-builder --chmod=0755 \
     /build/agent/target/x86_64-unknown-linux-musl/release/agent-collect-host \
     /opt/kcatta/agent-bins/x86_64-unknown-linux-musl/release/agent-collect-host

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
