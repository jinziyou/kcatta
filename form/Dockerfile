# syntax=docker/dockerfile:1

# Build the static agent artifacts Form deploys to managed targets.
FROM rust:1.97-bookworm AS agent-builder
RUN rustup target add x86_64-unknown-linux-musl \
 && rustup target add x86_64-pc-windows-gnu \
 && apt-get update \
 && apt-get install -y --no-install-recommends musl-tools gcc-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY --from=agent_src . ./agent
RUN cd agent && cargo build --locked --release \
      --target x86_64-unknown-linux-musl -p agent-collect-host \
 && cargo build --locked --release \
      --target x86_64-pc-windows-gnu -p agent-collect-host \
 && cargo build --locked --release \
      --target x86_64-unknown-linux-musl -p agent-collect-trace --features winnet \
 && cargo build --locked --release \
      --target x86_64-unknown-linux-musl -p agentd --features onaccess,network,ids

FROM python:3.14.6-slim
WORKDIR /workspace/form

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client openssl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv==0.11.6

# kcatta-analyzer currently supplies shared wire models and generic storage.
COPY --from=analyzer_src pyproject.toml README.md /workspace/analyzer/
COPY --from=analyzer_src src /workspace/analyzer/src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --extra winrm

ENV FORM_AGENT_TARGET_DIR=/opt/kcatta/agent-bins
RUN mkdir -p \
      /opt/kcatta/agent-bins/x86_64-unknown-linux-musl/release \
      /opt/kcatta/agent-bins/x86_64-pc-windows-gnu/release
COPY --from=agent-builder --chmod=0755 \
     /build/agent/target/x86_64-unknown-linux-musl/release/agent-collect-host \
     /build/agent/target/x86_64-unknown-linux-musl/release/agent-collect-trace \
     /build/agent/target/x86_64-unknown-linux-musl/release/agentd \
     /opt/kcatta/agent-bins/x86_64-unknown-linux-musl/release/
COPY --from=agent-builder --chmod=0755 \
     /build/agent/target/x86_64-pc-windows-gnu/release/agent-collect-host.exe \
     /opt/kcatta/agent-bins/x86_64-pc-windows-gnu/release/

RUN useradd --create-home formsvc \
 && mkdir -p /data /credentials /agent-tls /agent-identities \
 && chown -R formsvc:formsvc /data /credentials /agent-tls /agent-identities
USER formsvc

ENV FORM_DATA_DIR=/data
ENV FORM_STORAGE=sqlite
ENV XDG_CONFIG_HOME=/credentials
VOLUME ["/data", "/credentials", "/agent-tls", "/agent-identities"]
EXPOSE 10067 10443

CMD [".venv/bin/form-api", "--host", "0.0.0.0", "--port", "10067"]
