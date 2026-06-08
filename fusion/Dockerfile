FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home fusion
# Create + own the data dir BEFORE switching user, so the non-root `fusion` user can
# write /data/fusion.db (the VOLUME mountpoint would otherwise be root-owned).
RUN mkdir -p /data && chown fusion:fusion /data
USER fusion

ENV FUSION_DATA_DIR=/data
ENV FUSION_STORAGE=sqlite
VOLUME /data

EXPOSE 8000

CMD ["fusion-api", "--host", "0.0.0.0", "--port", "8000"]
