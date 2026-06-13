FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home analyzer
# Create + own the data dir BEFORE switching user, so the non-root `analyzer` user can
# write /data/analyzer.db (the VOLUME mountpoint would otherwise be root-owned).
RUN mkdir -p /data && chown analyzer:analyzer /data
USER analyzer

ENV ANALYZER_DATA_DIR=/data
ENV ANALYZER_STORAGE=sqlite
VOLUME /data

EXPOSE 8000

CMD ["analyzer-api", "--host", "0.0.0.0", "--port", "8000"]
