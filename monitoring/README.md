# Optional monitoring profile

The Compose `monitoring` profile adds pinned Prometheus plus a repository-owned
static dashboard without changing the default application stack:

```bash
make monitoring-check
docker compose --profile monitoring up -d --build
```

- Read-only dashboard: <http://localhost:10064>
- Prometheus alerts: <http://localhost:10065/alerts>
- Prometheus targets: <http://localhost:10065/targets>

Both ports bind to loopback by default. The dashboard is static HTML/JavaScript
with no login, write API, credentials, persistent state, or third-party browser
dependency. Put these UIs behind TLS/SSO/VPN before changing either bind address
to `0.0.0.0`.

Prometheus scrapes Form only through the private service network. Form's
`/metrics` route and Analyzer's `/metrics` route each use a generated,
metrics-only bearer token; Prometheus receives both isolated token volumes
read-only and cannot authorize control, ingest, report, or detection APIs. The
dashboard is attached only to the separate monitoring network and receives
neither credential. It reads the loopback-published Prometheus API from the
operator's browser and displays current values, six-hour trends, and active
alerts.

## Cache alerts

| Alert | Condition | Minimum duration |
| --- | --- | --- |
| `KcattaAnalyzerMetricsUnavailable` | Analyzer scrape fails | 2 minutes |
| `KcattaFormMetricsUnavailable` | Form scrape fails | 2 minutes |
| `KcattaReportProjectionCacheLowHitRatio` | hit ratio below 50%, at least 20 lookups/15m | 10 minutes |
| `KcattaReportProjectionCacheInvalidationBurst` | at least 10 invalidations/15m and over 25% of misses | 10 minutes |
| `KcattaReportProjectionCacheEvictionPressure` | at least 10 evictions/15m | 10 minutes |
| `KcattaReportProjectionCacheCapacityPressure` | over 90% of an entry/byte limit while evicting | 10 minutes |

The profile evaluates and displays alert rules but intentionally does not guess
an external notification destination. Production deployments should connect
Prometheus to an Alertmanager configured for the organization's approved email,
PagerDuty, webhook, or chat receiver.

Prometheus retains 15 days by default. Override only the local bind addresses or
retention when needed:

```bash
PROMETHEUS_BIND_ADDRESS=127.0.0.1 \
MONITORING_DASHBOARD_BIND_ADDRESS=127.0.0.1 \
PROMETHEUS_RETENTION_TIME=30d \
docker compose --profile monitoring up -d
```
