/** Sample payloads shared by E2E setup (mirrors analyzer/tests/test_api.py). */

export const ANALYZER_BASE_URL = process.env.ANALYZER_BASE_URL ?? "http://127.0.0.1:8000";

/** Shared bearer token for analyzer auth during E2E (analyzer + admin + seed requests). */
export const E2E_API_TOKEN = process.env.E2E_API_TOKEN ?? "e2e-test-token";

export function authHeaders(): Record<string, string> {
  return { Authorization: `Bearer ${E2E_API_TOKEN}` };
}

export const SAMPLE_ASSET_REPORT = {
  report_id: "r-e2e-001",
  collected_at: "2026-05-28T10:00:00+00:00",
  scanner_version: "0.1.0",
  host: {
    host_id: "h-e2e-001",
    hostname: "db-e2e-01",
    os: "Ubuntu 22.04",
    kernel: null,
    arch: "x86_64",
    ip_addrs: ["10.0.0.1"],
    mac_addrs: [],
    boot_time: null,
  },
  assets: [
    {
      kind: "package",
      asset_id: "pkg-e2e-1",
      name: "openssl",
      version: "3.0.2",
      source: "apt",
      install_path: null,
    },
  ],
  vulnerabilities: [],
} as const;

export const SAMPLE_FLOW_BATCH = {
  batch_id: "b-e2e-1",
  collected_at: "2026-05-28T10:00:00+00:00",
  collector_id: "col-e2e-1",
  collector_version: "0.1.0",
  flows: [
    {
      flow_id: "f-e2e-1",
      host_id: "h-e2e-001",
      start_ts: "2026-05-28T10:00:00+00:00",
      end_ts: "2026-05-28T10:00:00+00:00",
      proto: "tcp",
      src_ip: "10.0.0.1",
      src_port: 12345,
      dst_ip: "93.184.216.34",
      dst_port: 443,
      bytes_sent: 512,
      bytes_recv: 2048,
      packets_sent: 6,
      packets_recv: 8,
      app_proto: "TLS",
      dns_query: null,
      tls_sni: "example.com",
      ja3: null,
      threat_intel: [
        {
          indicator: "93.184.216.34",
          indicator_type: "ip",
          category: "c2",
          severity: "high",
          source: "e2e-demo",
          description: "E2E C2 indicator",
        },
      ],
    },
  ],
} as const;
