import { expect, test } from "@playwright/test";

import { ANALYZER_BASE_URL, SAMPLE_ASSET_REPORT, authHeaders } from "./fixtures";

test.describe("analyzer API auth", () => {
  test("health stays public", async ({ request }) => {
    const response = await request.get(`${ANALYZER_BASE_URL}/health`);
    expect(response.ok()).toBeTruthy();
    expect(await response.json()).toEqual({ status: "ok" });
  });

  test("ingest rejects missing token", async ({ request }) => {
    const response = await request.post(`${ANALYZER_BASE_URL}/ingest/asset-report`, {
      data: SAMPLE_ASSET_REPORT,
    });
    expect(response.status()).toBe(401);
  });

  test("reports reject invalid token", async ({ request }) => {
    const response = await request.get(`${ANALYZER_BASE_URL}/reports/asset-reports`, {
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(response.status()).toBe(401);
  });

  test("ingest accepts valid token", async ({ request }) => {
    const payload = {
      ...SAMPLE_ASSET_REPORT,
      report_id: "r-e2e-auth-check",
      host: { ...SAMPLE_ASSET_REPORT.host, hostname: "auth-check-host" },
    };
    const response = await request.post(`${ANALYZER_BASE_URL}/ingest/asset-report`, {
      data: payload,
      headers: authHeaders(),
    });
    expect(response.status()).toBe(202);
  });
});
