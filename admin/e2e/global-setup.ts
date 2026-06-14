import { request } from "@playwright/test";

import { ANALYZER_BASE_URL, SAMPLE_ASSET_REPORT, SAMPLE_TRACE_BATCH, authHeaders } from "./fixtures";

async function waitForAnalyzer(timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${ANALYZER_BASE_URL}/health`);
      if (response.ok()) {
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error(`analyzer API not ready at ${ANALYZER_BASE_URL}/health`);
  } finally {
    await ctx.dispose();
  }
}

async function waitForSeededReport(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${ANALYZER_BASE_URL}/reports/asset-reports`, {
        headers: authHeaders(),
      });
      if (response.ok()) {
        const reports = (await response.json()) as Array<{ report_id?: string }>;
        if (reports.some((report) => report.report_id === "r-e2e-001")) {
          return;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error("seeded report r-e2e-001 not visible via analyzer API");
  } finally {
    await ctx.dispose();
  }
}

export default async function globalSetup(): Promise<void> {
  await waitForAnalyzer();

  const ctx = await request.newContext();
  try {
    const reportResp = await ctx.post(`${ANALYZER_BASE_URL}/ingest/asset-report`, {
      data: SAMPLE_ASSET_REPORT,
      headers: authHeaders(),
    });
    if (!reportResp.ok()) {
      throw new Error(`seed asset report failed: ${reportResp.status()} ${await reportResp.text()}`);
    }

    const traceResp = await ctx.post(`${ANALYZER_BASE_URL}/ingest/trace-batch`, {
      data: SAMPLE_TRACE_BATCH,
      headers: authHeaders(),
    });
    if (!traceResp.ok()) {
      throw new Error(`seed trace batch failed: ${traceResp.status()} ${await traceResp.text()}`);
    }

    await waitForSeededReport();
  } finally {
    await ctx.dispose();
  }
}
