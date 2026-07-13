import { request } from "@playwright/test";

import {
  FORM_BASE_URL,
  SAMPLE_ASSET_REPORT,
  SAMPLE_TRACE_BATCH,
  authHeaders,
  ingestAuthHeaders,
} from "./fixtures";

async function waitForForm(timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${FORM_BASE_URL}/health`);
      if (response.ok()) {
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error(`Form API not ready at ${FORM_BASE_URL}/health`);
  } finally {
    await ctx.dispose();
  }
}

async function waitForSeededReport(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${FORM_BASE_URL}/reports/asset-reports`, {
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
    throw new Error("seeded report r-e2e-001 not visible via Form API");
  } finally {
    await ctx.dispose();
  }
}

export default async function globalSetup(): Promise<void> {
  await waitForForm();

  const ctx = await request.newContext();
  try {
    const reportResp = await ctx.post(`${FORM_BASE_URL}/ingest/asset-report`, {
      data: SAMPLE_ASSET_REPORT,
      headers: ingestAuthHeaders(),
    });
    if (!reportResp.ok()) {
      throw new Error(`seed asset report failed: ${reportResp.status()} ${await reportResp.text()}`);
    }

    const traceResp = await ctx.post(`${FORM_BASE_URL}/ingest/trace-batch`, {
      data: SAMPLE_TRACE_BATCH,
      headers: ingestAuthHeaders(),
    });
    if (!traceResp.ok()) {
      throw new Error(`seed trace batch failed: ${traceResp.status()} ${await traceResp.text()}`);
    }

    await waitForSeededReport();
  } finally {
    await ctx.dispose();
  }
}
