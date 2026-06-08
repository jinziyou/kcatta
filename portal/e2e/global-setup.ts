import { request } from "@playwright/test";

import { FUSION_BASE_URL, SAMPLE_ASSET_REPORT, SAMPLE_FLOW_BATCH, authHeaders } from "./fixtures";

async function waitForForm(timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${FUSION_BASE_URL}/health`);
      if (response.ok()) {
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error(`fusion API not ready at ${FUSION_BASE_URL}/health`);
  } finally {
    await ctx.dispose();
  }
}

async function waitForSeededReport(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const ctx = await request.newContext();
  try {
    while (Date.now() < deadline) {
      const response = await ctx.get(`${FUSION_BASE_URL}/reports/asset-reports`, {
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
    throw new Error("seeded report r-e2e-001 not visible via fusion API");
  } finally {
    await ctx.dispose();
  }
}

export default async function globalSetup(): Promise<void> {
  await waitForForm();

  const ctx = await request.newContext();
  try {
    const reportResp = await ctx.post(`${FUSION_BASE_URL}/ingest/asset-report`, {
      data: SAMPLE_ASSET_REPORT,
      headers: authHeaders(),
    });
    if (!reportResp.ok()) {
      throw new Error(`seed asset report failed: ${reportResp.status()} ${await reportResp.text()}`);
    }

    const flowResp = await ctx.post(`${FUSION_BASE_URL}/ingest/flow-batch`, {
      data: SAMPLE_FLOW_BATCH,
      headers: authHeaders(),
    });
    if (!flowResp.ok()) {
      throw new Error(`seed flow batch failed: ${flowResp.status()} ${await flowResp.text()}`);
    }

    await waitForSeededReport();
  } finally {
    await ctx.dispose();
  }
}
