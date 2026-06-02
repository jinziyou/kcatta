import { request } from "@playwright/test";

import { FORM_BASE_URL, SAMPLE_ASSET_REPORT, SAMPLE_FLOW_BATCH } from "./fixtures";

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
    throw new Error(`form API not ready at ${FORM_BASE_URL}/health`);
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
    });
    if (!reportResp.ok()) {
      throw new Error(`seed asset report failed: ${reportResp.status()} ${await reportResp.text()}`);
    }

    const flowResp = await ctx.post(`${FORM_BASE_URL}/ingest/flow-batch`, {
      data: SAMPLE_FLOW_BATCH,
    });
    if (!flowResp.ok()) {
      throw new Error(`seed flow batch failed: ${flowResp.status()} ${await flowResp.text()}`);
    }
  } finally {
    await ctx.dispose();
  }
}
