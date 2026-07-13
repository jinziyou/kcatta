import { defineConfig, devices } from "@playwright/test";

const ADMIN_URL = "http://127.0.0.1:10063";
const ANALYZER_URL = "http://127.0.0.1:10068";
const FORM_URL = "http://127.0.0.1:10067";
const E2E_API_TOKEN = process.env.E2E_API_TOKEN ?? "e2e-control-token";
const E2E_INGEST_TOKEN = process.env.E2E_INGEST_TOKEN ?? "e2e-ingest-token";
const E2E_ANALYZER_TOKEN = process.env.E2E_ANALYZER_TOKEN ?? "e2e-analyzer-token";

const sharedEnv = {
  E2E_API_TOKEN,
  E2E_INGEST_TOKEN,
  E2E_ANALYZER_TOKEN,
};

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: ADMIN_URL,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: "bash scripts/e2e-analyzer.sh",
      url: `${ANALYZER_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: sharedEnv,
    },
    {
      command: "bash scripts/e2e-form.sh",
      url: `${FORM_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: {
        ...sharedEnv,
        FORM_ANALYZER_BASE_URL: ANALYZER_URL,
      },
    },
    {
      command: process.env.CI ? "bash scripts/e2e-admin.sh" : "pnpm dev --port 10063",
      url: ADMIN_URL,
      env: {
        ...sharedEnv,
        FORM_BASE_URL: FORM_URL,
        FORM_API_TOKEN: E2E_API_TOKEN,
      },
      reuseExistingServer: !process.env.CI,
      timeout: process.env.CI ? 120_000 : 300_000,
    },
  ],
});
