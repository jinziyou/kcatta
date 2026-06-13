import { defineConfig, devices } from "@playwright/test";

const ADMIN_URL = "http://127.0.0.1:3000";
const ANALYZER_URL = "http://127.0.0.1:8000";
const E2E_API_TOKEN = process.env.E2E_API_TOKEN ?? "e2e-test-token";

const sharedEnv = {
  E2E_API_TOKEN,
  NEXT_PUBLIC_ANALYZER_BASE_URL: ANALYZER_URL,
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
      command: process.env.CI ? "bash scripts/e2e-admin.sh" : "pnpm dev --port 3000",
      url: ADMIN_URL,
      env: {
        ...sharedEnv,
        ANALYZER_API_TOKEN: E2E_API_TOKEN,
      },
      reuseExistingServer: !process.env.CI,
      timeout: process.env.CI ? 120_000 : 300_000,
    },
  ],
});
