import { defineConfig, devices } from "@playwright/test";

const PORTAL_URL = "http://127.0.0.1:3000";
const FORM_URL = "http://127.0.0.1:8000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: PORTAL_URL,
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
      command: "bash scripts/e2e-form.sh",
      url: `${FORM_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command: process.env.CI ? "bash scripts/e2e-portal.sh" : "pnpm dev --port 3000",
      url: PORTAL_URL,
      env: {
        NEXT_PUBLIC_FORM_BASE_URL: FORM_URL,
      },
      reuseExistingServer: !process.env.CI,
      timeout: process.env.CI ? 60_000 : 300_000,
    },
  ],
});
