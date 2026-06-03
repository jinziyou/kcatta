import { expect, test } from "@playwright/test";

test.describe("portal smoke", () => {
  test("home lists seeded asset report", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Asset reports" })).toBeVisible();
    const reportLink = page.getByRole("link", { name: /db-e2e-01/i });
    await expect(reportLink).toBeVisible({ timeout: 30_000 });
    await expect(reportLink).toContainText("r-e2e-001");
  });

  test("asset report detail page", async ({ page }) => {
    await page.goto("/reports/r-e2e-001");
    await expect(page.getByText("db-e2e-01")).toBeVisible();
    await expect(page.getByText("openssl")).toBeVisible();
  });

  test("flows page shows IOC hit batch", async ({ page }) => {
    await page.goto("/flows");
    await expect(page.getByRole("heading", { name: "Network flows" })).toBeVisible();
    await expect(page.getByText("col-e2e-1")).toBeVisible();
    await page.getByRole("link", { name: "IOC hits only" }).click();
    await expect(page.getByText("ip 93.184.216.34")).toBeVisible();
  });

  test("alerts page shows correlated alert", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
    await expect(page.getByText(/matched threat indicator/i)).toBeVisible();
  });

  test("nav links reach all main views", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "Findings" }).click();
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();

    await page.getByRole("link", { name: "Flows" }).click();
    await expect(page.getByRole("heading", { name: "Network flows" })).toBeVisible();

    await page.getByRole("link", { name: "Alerts" }).click();
    await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  });
});
