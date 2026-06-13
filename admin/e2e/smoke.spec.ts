import { expect, test } from "@playwright/test";

test.describe("admin smoke", () => {
  test("reports page lists seeded asset report", async ({ page }) => {
    await page.goto("/reports");
    await expect(page.getByRole("heading", { name: "资产报告" })).toBeVisible();
    const reportRow = page.getByRole("row").filter({ hasText: "db-e2e-01" });
    await expect(reportRow).toBeVisible({ timeout: 30_000 });
    await expect(
      reportRow.getByRole("link", { name: "查看资产报告详情" }),
    ).toHaveAttribute("href", "/reports/r-e2e-001");
  });

  test("asset report detail page", async ({ page }) => {
    await page.goto("/reports/r-e2e-001");
    await expect(page.getByText("db-e2e-01").first()).toBeVisible();
    await expect(page.getByText("openssl")).toBeVisible();
  });

  test("flows page shows IOC hit batch", async ({ page }) => {
    await page.goto("/flows");
    await expect(page.getByRole("heading", { name: "网络流量" })).toBeVisible();
    await expect(page.getByText("col-e2e-1")).toBeVisible();
    await page.getByRole("link", { name: "仅 IOC 命中" }).click();
    await expect(page.getByText("93.184.216.34", { exact: true })).toBeVisible();
  });

  test("alerts page shows correlated alert", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.getByRole("heading", { name: "关联告警" })).toBeVisible();
    await expect(page.getByText(/matched threat indicator/i)).toBeVisible();
  });

  test("nav links reach all main views", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("link", { name: "漏洞发现" }).click();
    await expect(page.getByRole("heading", { name: "漏洞发现" })).toBeVisible();

    await page.getByRole("link", { name: "网络流量" }).click();
    await expect(page.getByRole("heading", { name: "网络流量" })).toBeVisible();

    await page.getByRole("link", { name: "关联告警" }).click();
    await expect(page.getByRole("heading", { name: "关联告警" })).toBeVisible();
  });
});
