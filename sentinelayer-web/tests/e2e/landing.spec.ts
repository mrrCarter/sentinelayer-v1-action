import { test, expect } from "@playwright/test";

test("landing page renders hero", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: /AI-Powered Security Review/i })
  ).toBeVisible();
  await expect(page.getByText(/For Every Pull Request/i)).toBeVisible();
});
