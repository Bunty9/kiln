import { test, expect } from '@playwright/test';

test('heading is visible', async ({ page }) => {
  await page.setContent('<h1>kiln</h1>');
  const heading = page.locator('h1');
  await expect(heading).toContainText('kiln');
});
