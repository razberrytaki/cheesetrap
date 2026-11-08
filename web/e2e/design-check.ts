import { expect, type Page } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';

// Called only inside the runner-owned fixture; never connects to a separate server.
export async function checkDesign(page: Page, name: string) {
  const directory = '../.local/design-review';
  await mkdir(directory, { recursive: true });
  for (const width of [320, 390, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect(page.locator('h1')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `${directory}/${name}-${width}.png`, fullPage: true });
  }
  const html = await page.evaluate(() => {
    const clone = document.documentElement.cloneNode(true) as HTMLElement;
    clone.querySelectorAll('script, link').forEach(node => node.remove());
    clone.querySelectorAll('input[type="password"]').forEach(node => node.setAttribute('value', ''));
    const style = document.createElement('style');
    style.textContent = Array.from(document.styleSheets).flatMap(sheet => Array.from(sheet.cssRules).map(rule => rule.cssText)).join('\n');
    clone.querySelector('head')!.append(style);
    return '<!doctype html>' + clone.outerHTML;
  });
  await writeFile(`${directory}/${name}.html`, html);
}
