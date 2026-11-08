import { defineConfig } from '@playwright/test';
const origin = process.env.CHEESETRAP_E2E_URL;
if (process.env.CHEESETRAP_E2E_RUN !== '1' || !origin || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/.test(origin)) {
  throw new Error('Use npm run test:e2e; only the runner-owned loopback fixture is supported');
}
export default defineConfig({
  testDir: './e2e', workers: 1, retries: 0, forbidOnly: true, timeout: 30000,
  reporter: [['line'], ['./e2e/no-skips.ts'], ['json', { outputFile: '../.local/e2e/browser-results.json' }]], outputDir: '../.local/e2e/browser',
  use: { baseURL: origin, browserName: 'chromium', headless: true, trace: 'off', screenshot: 'off', video: 'off' },
});
