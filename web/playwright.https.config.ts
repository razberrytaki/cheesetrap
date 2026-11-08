import { defineConfig } from '@playwright/test';

const origin = process.env.CHEESETRAP_E2E_HTTPS_URL;
if (process.env.CHEESETRAP_E2E_RUN !== '1' || !origin || !/^https:\/\/127\.0\.0\.1:[1-9][0-9]*$/.test(origin)) {
  throw new Error('Use npm run test:e2e; only the runner-owned HTTPS fixture is supported');
}
export default defineConfig({
  testDir: './e2e-https', workers: 1, retries: 0, forbidOnly: true, timeout: 30000,
  reporter: [['line'], ['./e2e/no-skips.ts', { expectedTests: 1 }]], outputDir: '../.local/https-browser',
  use: {
    baseURL: origin, browserName: 'chromium', headless: true,
    // Only the runner-owned loopback proxy uses a self-signed test certificate.
    ignoreHTTPSErrors: true, trace: 'off', screenshot: 'off', video: 'off',
  },
});
