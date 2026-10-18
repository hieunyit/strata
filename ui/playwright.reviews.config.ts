import { defineConfig, devices } from '@playwright/test';
const baseURL = process.env.STRATA_REVIEW_LAB_URL;
if (!baseURL || !/^http:\/\/127\.0\.0\.1:\d+$/.test(baseURL)) throw new Error('An isolated loopback review lab URL is required');
export default defineConfig({
  testDir: './tests-lab', testMatch: 'review-queue.spec.ts', workers: 1, retries: 0, reporter: 'list', timeout: 90_000,
  use: { baseURL, trace: 'off', video: 'off', screenshot: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
