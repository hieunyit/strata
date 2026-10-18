import { defineConfig, devices } from '@playwright/test';
const baseURL = process.env.STRATA_MACHINE_LAB_URL;
if (!baseURL || !/^http:\/\/127\.0\.0\.1:\d+$/.test(baseURL)) throw new Error('An isolated loopback machine lab is required');
export default defineConfig({
  testDir: './tests-lab', testMatch: 'machine-credentials.spec.ts', workers: 1, retries: 0, reporter: 'list', timeout: 75_000,
  use: { baseURL, trace: 'off', video: 'off', screenshot: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
