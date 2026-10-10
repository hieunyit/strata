import { defineConfig, devices } from '@playwright/test';

// Runs against a lab started with `make lab-up` (deploy/lab): real Keycloak
// login, real control plane. `npm run test:lab`.
export default defineConfig({
  testDir: './tests-lab',
  workers: 1,
  retries: 0,
  reporter: 'list',
  timeout: 60_000,
  use: {
    baseURL: process.env.STRATA_LAB_UI ?? 'http://127.0.0.1:18088',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
