// @ts-check
import { defineConfig, devices } from '@playwright/test';

/**
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
    testDir: './tests',
    fullyParallel: true,
    forbidOnly: true,
    retries: 0,
    workers: 3,
    reporter: 'list',

    /* Configure projects for major browsers */
    projects: [
        {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] }
        }
    ]
});
