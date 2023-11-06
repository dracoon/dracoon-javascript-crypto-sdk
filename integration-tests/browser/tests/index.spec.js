//ts-check
import { test, expect } from '@playwright/test';

test('does not throw', async ({ page }) => {
    await page.goto('http://127.0.0.1:9052');

    page.on('pageerror', (error) => {
        throw error;
    });

    const ok = (
        await page.waitForEvent('console', {
            predicate: (msg) => {
                if (msg.type() === 'error') {
                    throw new Error(msg.text());
                }
                return msg.text() === 'generateUserKeyPair - ok!';
            },
            timeout: 20_000
        })
    ).text();
    expect(ok).toBe('generateUserKeyPair - ok!');
});
