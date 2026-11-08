import { test, expect } from '@playwright/test';

test('HTTPS proxy keeps login, reload and logout protected', async ({ page, context }) => {
  const origin = process.env.CHEESETRAP_E2E_HTTPS_URL!;
  const failures: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin !== origin) {
      failures.push('unexpected external request'); return route.abort();
    }
    return route.continue();
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '관리자 로그인' })).toBeVisible();
  await page.getByLabel('관리자 이름').fill('admin');
  await page.getByLabel('비밀번호', { exact: true }).fill('correct horse battery staple');
  await page.getByRole('button', { name: '로그인', exact: true }).click();
  const account = page.getByRole('button', { name: '계정 메뉴: admin', exact: true });
  await expect(account).toBeVisible();
  expect(new URL(page.url()).origin).toBe(origin);
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(200);
  const cookies = (await context.cookies()).filter(cookie => cookie.name.startsWith('cheesetrap_'));
  expect(cookies).toHaveLength(2);
  for (const cookie of cookies) {
    expect(cookie).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Strict', path: '/api/v1' });
  }
  await page.reload();
  await expect(account).toBeVisible();
  expect(new URL(page.url()).origin).toBe(origin);
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(200);
  await account.click();
  await page.getByRole('button', { name: '로그아웃', exact: true }).click();
  await expect(page.getByRole('heading', { name: '관리자 로그인' })).toBeVisible();
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(401);
  expect((await context.cookies()).some(cookie => cookie.name === 'cheesetrap_session')).toBe(false);
  expect(failures).toEqual([]);
});
