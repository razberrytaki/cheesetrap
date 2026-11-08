import { test, expect } from '@playwright/test';

test('draft-only navigation and settings expose no sending actions', async ({ page, context }) => {
  const failures: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  const origin = process.env.CHEESETRAP_E2E_URL!;
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin !== origin) {
      failures.push('unexpected external request');
      return route.abort();
    }
    return route.continue();
  });
  await page.goto('/reports');
  await page.getByLabel('관리자 이름').fill('review-admin');
  await page.getByLabel('비밀번호', { exact: true }).fill(process.env.CHEESETRAP_E2E_PASSWORD!);
  await page.getByRole('button', { name: '로그인', exact: true }).click();
  await expect(page.getByRole('heading', { name: '신고 목록', exact: true })).toBeVisible();
  expect(new URL(page.url()).origin).toBe(origin);
  await expect(page.getByRole('button', { name: '계정 메뉴: review-admin', exact: true })).toBeVisible();
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(200);
  await expect(page.getByRole('navigation', { name: '주 메뉴' }).getByRole('link', { name: '발송', exact: true })).toHaveCount(0);
  expect((await page.request.get('/api/v1/deliveries')).status()).toBe(404);
  const csrf = await (await page.request.get('/api/v1/auth/csrf')).json();
  const headers = { Origin: origin, 'X-CSRF-Token': csrf.csrf_token, 'Idempotency-Key': crypto.randomUUID() };
  for (const action of ['approve', 'cancel', 'retry', 'close-unconfirmed']) {
    expect((await page.request.post(`/api/v1/reports/${process.env.CHEESETRAP_E2E_REPORT!}/${action}`, { headers, data: {} })).status()).toBe(404);
  }
  expect((await page.request.post('/api/v1/settings/smtp-test', { headers, data: {} })).status()).toBe(404);
  await page.goto(`/reports/${process.env.CHEESETRAP_E2E_REPORT!}`);
  await expect(page.getByRole('heading', { name: '신고 검토', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /승인|발송|재전송/ })).toHaveCount(0);
  await page.getByRole('link', { name: '설정', exact: true }).click();
  await expect(page.getByLabel('Reply-To', { exact: true })).toBeVisible();
  await expect(page.getByText('자동 승인 활성화', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('group', { name: '발송 한도', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /SMTP/ })).toHaveCount(0);
  const settings = await (await page.request.get('/api/v1/settings')).json();
  expect(settings).not.toHaveProperty('automatic_mode');
  expect(settings).not.toHaveProperty('delivery_limits');
  expect(settings).not.toHaveProperty('smtp_test_recipient');
  expect(settings).not.toHaveProperty('latest_smtp_test');
  for (const removed of [{ automatic_mode: true }, { delivery_limits: { daily: 100, recipient_daily: 20 } }]) {
    expect((await page.request.patch('/api/v1/settings', { headers, data: { expected_version: settings.version, ...removed } })).status()).toBe(422);
  }
  await page.getByLabel('이벤트·판정 보관 (일)', { exact: true }).fill('45');
  await page.getByLabel('Reply-To', { exact: true }).fill('review@example.test');
  await page.getByRole('button', { name: '설정 저장', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: '설정을 저장했습니다.' })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('이벤트·판정 보관 (일)', { exact: true })).toHaveValue('45');
  await expect(page.getByLabel('Reply-To', { exact: true })).toHaveValue('review@example.test');
  await page.screenshot({ path: '../.local/e2e/browser/settings-saved.png', fullPage: true });
  await page.getByRole('link', { name: '신고', exact: true }).click();
  await expect(page.getByRole('heading', { name: '신고 목록', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: '신고 상태', exact: true }).selectOption('archived');
  await page.getByRole('button', { name: '필터 적용', exact: true }).click();
  await expect(page).toHaveURL(/state=archived/);
  const archivedID = process.env.CHEESETRAP_E2E_ARCHIVED_REPORT!;
  await page.locator(`a[href="/reports/${archivedID}"]`).click();
  await expect(page.getByRole('status').filter({ hasText: '이 기록은 읽기 전용입니다.' })).toBeVisible();
  await expect(page.getByRole('combobox', { name: /^연락처 후보/ })).toBeDisabled();
  await expect(page.getByRole('button', { name: '수신자로 저장', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: '초안 제외', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: /승인|발송|재전송/ })).toHaveCount(0);
  const archived = await (await page.request.get(`/api/v1/reports/${archivedID}`)).json();
  expect(archived.state).toBe('archived');
  const overview = await (await page.request.get('/api/v1/overview')).json();
  for (const state of ['held', 'needs_review', 'archived']) {
    const listed = await (await page.request.get(`/api/v1/reports?limit=200&state=${state}`)).json();
    expect(overview.operations.report_states[state] ?? '0').toBe(String(listed.items.length));
  }
  for (const action of ['reject', 'refresh-contact', 'select-contact']) {
    expect((await page.request.post(`/api/v1/reports/${archivedID}/${action}`, { headers, data: {
      expected_version: archived.version, current_revision_id: archived.current_revision_id,
      ...(action === 'select-contact' ? { recipient: 'second@example.test' } : {}),
    } })).status()).toBe(409);
  }
  await page.reload();
  await expect(page.getByRole('status').filter({ hasText: '이 기록은 읽기 전용입니다.' })).toBeVisible();
  await expect(page.getByRole('button', { name: '초안 제외', exact: true })).toBeDisabled();
  await page.screenshot({ path: '../.local/e2e/browser/archived-draft.png', fullPage: true });
  await context.clearCookies();
  await page.getByRole('button', { name: '신고 상태 새로고침', exact: true }).click();
  await expect(page.getByRole('heading', { name: '관리자 로그인' })).toBeVisible();
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(401);
  expect(failures).toEqual([]);
});
