import { test, expect } from '@playwright/test';
import { checkDesign } from './design-check';

test('captured engine evidence reaches authenticated review and persisted rejection', async ({ page }) => {
  test.setTimeout(60000);
  const origin = process.env.CHEESETRAP_E2E_URL!;
  const id = process.env.CHEESETRAP_E2E_REPORT!;
  const failures: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  // Any unexpected browser network destination fails the test and is blocked.
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin !== origin) {
      failures.push('unexpected external request'); return route.abort();
    }
    return route.continue();
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '관리자 로그인' })).toBeVisible();
  await checkDesign(page, 'login');
  await page.getByLabel('관리자 이름').fill('review-admin');
  await page.getByLabel('비밀번호', { exact: true }).fill(process.env.CHEESETRAP_E2E_PASSWORD!);
  await page.getByRole('button', { name: '로그인', exact: true }).click();
  await expect(page.getByRole('button', { name: '계정 메뉴: review-admin', exact: true })).toBeVisible();
  expect(new URL(page.url()).origin).toBe(origin);
  expect((await page.request.get('/api/v1/auth/me')).status()).toBe(200);
  for (const [route, heading] of [['/overview', '개요'], ['/reports', '신고 목록'], ['/settings', '설정']]) {
    await page.goto(route);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await expect(page.locator('main [role="status"]').filter({ hasText: /불러오는 중/ })).toHaveCount(0);
    await checkDesign(page, route.slice(1));
    if (route === '/overview') {
      await expect(page.getByRole('button', { name: /새로고침/ })).toHaveCount(1);
      await expect(page.getByText('검토 워크스페이스', { exact: true })).toHaveCount(0);
      // The real fixture has queued reports but no needs_review entry in its GROUP BY result.
      await expect(page.getByText('검토 대기 신고가 없습니다.', { exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: '검토 대기 신고', exact: true }).getByRole('definition')).toHaveText('0');
      const disclosure = page.getByText('수집 상태 상세', { exact: true });
      await disclosure.focus();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('table', { name: '센서별 수집 상태 비교' })).toBeVisible();
      await checkDesign(page, 'overview-collection-details');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('table', { name: '센서별 수집 상태 비교' })).not.toBeVisible();
      // Synthetic overview variants stay inside the runner-owned API fixture.
      const overviewRoute = '**/api/v1/overview';
      let reviewCount = '12';
      await page.route(overviewRoute, async route => {
        const response = await route.fetch();
        const data = await response.json();
        await route.fulfill({ response, json: { ...data, operations: {
          ...data.operations, report_states: { ...data.operations?.report_states, needs_review: reviewCount },
        } } });
      });
      await page.getByRole('button', { name: '개요 새로고침' }).click();
      await expect(page.getByText('검토할 신고가 있습니다.', { exact: true })).toBeVisible();
      await checkDesign(page, 'overview-review');
      reviewCount = '9007199254740993';
      await page.getByRole('button', { name: '개요 새로고침' }).click();
      await expect(page.getByText(reviewCount, { exact: true }).first()).toBeVisible();
      await checkDesign(page, 'overview-large-count');
      await page.unroute(overviewRoute);
      const review = page.getByRole('region', { name: '검토 대기 신고', exact: true });
      await expect(review).toBeVisible();
      await review.getByRole('link').focus();
      await page.keyboard.press('Enter');
      await expect(page).toHaveURL(/\/reports\?state=needs_review$/);
      await expect(page.getByRole('heading', { name: '신고 목록', exact: true })).toBeVisible();
    }
  }
  const settingsRoute = '**/api/v1/settings';
  await page.route(settingsRoute, async route => {
    const response = await route.fetch();
    const snapshot = await response.json();
    await route.fulfill({ response, json: { ...snapshot, pending_schedule: null } });
  });
  await page.reload();
  await expect(page.getByText('예약된 변경이 없습니다.', { exact: true })).toBeVisible();
  await checkDesign(page, 'settings-empty-schedule');
  const currentSchedule = await page.getByRole('region', { name: '현재 초안 집계 일정', exact: true }).boundingBox();
  const pendingSchedule = await page.getByRole('region', { name: '예약된 초안 집계 일정', exact: true }).boundingBox();
  expect(currentSchedule).not.toBeNull();
  expect(pendingSchedule).not.toBeNull();
  expect(pendingSchedule!.height).toBeCloseTo(currentSchedule!.height, 0);
  expect(pendingSchedule!.y).toBeCloseTo(currentSchedule!.y, 0);
  await expect(page.getByText('발송 한도', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /SMTP/ })).toHaveCount(0);
  await page.getByRole('heading', { name: '설정', exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: '../.local/design-review/settings-layout-desktop.png' });
  await page.unroute(settingsRoute);
  await page.getByRole('link', { name: '이벤트', exact: true }).click();
  await expect(page.getByText('cowrie.login.failed').first()).toBeVisible();
  await page.getByRole('combobox', { name: '이벤트 유형', exact: true }).selectOption({ label: 'SSH · 로그인 실패' });
  await page.getByRole('button', { name: '필터 적용', exact: true }).click();
  await expect(page).toHaveURL(/event_type=cowrie.login.failed/);
  const filteredTypes = page.getByRole('table', { name: '수집 이벤트 목록' }).locator('.event-type');
  await expect(filteredTypes.first()).toHaveText('cowrie.login.failed');
  expect((await filteredTypes.allTextContents()).every(value => value === 'cowrie.login.failed')).toBe(true);
  const refresh = page.getByRole('button', { name: '이벤트 새로고침', exact: true });
  await expect(refresh).toBeEnabled();
  await expect(page.getByRole('button', { name: /새로고침/ })).toHaveCount(1);
  const filteredURL = page.url();
  const statusRefresh = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/overview' && response.ok());
  const eventRefresh = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/events' && new URL(response.url()).searchParams.get('event_type') === 'cowrie.login.failed' && response.ok());
  await refresh.click();
  await Promise.all([statusRefresh, eventRefresh]);
  await expect(refresh).toBeEnabled();
  await expect(page).toHaveURL(filteredURL);
  await expect(page.getByRole('combobox', { name: '이벤트 유형', exact: true })).toHaveValue('cowrie.login.failed');
  await expect(filteredTypes.first()).toHaveText('cowrie.login.failed');
  await expect(page.locator('.topbar')).toHaveCount(0);
  await checkDesign(page, 'events');
  await page.screenshot({ path: '../.local/design-review/events-toolbar-desktop.png' });
  const account = page.getByRole('button', { name: '계정 메뉴: review-admin', exact: true });
  await account.focus(); await page.keyboard.press('Enter');
  await expect(account).toHaveAttribute('aria-expanded', 'true');
  await checkDesign(page, 'events-account-menu');
  await page.setViewportSize({ width: 320, height: 900 });
  const accountPanel = page.getByRole('group', { name: '계정', exact: true });
  const panelBounds = await accountPanel.boundingBox();
  expect(panelBounds!.x).toBeGreaterThanOrEqual(0);
  expect(panelBounds!.x + panelBounds!.width).toBeLessThanOrEqual(320);
  const brandBounds = await page.locator('.wordmark').boundingBox();
  const accountBounds = await account.boundingBox();
  expect(brandBounds!.x + brandBounds!.width).toBeLessThanOrEqual(accountBounds!.x);
  await page.screenshot({ path: '../.local/design-review/events-account-mobile.png' });
  await page.getByRole('button', { name: '로그아웃', exact: true }).focus();
  await page.keyboard.press('Escape');
  await expect(account).toHaveAttribute('aria-expanded', 'false');
  await expect(account).toBeFocused();
  await account.click();
  await page.getByRole('heading', { name: '수집 상태', exact: true }).click();
  await expect(account).toHaveAttribute('aria-expanded', 'false');
  await page.getByRole('button', { name: '초기화', exact: true }).click();
  await expect(page.getByRole('combobox', { name: '이벤트 유형', exact: true })).toHaveValue('');
  await page.getByText('수집 상태 상세', {exact:true}).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('table', {name:'센서별 수집 상태 비교'})).toBeVisible();
  await checkDesign(page, 'collection-details');
  await page.getByRole('region', {name:'센서 비교표 가로 스크롤'}).focus();
  await expect(page.getByRole('region', {name:'센서 비교표 가로 스크롤'})).toBeFocused();
  await page.getByText('수집 상태 상세', {exact:true}).click();

  await page.getByRole('link', { name: '본문으로 건너뛰기' }).focus();
  await expect(page.getByRole('link', { name: '본문으로 건너뛰기' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#workspace')).toBeFocused();
  await page.getByLabel('판정 결과').selectOption('evidence');
  await page.getByRole('button', {name: '필터 적용', exact:true}).click();
  await expect(page).toHaveURL(/detection_result=evidence/);
  await expect(page.getByRole('table', {name:'수집 이벤트 목록'}).locator('tbody tr').first()).toContainText('판정 근거 포함');
  await page.getByLabel('판정 결과').selectOption('pending');
  await page.getByRole('button', {name: '필터 적용', exact:true}).click();
  await expect(page.getByRole('heading', {name:'조건에 맞는 이벤트가 없습니다.'})).toBeVisible();
  await page.getByRole('button', {name:'초기화',exact:true}).click();
  await expect(page.getByText('cowrie.login.failed').first()).toBeVisible();

  await page.getByRole('row').filter({ hasText: 'web.request' }).first().getByRole('button', { name: '상세 보기' }).click();
  await expect(page.getByRole('complementary', { name: '이벤트 상세' }).locator('pre')).toContainText('<img src=x onerror=alert(1)>');
  await checkDesign(page, 'event-detail');
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('private-test-canary');
  await page.getByRole('button', { name: '상세 접기', exact: true }).click();
  await expect(page.getByRole('complementary', { name: '이벤트 상세' })).toHaveCount(0);
  await page.getByRole('link', { name: '1.1.1.1', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'IP 상세', exact: true })).toBeVisible();
  await expect(page.getByText('SSH-REPEAT').first()).toBeVisible();
  await checkDesign(page, 'ip');
  // Many synthetic overlapping detections and a long explanation reproduce the
  // scroll issue without copying operational evidence into the browser fixture.
  const ipRoute = '**/api/v1/ips/*?*';
  await page.route(ipRoute, async route => {
    const fixtureURL = new URL(route.request().url());
    const query = new URLSearchParams(fixtureURL.search);
    expect(query.get('detection_limit')).toBe('10');
    const offset = query.has('detection_cursor') ? 10 : 0;
    fixtureURL.searchParams.delete('detection_cursor');
    const response = await route.fetch({ url: fixtureURL.toString() });
    const data = await response.json();
    await route.fulfill({ response, json: { ...data,
      detections: Array.from({ length: 10 }, (_, index) => ({ ...data.detections[0],
        detection_id: `synthetic-${offset + index}`, rule_id: `SSH-REPEAT-${offset + index}`,
        explanation: { text: 'Synthetic explanation. '.repeat(500) },
      })),
      next_detection_cursor: offset ? '' : 'synthetic-next',
    } });
  });
  await page.getByRole('button', { name: 'IP 새로고침' }).click();
  await expect(page.getByText('이 페이지 10건 · 페이지당 최대 10건')).toBeVisible();
  await expect(page.getByText('Synthetic explanation.', { exact: false })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 1000 });
  expect(await page.locator('.detection-section').evaluate(node => node.scrollHeight)).toBeLessThan(3200);
  await checkDesign(page, 'ip-many-detections');
  expect(await page.locator('.detection-section').evaluate(node => node.scrollHeight)).toBeLessThan(1200);
  const detailButton = page.getByRole('table', { name: 'IP 탐지 목록' }).getByRole('button', { name: '상세 보기' }).first();
  await detailButton.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: '탐지 상세 · SSH-REPEAT-0', exact: true })).toBeVisible();
  await checkDesign(page, 'ip-detection-detail');
  await page.locator('.detection-detail pre').focus();
  await expect(page.locator('.detection-detail pre')).toBeFocused();
  await page.getByRole('button', { name: '상세 접기', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(detailButton).toBeFocused();
  await page.getByRole('link', { name: '다음 탐지', exact: true }).click();
  await expect(page.getByText('SSH-REPEAT-10', { exact: true })).toBeVisible();
  await expect(page.getByText('SSH-REPEAT-0', { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page.getByText('SSH-REPEAT-0', { exact: true })).toBeVisible();
  await page.unroute(ipRoute);
  await page.locator(`a[href="/reports/${id}"]`).click();
  await expect(page.getByRole('heading', { name: '신고 검토', exact: true })).toBeVisible();
  await expect(page.locator('.report-body')).toContainText('1.1.1.1');
  await expect(page.locator('.report-body')).toContainText('repeated failed SSH authentication attempts');
  await expect(page.locator('.report-body')).not.toContainText('cowrie');
  await expect(page.locator('.report-body')).not.toContainText('settings=v');
  await checkDesign(page, 'report-detail');
  const controls = page.getByRole('region', { name: '현재 개정 작업', exact: true });
  const draftBounds = await page.locator('.review-draft').boundingBox();
  const controlsBounds = await controls.boundingBox();
  expect(controlsBounds!.y).toBeCloseTo(draftBounds!.y, 0);
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.locator('.review-page').evaluate(node => node.scrollHeight)).toBeLessThan(2800);
  await page.screenshot({ path: '../.local/design-review/report-compact-mobile.png', fullPage: true });
  const evidenceDisclosure = page.locator('.review-reference > details').filter({ has: page.locator('summary', { hasText: /^증거 ·/ }) });
  await expect(evidenceDisclosure).not.toHaveAttribute('open', '');
  await evidenceDisclosure.locator('summary').focus();
  await page.keyboard.press('Enter');
  const evidenceButtons = page.getByRole('button', { name: /^이벤트 #.* 증거 보기$/ });
  await expect(evidenceButtons).toHaveCount(10);
  await expect(page.getByRole('region', { name: /^이벤트 #.* 증거 상세$/ })).toHaveCount(0);
  const firstEvidence = evidenceButtons.first();
  await firstEvidence.focus(); await page.keyboard.press('Enter');
  await expect(page.getByRole('region', { name: /^이벤트 #.* 증거 상세$/ })).toHaveCount(1);
  await evidenceButtons.first().click();
  await expect(firstEvidence).toHaveAttribute('aria-expanded', 'false');
  await expect(page.getByRole('region', { name: /^이벤트 #.* 증거 상세$/ })).toHaveCount(1);
  await checkDesign(page, 'report-evidence-open');
  await page.getByRole('button', { name: /^이벤트 #.* 증거 접기$/ }).click();
  await expect(page.getByText('연락처 후보가 여러 개임', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: '승인 및 발송', exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 900 });
  await page.getByRole('combobox', { name: /^연락처 후보/ }).selectOption('second@example.test');
  const saveRecipient = page.getByRole('button', { name: '수신자로 저장', exact: true });
  await saveRecipient.scrollIntoViewIfNeeded();
  const scrollBeforeSave = await page.evaluate(() => scrollY);
  expect(scrollBeforeSave).toBeGreaterThan(300);
  let releaseSnapshot!: () => void;
  const snapshotReady = new Promise<void>(resolve => { releaseSnapshot = resolve; });
  const reportRoute = `**/api/v1/reports/${id}`;
  await page.route(reportRoute, async route => {
    const response = await route.fetch();
    await snapshotReady;
    await route.fulfill({ response });
  });
  await page.getByRole('button', { name: '수신자로 저장', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: '수신자로 저장했습니다' })).toBeVisible();
  await expect(page.getByText('최신 신고 상태를 불러오는 중…', { exact: true })).toBeVisible();
  await expect(page.locator('.report-body')).toBeVisible();
  await expect(page.getByRole('button', { name: '초안 제외', exact: true })).toBeDisabled();
  expect(await page.evaluate(() => scrollY)).toBeGreaterThanOrEqual(scrollBeforeSave - 100);
  await expect(evidenceDisclosure).toHaveAttribute('open', '');
  releaseSnapshot();
  await expect(page.getByRole('button', { name: '초안 제외', exact: true })).toBeEnabled();
  await page.unroute(reportRoute);
  await expect(evidenceDisclosure).toHaveAttribute('open', '');
  await expect(page.locator('dd').filter({ hasText: /^second@example\.test$/ })).toBeVisible();
  await page.reload();
  await expect(page.locator('dd').filter({ hasText: /^second@example\.test$/ })).toBeVisible();
  await page.getByRole('button', { name: '초안 제외', exact: true }).click();
  await expect(page.getByText('rejected', { exact: true }).first()).toBeVisible();
  await page.reload();
  await expect(page.getByText('rejected', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: '초안 제외', exact: true })).toBeDisabled();
  await page.goto(`/reports/${process.env.CHEESETRAP_E2E_WEB_REPORT!}`);
  await expect(page.locator('.report-body')).toContainText('HTTP requests matching a path traversal pattern');
  await expect(page.locator('.report-body')).toContainText('/../etc/passwd');
  await page.screenshot({ path: '../.local/e2e/browser/report.png', fullPage: true });
  expect(failures).toEqual([]);
});
