import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiClient } from '../../api/client';
import { deferred, fetcher, json, sampleEvent } from '../../test/fixtures';
import { EventList } from './EventList';

const page = (items = [sampleEvent], next_cursor = '') => json({ items, next_cursor });
describe('EventList', () => {
  beforeEach(() => window.history.replaceState({}, '', '/events'));
  it('selects login failures by their readable name and sends the full event type', async () => {
    const queries: URLSearchParams[] = [];
    render(<EventList client={new ApiClient(fetcher(url => { queries.push(url.searchParams); return page(); }))} />);
    await screen.findByText('192.0.2.10');
    const option = screen.getByRole('option', { name: 'SSH · 로그인 실패' });
    fireEvent.change(screen.getByRole('combobox', { name: '이벤트 유형' }), { target: { value: (option as HTMLOptionElement).value } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    await waitFor(() => expect(queries.at(-1)?.get('event_type')).toBe('cowrie.login.failed'));
    expect(new URLSearchParams(window.location.search).get('event_type')).toBe('cowrie.login.failed');
    fireEvent.click(screen.getByRole('button', { name: '초기화' }));
    await waitFor(() => expect(queries.at(-1)?.has('event_type')).toBe(false));
    expect(screen.getByRole('combobox', { name: '이벤트 유형' })).toHaveValue('');
  });
  it('preserves unknown event types from shared URLs and allows exact custom input', async () => {
    window.history.replaceState({}, '', '/events?event_type=future.event');
    const queries: URLSearchParams[] = [];
    render(<EventList client={new ApiClient(fetcher(url => { queries.push(url.searchParams); return page(); }))} />);
    await screen.findByText('192.0.2.10');
    expect(screen.getByLabelText('이벤트 유형 직접 입력')).toHaveValue('future.event');
    fireEvent.change(screen.getByLabelText('이벤트 유형 직접 입력'), { target: { value: 'other.event' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    await waitFor(() => expect(queries.at(-1)?.get('event_type')).toBe('other.event'));
    fireEvent.click(screen.getByRole('button', { name: '초기화' }));
    expect(screen.queryByLabelText('이벤트 유형 직접 입력')).not.toBeInTheDocument();
  });
  it('shows loading, then an honest empty state', async () => {
    const pending = deferred<Response>();
    render(<EventList client={new ApiClient(fetcher(() => pending.promise))} />);
    expect(screen.getByRole('status')).toHaveTextContent('이벤트를 불러오는 중');
    await act(async () => pending.resolve(page([])));
    expect(await screen.findByText('조건에 맞는 이벤트가 없습니다.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
  it('shows collection failures separately from empty results and supports retry', async () => {
    let fail = true;
    render(<EventList client={new ApiClient(fetcher(() => fail ? json({}, 503) : page()))} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('이벤트를 불러오지 못했습니다.');
    expect(screen.queryByText('조건에 맞는 이벤트가 없습니다.')).not.toBeInTheDocument();
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByText('192.0.2.10')).toBeInTheDocument();
  });
  it('preserves every filter across cursor pages and resets the cursor on apply/reset', async () => {
    const queries: URLSearchParams[] = [];
    const client = new ApiClient(fetcher((url) => { queries.push(url.searchParams); return page([sampleEvent], 'opaque+/='); }));
    render(<EventList client={client} />);
    await screen.findByText('192.0.2.10');
    fireEvent.change(screen.getByLabelText('출발지 IP'), { target: { value: '192.0.2.10' } });
    fireEvent.change(screen.getByLabelText('서비스'), { target: { value: 'ssh' } });
    fireEvent.change(screen.getByRole('combobox', { name: '이벤트 유형' }), { target: { value: 'cowrie.login.failed' } });
    fireEvent.change(screen.getByLabelText('수집 시작 (포함)'), { target: { value: '2026-10-17T10:00' } });
    fireEvent.change(screen.getByLabelText('수집 종료 (제외)'), { target: { value: '2026-10-18T10:00' } });
    fireEvent.change(screen.getByLabelText('판정 결과'), { target: { value: 'no_match' } });
    fireEvent.change(screen.getByLabelText('테스트 이벤트'), { target: { value: 'true' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    await waitFor(() => expect(queries).toHaveLength(2));
    fireEvent.click(await screen.findByRole('button', { name: '다음' }));
    await waitFor(() => expect(queries).toHaveLength(3));
    expect(Object.fromEntries(queries[2])).toEqual({ limit: '50', cursor: 'opaque+/=', source_ip: '192.0.2.10', service: 'ssh', event_type: 'cowrie.login.failed', since: new Date('2026-10-17T10:00').toISOString(), until: new Date('2026-10-18T10:00').toISOString(), is_test: 'true', detection_result: 'no_match' });
    fireEvent.change(screen.getByLabelText('서비스'), { target: { value: 'http' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    await waitFor(() => expect(queries).toHaveLength(4));
    expect(queries[3].has('cursor')).toBe(false);
    expect(queries[3].get('service')).toBe('http');
    fireEvent.click(screen.getByRole('button', { name: '초기화' }));
    await waitFor(() => expect(queries).toHaveLength(5));
    expect(Object.fromEntries(queries[4])).toEqual({ limit: '50' });
  });
  it('renders attacker-controlled fields as inert text and preserves bigint/null/quality details', async () => {
    const attack = '<img src=x onerror="alert(1)">';
    const event = { ...sampleEvent, event_type: attack, is_test: true, quality_flags: ['missing_timestamp'], attributes_truncated: true, attributes: { command: '<script>alert(1)</script>', url: 'javascript:alert(1)' } };
    const network = fetcher((url) => url.pathname.endsWith(event.event_id) ? json(event) : page([event]));
    const { container } = render(<EventList client={new ApiClient(network)} />);
    expect(await screen.findByText(attack)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '상세 보기' }));
    const detail = await screen.findByRole('complementary', { name: '이벤트 상세' });
    expect(within(detail).getByText('9007199254740993')).toBeInTheDocument();
    expect(within(detail).getByText('missing_timestamp')).toBeInTheDocument();
    expect(within(detail).getByText('속성 크기 제한으로 일부 증거가 생략되었습니다.')).toBeInTheDocument();
    expect(within(detail).getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(within(detail).getByText('기록 없음')).toBeInTheDocument();
    expect(container.querySelectorAll('img, script, a[href^="javascript:"]')).toHaveLength(0);
  });
  it('keeps a newer detail selection when an older request completes late', async () => {
    const late = deferred<Response>();
    const second = { ...sampleEvent, event_id: '00000000-0000-4000-8000-000000000002', attributes: { command: 'new evidence' } };
    const network = fetcher((url) => {
      if (url.pathname.endsWith(sampleEvent.event_id)) return late.promise;
      if (url.pathname.endsWith(second.event_id)) return json(second);
      return page([sampleEvent, second]);
    });
    render(<EventList client={new ApiClient(network)} />);
    const buttons = await screen.findAllByRole('button', { name: '상세 보기' });
    fireEvent.click(buttons[0]); fireEvent.click(buttons[1]);
    expect(await screen.findByText(/new evidence/)).toBeInTheDocument();
    await act(async () => late.resolve(json({ ...sampleEvent, attributes: { command: 'old evidence' } })));
    expect(screen.queryByText(/old evidence/)).not.toBeInTheDocument();
    expect(screen.getByText(/new evidence/)).toBeInTheDocument();
  });
  it.each(['not-an-ip', '999.1.1.1', '192.0.2', '192.0.2.1/24', '01.2.3.4', '2001:::1'])('rejects invalid IP %s inline without losing results', async (value) => {
    const network = fetcher(() => page());
    render(<EventList client={new ApiClient(network)} />);
    await screen.findByText('192.0.2.10');
    const input = screen.getByLabelText('출발지 IP');
    fireEvent.change(input, { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveFocus();
    expect(screen.getByRole('alert')).toHaveTextContent('IPv4');
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
    expect(network).toHaveBeenCalledOnce();
    expect(window.location.search).toBe('');
    fireEvent.change(input, { target: { value: '2001:db8::1' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    await waitFor(() => expect(network).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('opens details immediately after the selected row and restores focus on close', async () => {
    const second = { ...sampleEvent, event_id: '00000000-0000-4000-8000-000000000002' };
    render(<EventList client={new ApiClient(fetcher(url => url.pathname.endsWith(second.event_id) ? json(second) : page([sampleEvent, second])))} />);
    const buttons = await screen.findAllByRole('button', { name: '상세 보기' });
    fireEvent.click(buttons[1]);
    const detail = await screen.findByRole('complementary', { name: '이벤트 상세' });
    expect(buttons[1].closest('tr')?.nextElementSibling).toContainElement(detail);
    expect(buttons[1]).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(screen.getByRole('button', { name: '상세 접기' }));
    expect(buttons[1]).toHaveFocus();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });
  it('can collapse while loading and ignores the late detail response', async () => {
    const pending = deferred<Response>();
    render(<EventList client={new ApiClient(fetcher(url => url.pathname.endsWith(sampleEvent.event_id) ? pending.promise : page()))} />);
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(screen.getByText('상세를 불러오는 중…')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '상세 접기' }));
    await act(async () => pending.resolve(json(sampleEvent)));
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.queryByText('상세를 불러오는 중…')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '상세 보기' })).toHaveAttribute('aria-expanded', 'false');
  });
  it('does not call the API for an inverted time range', async () => {
    const network = fetcher(() => page([]));
    render(<EventList client={new ApiClient(network)} />);
    await screen.findByText('조건에 맞는 이벤트가 없습니다.');
    fireEvent.change(screen.getByLabelText('수집 시작 (포함)'), { target: { value: '2026-10-19T00:00' } });
    fireEvent.change(screen.getByLabelText('수집 종료 (제외)'), { target: { value: '2026-10-18T00:00' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    expect(screen.getByRole('alert')).toHaveTextContent('수집 시작 시각은 종료 시각보다 빨라야 합니다.');
    expect(network).toHaveBeenCalledOnce();
  });
  it('distinguishes detail failure from an empty list and restores focus on close', async () => {
    let detailFails = true;
    const network = fetcher((url) => url.pathname.endsWith(sampleEvent.event_id) ? (detailFails ? json({}, 503) : json(sampleEvent)) : page());
    render(<EventList client={new ApiClient(network)} />);
    fireEvent.click(await screen.findByRole('button', { name: '상세 보기' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('이벤트 상세를 불러오지 못했습니다.');
    detailFails = false;
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(await screen.findByRole('complementary', { name: '이벤트 상세' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '상세 접기' }));
    expect(screen.getByRole('button', { name: '상세 보기' })).toHaveFocus();
  });
  it('ignores a late response after filters change', async () => {
    const old = deferred<Response>();
    let count = 0;
    render(<EventList client={new ApiClient(fetcher(() => ++count === 1 ? old.promise : page([{ ...sampleEvent, source_ip: '192.0.2.22' }])))} />);
    fireEvent.change(screen.getByLabelText('서비스'), { target: { value: 'http' } });
    fireEvent.click(screen.getByRole('button', { name: '필터 적용' }));
    expect(await screen.findByText('192.0.2.22')).toBeInTheDocument();
    await act(async () => old.resolve(page()));
    expect(screen.queryByText('192.0.2.10')).not.toBeInTheDocument();
  });
  it('restores result filters from the URL and refreshes an expired snapshot from page one', async () => {
    window.history.replaceState({}, '', '/events?detection_result=no_match&cursor=expired');
    const queries: URLSearchParams[] = [];
    render(<EventList client={new ApiClient(fetcher(url => {
      queries.push(url.searchParams);
      return url.searchParams.has('cursor') ? json({}, 409) : page([{...sampleEvent, detection_result: 'no_match'}]);
    }))} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('목록 기준이 만료');
    expect(screen.getByLabelText('판정 결과')).toHaveValue('no_match');
    fireEvent.click(screen.getByRole('button', {name: '이벤트 새로고침'}));
    await screen.findByText('192.0.2.10');
    expect(queries[1].has('cursor')).toBe(false);
    expect(queries[1].get('detection_result')).toBe('no_match');
    expect(within(screen.getByRole('table')).getByText('판정 완료 · 근거 없음')).toBeInTheDocument();
    expect(screen.getByText(/근거 없음은 안전함을 뜻하지 않으며/)).toBeInTheDocument();
  });

});
