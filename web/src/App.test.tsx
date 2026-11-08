import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { ApiClient } from './api/client';
import { deferred, fetcher, identity, json, overview, sampleEvent } from './test/fixtures';
import { App } from './App';

describe('App session boundary', () => {
  beforeEach(() => window.history.replaceState({}, '', '/events?'));
  it('clears protected events on expiry and ignores a late protected status response', async () => {
    let expired = false;
    const late = deferred<Response>();
    const network = fetcher((url) => {
      if (url.pathname.endsWith('/me')) return json(identity);
      if (url.pathname.endsWith('/overview')) return expired ? late.promise : json(overview);
      return expired ? json({}, 401) : json({ items: [sampleEvent], next_cursor: '' });
    });
    render(<App client={new ApiClient(network)} />);
    expect(await screen.findByText('192.0.2.10')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: '이벤트 새로고침' })).toBeEnabled());
    expired = true;
    fireEvent.click(screen.getByRole('button', { name: '이벤트 새로고침' }));
    expect(await screen.findByText('세션이 만료되었습니다. 다시 로그인하세요.')).toBeInTheDocument();
    expect(screen.queryByText('192.0.2.10')).not.toBeInTheDocument();
    await act(async () => late.resolve(json(overview)));
    expect(screen.queryByText('이벤트 #9007199254740993까지 저장')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '로그인' })).toBeInTheDocument();
  });
  it('shows actual collection progress without labeling it as attack or online counts', async () => {
    const network = fetcher((url) => url.pathname.endsWith('/me') ? json(identity) : url.pathname.endsWith('/overview') ? json(overview) : json({ items: [], next_cursor: '' }));
    render(<App client={new ApiClient(network)} />);
    expect(await screen.findByText('이벤트 #9007199254740993까지 저장')).toBeInTheDocument();
    expect(screen.getByText('이벤트 #9007199254740992까지 판정 완료')).toBeInTheDocument();
    expect(screen.getByText('수집 진행')).toBeInTheDocument();
    expect(screen.getByText('판정 진행')).toBeInTheDocument();
    expect(screen.queryByText(/공격 수|온라인/)).not.toBeInTheDocument();
  });
  it('reports an unavailable status instead of invented zero counts and retries manually', async () => {
    let fail = true;
    const network = fetcher((url) => url.pathname.endsWith('/me') ? json(identity) : url.pathname.endsWith('/overview') ? (fail ? json({}, 503) : json(overview)) : json({ items: null, next_cursor: '' }));
    render(<App client={new ApiClient(network)} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('수집 상태를 불러오지 못했습니다.');
    expect(screen.queryByText('수집 진행')).not.toBeInTheDocument();
    expect(await screen.findByText('조건에 맞는 이벤트가 없습니다.')).toBeInTheDocument();
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: '이벤트 새로고침' }));
    expect(await screen.findByText('이벤트 #9007199254740993까지 저장')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('clears event data when the status endpoint expires the session', async () => {
    let expired = false;
    const network = fetcher((url) => url.pathname.endsWith('/me') ? json(identity) : url.pathname.endsWith('/overview') ? (expired ? json({}, 401) : json(overview)) : json({ items: [sampleEvent], next_cursor: '' }));
    render(<App client={new ApiClient(network)} />);
    await screen.findByText('192.0.2.10');
    await waitFor(() => expect(screen.getByRole('button', { name: '이벤트 새로고침' })).toBeEnabled());
    expired = true;
    fireEvent.click(screen.getByRole('button', { name: '이벤트 새로고침' }));
    expect(await screen.findByText('세션이 만료되었습니다. 다시 로그인하세요.')).toBeInTheDocument();
    expect(screen.queryByText('192.0.2.10')).not.toBeInTheDocument();
  });
  it('does not replace a startup network failure with a logged-out claim', async () => {
    render(<App client={new ApiClient(fetcher(() => { throw new TypeError('offline'); }))} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('서버에 연결할 수 없습니다.');
    expect(screen.queryByLabelText('비밀번호')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument();
  });
  it('refreshes both regions once while preserving all applied filters and readable results', async () => {
    const filters = 'source_ip=192.0.2.10&service=ssh&event_type=cowrie.login.failed&detection_result=pending&is_test=false&since=2026-10-17T00%3A00%3A00Z&until=2026-10-30T00%3A00%3A00Z';
    window.history.replaceState({}, '', `/events?${filters}`);
    const status = deferred<Response>(); const events = deferred<Response>();
    const requests: URL[] = []; let refreshing = false;
    const network = fetcher(url => {
      requests.push(url);
      if (url.pathname.endsWith('/me')) return json(identity);
      if (url.pathname.endsWith('/overview')) return refreshing ? status.promise : json(overview);
      return refreshing ? events.promise : json({ items: [sampleEvent], next_cursor: '' });
    });
    render(<App client={new ApiClient(network)} />);
    const refresh = await screen.findByRole('button', { name: '이벤트 새로고침' });
    await waitFor(() => expect(refresh).toBeEnabled());
    expect(screen.getAllByRole('button', { name: /새로고침/ })).toHaveLength(1);
    fireEvent.change(screen.getByLabelText('서비스'), {target: {value: 'http'}});
    refreshing = true; fireEvent.click(refresh);
    expect(refresh).toBeDisabled();
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
    expect(screen.getByText('이벤트 #9007199254740993까지 저장')).toBeInTheDocument();
    await act(async () => events.resolve(json({ items: [{ ...sampleEvent, ingestion_seq: '9007199254740994' }], next_cursor: '' })));
    expect(refresh).toBeDisabled();
    await act(async () => status.resolve(json({ ...overview, ingested_seq: '9007199254740994' })));
    await waitFor(() => expect(refresh).toBeEnabled());
    expect(screen.getByText('이벤트 #9007199254740994까지 저장')).toBeInTheDocument();
    const eventRequests = requests.filter(url => url.pathname.endsWith('/events'));
    expect(eventRequests).toHaveLength(2);
    expect(eventRequests[1].search).toBe(eventRequests[0].search);
    expect(requests.filter(url => url.pathname.endsWith('/overview'))).toHaveLength(2);
    expect(new URLSearchParams(window.location.search).toString()).toBe(filters);
    expect(screen.getByLabelText('출발지 IP')).toHaveValue('192.0.2.10');
    expect(screen.getByLabelText('이벤트 유형')).toHaveValue('cowrie.login.failed');
    expect(screen.getByLabelText('서비스')).toHaveValue('http');
  });
  it('keeps the successful region usable when status refresh fails and retries both', async () => {
    let statusFails = false; let eventType = 'login.failed';
    const network = fetcher(url => url.pathname.endsWith('/me') ? json(identity)
      : url.pathname.endsWith('/overview') ? (statusFails ? json({}, 503) : json(overview))
      : json({ items: [{ ...sampleEvent, event_type: eventType }], next_cursor: '' }));
    render(<App client={new ApiClient(network)} />);
    const refresh = await screen.findByRole('button', { name: '이벤트 새로고침' });
    await waitFor(() => expect(refresh).toBeEnabled());
    statusFails = true; eventType = 'cowrie.session.connect'; fireEvent.click(refresh);
    expect(await screen.findByRole('alert')).toHaveTextContent('이전 조회 결과를 표시합니다.');
    expect(await screen.findByText('cowrie.session.connect')).toBeInTheDocument();
    await waitFor(() => expect(refresh).toBeEnabled());
    statusFails = false; fireEvent.click(refresh);
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });
  it('refreshes a cursor page from the first page without dropping its filters', async () => {
    window.history.replaceState({}, '', '/events?service=ssh&event_type=cowrie.login.failed&cursor=older-page');
    const queries: URL[] = [];
    const network = fetcher(url => {
      if (url.pathname.endsWith('/me')) return json(identity);
      if (url.pathname.endsWith('/overview')) return json(overview);
      queries.push(url); return json({ items: [sampleEvent], next_cursor: '' });
    });
    render(<App client={new ApiClient(network)} />);
    await waitFor(() => expect(screen.getByRole('button', { name: '이벤트 새로고침' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: '이벤트 새로고침' }));
    await waitFor(() => expect(queries).toHaveLength(2));
    expect(Object.fromEntries(queries[1].searchParams)).toEqual({limit: '50', service: 'ssh', event_type: 'cowrie.login.failed'});
    expect(screen.getByLabelText('서비스')).toHaveValue('ssh');
    expect(screen.getByLabelText('이벤트 유형')).toHaveValue('cowrie.login.failed');
  });
  it('retains the previous list on refresh failure while showing the updated collection status', async () => {
    let fails = false;
    const network = fetcher(url => url.pathname.endsWith('/me') ? json(identity)
      : url.pathname.endsWith('/overview') ? json({...overview, ingested_seq: fails ? '9007199254740995' : overview.ingested_seq})
      : fails ? json({}, 503) : json({items: [sampleEvent], next_cursor: ''}));
    render(<App client={new ApiClient(network)} />);
    const refresh = await screen.findByRole('button', {name: '이벤트 새로고침'});
    await waitFor(() => expect(refresh).toBeEnabled());
    fails = true; fireEvent.click(refresh);
    expect(await screen.findByRole('alert')).toHaveTextContent('이벤트를 불러오지 못했습니다.');
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument();
    expect(await screen.findByText('이벤트 #9007199254740995까지 저장')).toBeInTheDocument();
    await waitFor(() => expect(refresh).toBeEnabled());
  });
});
