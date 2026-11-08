import { useEffect, useState } from 'react';
import { ApiClient, ApiError, errorMessage, isCancelled, type Event } from '../../api/client';
import { resultLabels } from './result';
import { utcTime } from './format';

type State = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; event: Event };
export function EventDetail({ client, id }: { client: ApiClient; id: string }) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const abort = new AbortController(); let active = true;
    setState({ kind: 'loading' });
    client.event(id, abort.signal).then((event) => { if (active) setState({ kind: 'ready', event }); })
      .catch((error: unknown) => { if (active && !isCancelled(error)) setState({ kind: 'error', message: error instanceof ApiError && error.status === 404 ? '이벤트를 찾을 수 없습니다. 목록을 새로고침하세요.' : errorMessage(error, '이벤트 상세를 불러오지 못했습니다. 다시 시도하세요.') }); });
    return () => { active = false; abort.abort(); };
  }, [client, id, attempt]);
  if (state.kind === 'loading') return <section className="inspector"><p role="status">상세를 불러오는 중…</p></section>;
  if (state.kind === 'error') return <section className="inspector"><h2>이벤트 상세</h2><p role="alert" className="error">{state.message}</p><div className="inline-actions"><button onClick={() => setAttempt((n) => n + 1)}>다시 시도</button></div></section>;
  const event = state.event;
  return <aside className="inspector" aria-label="이벤트 상세">
    <div className="section-heading compact"><h2>이벤트 상세</h2></div>
    <p className="detail-type">{event.event_type}</p>
    <dl className="detail-fields">
      <div><dt>이벤트 ID</dt><dd className="mono">{event.event_id}</dd></div>
      <div><dt>판정 결과 (현재)</dt><dd>{resultLabels[event.detection_result]}</dd></div>
      <div><dt>수집 순번</dt><dd className="mono">{event.ingestion_seq}</dd></div>
      <div><dt>엔진 / 서비스</dt><dd>{event.engine} / {event.service}</dd></div>
      <div><dt>수집 시각</dt><dd className="mono">{utcTime(event.ingested_at)}</dd></div>
      <div><dt>관측 시각</dt><dd className="mono">{event.observed_at ? utcTime(event.observed_at) : '기록 없음'}</dd></div>
      <div><dt>출발지 IP / 포트</dt><dd className="mono">{event.source_ip ?? '—'} / {event.source_port ?? '—'}</dd></div>
      <div><dt>목적지 IP / 포트</dt><dd className="mono">{event.destination_ip ?? '—'} / {event.destination_port ?? '—'}</dd></div>
      <div><dt>세션 ID</dt><dd className="mono">{event.session_id ?? '—'}</dd></div>
      <div><dt>테스트 이벤트</dt><dd>{event.is_test ? '예' : '아니요'}</dd></div>
      <div><dt>품질 플래그</dt><dd>{event.quality_flags?.length ? <ul className="flag-list">{event.quality_flags.map((flag, i) => <li key={`${i}-${flag}`}>{flag}</li>)}</ul> : '없음'}</dd></div>
    </dl>
    <h3>정규화된 증거</h3>
    {event.attributes_truncated && <p className="notice">속성 크기 제한으로 일부 증거가 생략되었습니다.</p>}
    <pre className="evidence" tabIndex={0} aria-label="정규화된 증거">{JSON.stringify(event.attributes, null, 2)}</pre>
  </aside>;
}
