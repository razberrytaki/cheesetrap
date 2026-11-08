import { useEffect, useState } from 'react';
import { OperationalStatus, statusTimestamp, statusTimeZone } from './OperationalStatus';
import { ApiClient, errorMessage, isCancelled, type Overview } from '../../api/client';

type State = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; data: Overview; at: string };
const labels: [Exclude<keyof Overview, "operations">, string][] = [['sensors_active', '활성'], ['sensors_degraded', '저하'], ['sensors_unknown', '확인 불가'], ['sensors_disabled', '비활성'], ['sensors_with_gaps', '수집 공백']];
export function CollectionStatus({ client, dashboard = false, refreshRevision, onLoadingChange }: {
  client: ApiClient; dashboard?: boolean; refreshRevision?: number; onLoadingChange?: (loading: boolean) => void;
}) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshError, setRefreshError] = useState('');
  useEffect(() => {
    const abort = new AbortController(); let active = true;
    setLoading(true); onLoadingChange?.(true); setRefreshError('');
    setState(previous => previous.kind === 'ready' ? previous : { kind: 'loading' });
    client.overview(abort.signal).then((data) => { if (active) setState({ kind: 'ready', data, at: new Date().toISOString() }); })
      .catch((error: unknown) => { if (active && !isCancelled(error)) {
        const message = errorMessage(error, '수집 상태를 불러오지 못했습니다. 잠시 후 다시 시도하세요.');
        setRefreshError(message);
        setState(previous => previous.kind === 'ready' ? previous : { kind: 'error', message });
      } }).finally(() => { if (active) { setLoading(false); onLoadingChange?.(false); } });
    return () => { active = false; abort.abort(); };
  }, [client, revision, refreshRevision, onLoadingChange]);
  return <section className={`collection-status${dashboard ? " dashboard-status" : ""}`} aria-labelledby="collection-title" aria-busy={loading}>
    <div className={dashboard ? "sr-only" : "section-heading compact"}><h2 id="collection-title">{dashboard ? "운영 현황" : "수집 상태"}</h2>{refreshRevision === undefined && <button className="quiet" aria-label="수집 상태 새로고침" onClick={() => setRevision((n) => n + 1)} disabled={loading}>새로고침</button>}</div>
    {state.kind === 'loading' && <p className="muted" role="status">수집 상태를 불러오는 중…</p>}
    {state.kind === 'error' && <p role="alert" className="error">{state.message}</p>}
    {state.kind === 'ready' && refreshError && <p role="alert" className="error">{refreshError} 이전 조회 결과를 표시합니다.</p>}
    {state.kind === 'ready' && <>
      <div className={dashboard ? "dashboard-layout" : undefined}>
      {dashboard && <ReviewFocus data={state.data} />}
      <div className={dashboard ? "dashboard-health" : undefined}>
      {dashboard && <h3>수집 상태</h3>}
      <div className="collection-summary">
        <dl className={dashboard ? "dashboard-readings" : "sensor-counts"}>
          <div><dt>활성 센서</dt><dd>{state.data.sensors_active}</dd></div>
          <div><dt>수집 공백</dt><dd>{state.data.sensors_with_gaps}</dd></div>

        </dl>
        <span className="status-caption">확인 {statusTimestamp(state.at)} ({statusTimeZone})</span>
      </div>
      <div className="collection-alerts" role="status">
        {labels.filter(([key]) => key !== 'sensors_active' && state.data[key] !== '0').map(([key, label]) => <span className="notice" key={key}>{label} {state.data[key]}</span>)}
        {(!state.data.operations || state.data.operations.storage_state !== 'normal') && <span className="notice">{({ warning: '용량 경고', restricted: '용량 제한 중', stale: '용량 관측 만료' } as Record<string, string>)[state.data.operations?.storage_state ?? ''] ?? '용량 확인 불가'}</span>}
        {state.data.operations?.storage_backlog && <span className="notice">처리 지연으로 이벤트 보호 중</span>}
      </div>
      </div>
      </div>
      <details className="collection-details"><summary>수집 상태 상세</summary>
      <div className="collection-details-body">
      <OperationalStatus value={state.data.operations} ingestedSeq={state.data.ingested_seq} detectedSeq={state.data.detected_seq} />
      <details className="status-secondary"><summary>센서 상태별 집계</summary>
      <dl className="status-fields status-fields-narrow">{labels.map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{state.data[key]}</dd></div>)}</dl>
      <p className="muted">수집 공백은 다른 센서 상태와 중복될 수 있습니다.</p>
      </details>

      </div></details>
    </>}
  </section>;
}

function ReviewFocus({ data }: { data: Overview }) {
  const states = data.operations?.report_states;
  // Successful GROUP BY results omit states with zero reports; a missing breakdown is unknown.
  const count = states == null ? undefined : states.needs_review ?? '0';
  const message = count === undefined
    ? '검토 대기 수를 확인할 수 없습니다.'
    : count === '0' ? '검토 대기 신고가 없습니다.' : '검토할 신고가 있습니다.';
  return <section className="review-focus" aria-labelledby="review-focus-title">
    <h3 id="review-focus-title">검토 대기 신고</h3>
    <dl><dt className="sr-only">검토 대기 건수</dt>
      <dd className={`review-count${count === undefined ? ' unavailable' : ''}`}>{count ?? '확인 불가'}</dd>
    </dl>
    <p className="review-message">{message}</p>
    <p className="muted">{count === undefined ? '신고 목록에서 현재 상태를 확인하세요.' : '관측 기록과 증거를 확인한 뒤 신고 초안을 검토하세요.'}</p>
    <a className="review-action" href="/reports?state=needs_review"><span>{count === '0' || count === undefined ? '검토 대기 목록 확인' : '신고 검토하기'}</span><span aria-hidden="true">→</span></a>
  </section>;
}
