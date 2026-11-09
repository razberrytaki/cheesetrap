import { gapCauseLabel } from '../shared/gapLabels';
import type { Overview } from '../../api/client';
import { Field } from '../shared/ui';

type Operations = Overview['operations'];
const storageLabels: Record<string, string> = {
 normal: '정상', warning: '용량 경고', restricted: '용량 제한 중',
 unavailable: '용량 확인 불가', stale: '용량 관측 만료',
};
const stateLabels: Record<string, string> = { needs_review: '검토 대기', held: '보류', rejected: '제외', archived: '과거 기록' };
const seconds = (value: number | null) => value == null ? '관측 없음' : `${Math.ceil(value).toLocaleString('ko-KR')}초`;
export const statusTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
export const statusTimestamp = (value: string | null) => value == null ? '관측 없음' : new Date(value).toLocaleString('ko-KR', {year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'});
function SensorTime({ value }: { value: string | null }) {
 return value == null ? <span className="muted">관측 없음</span> : <time dateTime={value}>{statusTimestamp(value)}</time>;
}
export function OperationalStatus({ value, ingestedSeq, detectedSeq }: { value: Operations; ingestedSeq?: string; detectedSeq?: string }) {
 const usage = value?.disk_used_percent;
 const currentUsage = !!value && ['normal', 'warning', 'restricted'].includes(value.storage_state)
  && usage != null && Number.isFinite(usage) && usage >= 0 && usage <= 100;
 return <div className="operational-status">
  <div className="status-columns">
   <section aria-labelledby="processing-title"><h3 id="processing-title">처리 상태</h3>
    <dl className="status-fields">
     {ingestedSeq !== undefined && <Field name="수집 진행">이벤트 #{ingestedSeq}까지 저장</Field>}
     {detectedSeq !== undefined && <Field name="판정 진행">이벤트 #{detectedSeq}까지 판정 완료</Field>}
     <Field name="수집기 관측 지연">{seconds(value?.collection_lag_seconds ?? null)}</Field>
     <Field name="탐지 대기 시간">{seconds(value?.detection_lag_seconds ?? null)}</Field>
     <Field name="큐 최고 대기 시간">{seconds(value?.oldest_queue_age_seconds ?? null)}</Field>
     <Field name="조회 실패">{value?.lookup_failures ?? '확인 불가'}</Field>
    </dl>
   </section>
   <section aria-labelledby="operations-title"><h3 id="operations-title">저장 공간</h3>
    <dl className="status-fields">
     <Field name="용량 상태"><strong className={value?.storage_state === 'normal' ? 'status-healthy' : 'status-attention'}>{storageLabels[value?.storage_state ?? 'unavailable'] ?? '용량 확인 불가'}</strong></Field>
     {currentUsage && <><Field name="사용·예약">{usage.toFixed(1)}%</Field><Field name="사용 가능">{(100 - usage).toFixed(1)}%</Field></>}
     <Field name="보호 중인 이벤트">{value?.protected_events ?? '확인 불가'}</Field>
    </dl>
    {currentUsage ? <meter className="storage-meter" min={0} max={100} low={80} high={90} optimum={0} value={usage} aria-label="디스크 사용·예약 비율" /> : <p className="muted">현재 사용 가능한 공간을 확인할 수 없습니다.</p>}
    <p className="status-caption">80%부터 경고 · 90%부터 신규 수집·자동 처리 제한</p>
    <details className="status-explanation"><summary>저장 공간 계산 기준</summary>
     <p className="muted">데이터 저장 디스크 전체를 측정하며, 이벤트 데이터만의 크기가 아닙니다. 사용·예약에는 다른 파일과 시스템 예약 공간도 포함됩니다. 여러 저장 위치 중 가장 여유가 적은 곳을 기준으로 표시합니다.</p>
     <p className="status-caption">마지막 측정 {statusTimestamp(value?.storage_sampled_at ?? null)} ({statusTimeZone})</p>
     <p className="muted">측정값이 2분 넘게 갱신되지 않으면 현재 공간을 알 수 없는 상태로 표시합니다.</p>
    </details>
    {value?.storage_state === 'restricted' && <p role="status">신규 수집과 자동 처리가 제한됩니다. 용량이 복구되면 재개하며, 기존 공백 기록은 유지됩니다.</p>}
    {value?.storage_backlog && <p className="notice">판정·집계 또는 증거 사본을 기다리는 이벤트를 보호 중입니다. 처리 지연과 저장 공간을 확인하세요.</p>}
   </section>
  </div>
  <section className="sensor-observations" aria-labelledby="sensor-observations-title">
   <h3 id="sensor-observations-title">센서별 관측</h3>
   <p className="status-caption">수집기의 최근 관측과 엔진 로그 확인 시각을 함께 비교합니다. 기기 현지 시각 ({statusTimeZone}) 기준입니다.</p>
   {!value ? <p className="muted">운영 상태를 확인할 수 없습니다.</p> : (value.sensors ?? []).length === 0 ? <p className="muted">등록된 센서가 없습니다.</p> : <div className="sensor-comparison-scroll" role="region" aria-label="센서 비교표 가로 스크롤" tabIndex={0}>
    <table className="sensor-comparison"><caption className="sr-only">센서별 수집 상태 비교</caption>
     <thead><tr><th scope="col">센서</th><th scope="col">수집기 상태</th><th scope="col">수집기 관측</th><th scope="col">엔진 로그 확인</th><th scope="col">누적 공백</th><th scope="col">마지막 수집 공백</th></tr></thead>
     <tbody>{(value.sensors ?? []).map(sensor => <tr key={sensor.name}>
      <th scope="row">{sensor.name}</th>
      <td><span className={sensor.collector_state === 'active' ? 'status-healthy' : ''}>{stateLabels[sensor.collector_state] ?? sensor.collector_state}</span></td>
      <td><SensorTime value={sensor.last_observation_at} /></td><td><SensorTime value={sensor.last_engine_log_at} /></td><td>{sensor.gap_count}</td>
      <td>{sensor.last_gap ? <><SensorTime value={sensor.last_gap.started_at} /> ~ <SensorTime value={sensor.last_gap.observed_through} />{sensor.last_gap.causes.map(cause => <div key={cause}>{gapCauseLabel(cause)}</div>)}</> : '없음'}</td>
     </tr>)}</tbody>
    </table>
   </div>}
   <details className="status-explanation"><summary>두 시각은 어떻게 다른가요?</summary><p className="muted">수집기 관측은 수집기가 상태를 확인한 시각입니다. 엔진 로그 확인은 마지막 로그를 읽어 저장한 서버 시각입니다. 새 로그가 없다는 이유만으로 엔진 장애라고 판단하지 않습니다.</p></details>
  </section>
  {value && <details className="status-secondary"><summary>초안 검토 상태</summary>
   <div className="status-columns"><section><h4>신고 상태</h4><dl className="status-fields">{Object.entries(value.report_states ?? {}).map(([key, count]) => <Field key={key} name={stateLabels[key] ?? key}>{count}</Field>)}</dl></section>
   </div>
   <p className="muted">보관 중인 이력 기준입니다. 결과 불명은 성공 건수에 포함하지 않습니다.</p>
  </details>}
 </div>;
}
