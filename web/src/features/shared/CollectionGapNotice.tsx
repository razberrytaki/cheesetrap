import { gapCauseLabel } from './gapLabels';
import { utcTime } from '../events/format';

type Incident = { started_at: string; observed_through: string; causes: string[] };
function incident(value: unknown): Incident | null {
  if (value == null || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  if (typeof v.started_at !== 'string' || typeof v.observed_through !== 'string') return null;
  return { started_at: v.started_at, observed_through: v.observed_through,
    causes: Array.isArray(v.causes) ? v.causes.filter((cause): cause is string => typeof cause === 'string') : [] };
}

export function CollectionGapNotice({ value }: { value: unknown }) {
  if (value == null || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const incidents = (Array.isArray(raw.incidents) ? raw.incidents : [value]).map(incident).filter((v): v is Incident => v !== null);
  if (!incidents.length) return null;
  return <div className="notice"><p>신고 기간 중 수집 공백 기록 (UTC)</p>
    <ul>{incidents.map((gap, i) => <li key={i}>
      <time dateTime={gap.started_at}>{utcTime(gap.started_at)}</time> ~ <time dateTime={gap.observed_through}>{utcTime(gap.observed_through)}</time>
      {gap.causes.map(cause => <div key={cause}>{gapCauseLabel(cause)}</div>)}
    </li>)}</ul>
  </div>;
}
