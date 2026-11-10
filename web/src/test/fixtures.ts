import { vi } from 'vitest';
import type { Event, Overview } from '../api/client';

export const identity = { admin_id: 'admin-id', username: 'operator' };
export const sampleEvent: Event = {
  detection_result: "pending",
  event_id: '00000000-0000-4000-8000-000000000001', ingestion_seq: '9007199254740993',
  engine: 'cowrie', service: 'ssh', event_type: 'login.failed', source_ip: '192.0.2.10',
  source_port: 45678, destination_ip: null, destination_port: null, session_id: null,
  observed_at: null, ingested_at: '2026-10-18T01:02:03Z', quality_flags: null,
  is_test: false, attributes: { username: 'root' }, attributes_truncated: false,
};
export const overview: Overview = {
  operations: { storage_state: 'unavailable', disk_used_percent: null, storage_sampled_at: null,
    storage_backlog: false, protected_events: '0', collection_lag_seconds: null, detection_lag_seconds: null, oldest_queue_age_seconds: null,
    lookup_failures: '0', report_states: {}, sensors: [],
    retention: { raw_days: 7, raw_bytes: "1073741824", event_days: 30, history_days: 180, job_days: 7 } },
  ingested_seq: '9007199254740993', detected_seq: '9007199254740992',
  sensors_active: '2', sensors_degraded: '1', sensors_unknown: '3', sensors_disabled: '4', sensors_with_gaps: '1', sensors_recent_gaps: '1',
};
export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
export function fetcher(handler: (url: URL, init?: RequestInit) => Response | Promise<Response>) {
  return vi.fn<typeof fetch>((input, init) => Promise.resolve(handler(new URL(String(input), 'http://127.0.0.1:8080'), init)));
}
