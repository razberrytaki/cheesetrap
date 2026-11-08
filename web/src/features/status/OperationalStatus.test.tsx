import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { Overview } from '../../api/client';
import { OperationalStatus } from './OperationalStatus';

const sample = {
 storage_state: 'normal', disk_used_percent: 42.3, storage_sampled_at: '2026-10-25T12:00:00Z',
 storage_backlog: false, protected_events: '0', collection_lag_seconds: null,
 detection_lag_seconds: null, oldest_queue_age_seconds: null, lookup_failures: '0',
 sensors: [], report_states: {},
 retention: {raw_days:7,raw_bytes:"1073741824",event_days:30,history_days:180,job_days:7},
} as NonNullable<Overview['operations']>;

describe('storage explanation', () => {
 it('distinguishes unavailable space from remaining space and explains thresholds', () => {
  render(<OperationalStatus value={sample} />);
  expect(screen.getByText('42.3%')).toBeVisible();
  expect(screen.getByText('57.7%')).toBeVisible();
  expect(screen.getByText('사용·예약')).toBeVisible();
  expect(screen.getByText('사용 가능')).toBeVisible();
  expect(screen.getByText(/80%부터 경고/)).toBeVisible();
  fireEvent.click(screen.getByText('저장 공간 계산 기준'));
  expect(screen.getByText(/이벤트 데이터만의 크기가 아닙니다/)).toBeVisible();
 });
 it.each(['stale', 'unavailable'])('does not present %s observations as current free space', state => {
  render(<OperationalStatus value={{...sample, storage_state:state}} />);
  expect(screen.queryByText('57.7%')).not.toBeInTheDocument();
  expect(screen.getByText('현재 사용 가능한 공간을 확인할 수 없습니다.')).toBeVisible();
 });
 it('never turns missing usage into zero', () => {
  render(<OperationalStatus value={{...sample, storage_state:'unavailable', disk_used_percent:null}} />);
  expect(screen.queryByText('0.0%')).not.toBeInTheDocument();
  expect(screen.getByText('현재 사용 가능한 공간을 확인할 수 없습니다.')).toBeVisible();
 });
});
