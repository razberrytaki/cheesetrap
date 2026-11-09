import { expect, it } from 'vitest';
import { gapCauseLabel, holdReasonLabel } from './gapLabels';

it('labels the closed gap vocabulary and preserves unknown codes', () => {
  expect(['retention_cleanup', 'storage_restricted', 'source_change', 'legacy'].map(gapCauseLabel)).toEqual([
    '보관 정리로 원본 삭제(미확인 손실 가능)', '저장 공간 제한으로 수집 중지', '로그 파일 변경 또는 읽기 오류', '이전 버전에서 기록된 공백',
  ]);
  expect(holdReasonLabel('collection_gap')).toBe('수집 공백 기록');
  expect(gapCauseLabel('__proto__')).toBe('__proto__');
  expect(holdReasonLabel('constructor')).toBe('constructor');
  expect(gapCauseLabel('future_cause')).toBe('future_cause');
  expect(holdReasonLabel('future_reason')).toBe('future_reason');
});
