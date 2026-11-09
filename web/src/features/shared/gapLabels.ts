export const gapCauseLabels: Record<string, string> = {
  retention_cleanup: '보관 정리로 원본 삭제(미확인 손실 가능)',
  storage_restricted: '저장 공간 제한으로 수집 중지',
  source_change: '로그 파일 변경 또는 읽기 오류',
  legacy: '이전 버전에서 기록된 공백',
};

export const holdReasonLabels: Record<string, string> = {
  collection_gap: '수집 공백 기록',
  contact_ambiguous: '연락처 후보가 여러 개임',
  contact_missing: '신고 연락처 없음',
  contact_expired: '신고 연락처 조회 만료',
  contact_lookup_failed: '신고 연락처 조회 실패',
  contact_address_mismatch: '신고 연락처 주소 불일치',
  evidence_ineligible: '신고 증거 부적격',
  test_evidence: '테스트 증거 포함',
  observed_at_missing: '관측 시각 없음',
  destination_not_public: '공개 목적지 확인 필요',
  stale_evidence: '오래된 증거',
  reply_to_missing: '회신 주소 미설정',
};

export const gapCauseLabel = (cause: string) => Object.hasOwn(gapCauseLabels, cause) ? gapCauseLabels[cause] : cause;
export const holdReasonLabel = (reason: string) => Object.hasOwn(holdReasonLabels, reason) ? holdReasonLabels[reason] : reason;
