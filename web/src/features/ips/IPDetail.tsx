import { Fragment, useEffect, useState } from "react";
import { ApiClient } from "../../api/client";
import { useRead } from "../shared/useRead";
import { Field, TextData } from "../shared/ui";
import { ReportRows } from "../reports/ReportList";
import { utcTime } from "../events/format";
export function IPDetail({ client, ip }: { client: ApiClient; ip: string }) {
  const [retry, setRetry] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const search = new URLSearchParams(window.location.search);
  useEffect(() => setSelected(null), [client, ip, window.location.search, retry]);
  const state = useRead(
    (signal) =>
      client.ip(
        ip,
        {
          limit: 10,
          detection_limit: 10,
          cursor: search.get("cursor") || "",
          detection_cursor: search.get("detection_cursor") || "",
        },
        signal,
      ),
    [client, ip, window.location.search, retry],
  );
  const next = (key: string, value: string) =>
    `/ips/${encodeURIComponent(ip)}?${new URLSearchParams({ ...Object.fromEntries(search), [key]: value })}`;
  return (
    <section>
      <div className="section-heading">
        <div>
          <p className="eyebrow">출발지별 증거</p><h1>IP 상세</h1>
          <p className="mono">{ip}</p>
        </div>
        <button
          onClick={() => setRetry((n) => n + 1)}
          disabled={state.kind === "loading"}
        >
          IP 새로고침
        </button>
      </div>
      <div className="inline-actions">
        <a href={`/events?${new URLSearchParams({ source_ip: ip })}`}>
          이 IP의 이벤트
        </a>
        <a href={`/events?${new URLSearchParams({ source_ip: ip, event_type: "cowrie.login.failed" })}`}>
          이 IP의 SSH 로그인 실패
        </a>
        <a href={`/reports?${new URLSearchParams({ source_ip: ip })}`}>
          이 IP의 신고
        </a>
      </div>
      {state.kind === "loading" ? (
        <p role="status">IP 정보를 불러오는 중…</p>
      ) : state.kind === "error" ? (
        <p className="error" role="alert">
          {state.message}
        </p>
      ) : (
        <>
          <section className="review-section">
            <h2>등록기관 및 연락처</h2>
            <dl className="detail-fields review-summary">
              <Field name="캐시 만료 시각">
                {state.data.registry_expires_at
                  ? utcTime(state.data.registry_expires_at)
                  : "정보 없음"}
              </Field>
              <Field name="최근 갱신 요청">
                {state.data.latest_refresh?.status || "요청 없음"}
              </Field>
            </dl>
            {state.data.registry_expired && (
              <p className="notice">
                등록기관 캐시가 만료되었습니다. 신고 검토 화면에서 갱신을 요청할
                수 있습니다.
              </p>
            )}
            {state.data.registry_truncated && (
              <p className="notice">등록기관 정보가 잘렸습니다.</p>
            )}
            <details>
              <summary>등록기관 상세 데이터</summary>
              <TextData value={state.data.registry} />
            </details>
          </section>
          <section className="review-section detection-section">
            <h2>탐지</h2>
            <p className="muted">이 페이지 {state.data.detections?.length ?? 0}건 · 페이지당 최대 10건</p>
            <p className="muted">같은 이벤트가 여러 탐지의 근거에 포함될 수 있습니다. 탐지 건수는 개별 공격 횟수가 아닙니다.</p>
            {state.data.detections?.length ? (
              <table className="event-table detection-table">
                <caption className="sr-only">IP 탐지 목록</caption>
                <thead><tr>
                  <th>규칙</th><th>판정 구간 종료 (UTC)</th><th>증거 수</th><th>증거 적격</th>
                  <th><span className="sr-only">상세</span></th>
                </tr></thead>
                <tbody>{state.data.detections.map((d) => (
                  <Fragment key={d.detection_id}>
                    <tr className={selected === d.detection_id ? "selected" : undefined}>
                      <td data-label="규칙"><span>{d.rule_id}</span><span className="event-type">버전 {d.rule_version}</span></td>
                      <td data-label="판정 구간 종료 (UTC)" className="mono timestamp"><time dateTime={d.window_end}>{utcTime(d.window_end, false)}</time></td>
                      <td data-label="증거 수">{d.evidence_count}</td>
                      <td data-label="증거 적격">{d.evidence_eligible ? "적격" : "부적격"}</td>
                      <td className="row-action"><button className="quiet"
                        aria-expanded={selected === d.detection_id}
                        aria-controls={selected === d.detection_id ? "selected-detection-detail" : undefined}
                        onClick={(e) => {
                          e.currentTarget.focus();
                          setSelected(current => current === d.detection_id ? null : d.detection_id);
                        }}
                      >{selected === d.detection_id ? "상세 접기" : "상세 보기"}</button></td>
                    </tr>
                    {selected === d.detection_id && <tr className="event-detail-row">
                      <td colSpan={5} id="selected-detection-detail">
                        <div className="detection-detail">
                          <h3>탐지 상세 · {d.rule_id}</h3>
                          <dl className="detail-fields review-summary">
                            <Field name="처리 수집 순번">{d.processing_ingestion_seq}</Field>
                            <Field name="규칙 설정 버전">{d.settings_version}</Field>
                          </dl>
                          {d.explanation_truncated && <p className="notice">탐지 설명이 잘렸습니다.</p>}
                          <TextData value={d} />
                        </div>
                      </td>
                    </tr>}
                  </Fragment>
                ))}</tbody>
              </table>
            ) : (
              <p className="muted">탐지가 없습니다.</p>
            )}
            <div className="pagination">
              <span>이전 페이지는 브라우저 뒤로가기로 이동</span>
              {state.data.next_detection_cursor && (
              <a
                href={next(
                  "detection_cursor",
                  state.data.next_detection_cursor,
                )}
              >
                다음 탐지
              </a>
              )}
            </div>
          </section>
          <section className="review-section">
            <h2>관련 신고</h2>
            {state.data.reports?.length ? (
              <ReportRows items={state.data.reports} />
            ) : (
              <p className="muted">관련 신고가 없습니다.</p>
            )}
            {state.data.next_cursor && (
              <a href={next("cursor", state.data.next_cursor)}>다음 신고</a>
            )}
          </section>
        </>
      )}
    </section>
  );
}
