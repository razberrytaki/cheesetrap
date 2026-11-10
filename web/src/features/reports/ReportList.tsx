import { holdReasonLabel } from '../shared/gapLabels';
import { useState, type FormEvent } from "react";
import { ApiClient, type ReportQuery, type Schema } from "../../api/client";
import { useRead } from "../shared/useRead";
import { ipHref, reportHref } from "../shared/ui";
import { utcTime } from "../events/format";
export function ReportRows({ items }: { items: Schema["ReportDraft"][] }) {
  return (
    <div className="event-results">
      <table className="event-table">
        <caption className="sr-only">신고 목록</caption>
        <thead>
          <tr>
            <th>생성 시각 (UTC)</th>
            <th>출발지 IP</th>
            <th>제목 / 수신자</th>
            <th>상태 / 보류</th>
            <th>상세</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.report_id}>
              <td data-label="생성 시각 (UTC)" className="timestamp mono">
                {utcTime(r.created_at, false)}
              </td>
              <td data-label="출발지 IP">
                <a href={ipHref(r.source_ip)}>{r.source_ip}</a>
              </td>
              <td data-label="제목 / 수신자">
                {r.subject}
                <span className="event-type">
                  {r.recipient || "수신자 미선택"}
                </span>
              </td>
              <td data-label="상태 / 보류">
                {r.state}
                {r.hold_reasons?.map((reason, i) => (
                  <span className="event-type" key={i}>
                    {holdReasonLabel(reason)}
                  </span>
                ))}
              </td>
              <td>
                <a href={reportHref(r.report_id)}>신고 보기</a>
                <span className="event-type">
                  증거 {r.evidence_count} · 규칙 {r.rule_count}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function ReportList({ client }: { client: ApiClient }) {
  const search = new URLSearchParams(window.location.search);
  const stateFilter = search.get("state");
  const query: ReportQuery = {
    limit: 50,
    source_ip: search.get("source_ip") || "",
    cursor: search.get("cursor") || "",
    ...(stateFilter === "held" ||
    stateFilter === "needs_review" ||
    stateFilter === "rejected" ||
    stateFilter === "archived"
      ? { state: stateFilter }
      : {}),
  };
  const [ip, setIP] = useState(query.source_ip || ""),
    [status, setStatus] = useState(query.state || ""),
    [retry, setRetry] = useState(0);
  const state = useRead(
    (signal) => client.reports(query, signal),
    [client, window.location.search, retry],
  );
  function apply(e: FormEvent) {
    e.preventDefault();
    const params = new URLSearchParams();
    if (ip.trim()) params.set("source_ip", ip.trim());
    if (status) params.set("state", status);
    window.history.pushState({}, "", `/reports?${params}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }
  return (
    <section>
      <div className="section-heading">
        <div>
          <p className="eyebrow">초안 근거 확인</p><h1>신고 목록</h1>
          <p className="muted">현재 개정의 상태와 보류 사유를 확인합니다.</p>
        </div>
        <button
          aria-label="신고 목록 새로고침"
          disabled={state.kind === "loading"}
          onClick={() => setRetry((n) => n + 1)}
        >
          새로고침
        </button>
      </div>
      <form className="filters" onSubmit={apply}>
        <div className="filter-fields">
          <label>
            출발지 IP
            <input value={ip} onChange={(e) => setIP(e.target.value)} />
          </label>
          <label>
            신고 상태
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as typeof status)}
            >
              <option value="">전체</option>
              <option value="held">보류</option>
              <option value="needs_review">검토 대기</option>
              <option value="rejected">제외</option>
              <option value="archived">과거 기록</option>
            </select>
          </label>
        </div>
        <div className="filter-actions">
          <button type="submit">필터 적용</button>
        </div>
      </form>
      {state.kind === "loading" ? (
        <p role="status">신고를 불러오는 중…</p>
      ) : state.kind === "error" ? (
        <p role="alert" className="error">
          {state.message}
        </p>
      ) : (
        <>
          {state.data.items?.length ? (
            <ReportRows items={state.data.items} />
          ) : (
            <p className="result-message">조건에 맞는 신고가 없습니다.</p>
          )}
          <div className="pagination">
            <span>
              이 페이지 {state.data.items?.length ?? 0}건 · 이전 페이지는
              브라우저 뒤로가기로 이동
            </span>
            {state.data.next_cursor && (
              <a
                href={`/reports?${new URLSearchParams({ ...Object.fromEntries(search), cursor: state.data.next_cursor })}`}
              >
                다음 페이지
              </a>
            )}
          </div>
        </>
      )}
    </section>
  );
}
