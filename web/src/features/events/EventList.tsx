import { Fragment, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ApiClient,
  ApiError,
  errorMessage,
  isCancelled,
  type Event,
  type EventQuery,
} from "../../api/client";
import { ipHref } from "../shared/ui";
import { EventDetail } from "./EventDetail";
import { resultLabels } from "./result";
import { utcTime } from "./format";

function validIP(value: string): boolean {
  if (!value) return true;
  if (value.includes(":")) {
    // URL's IPv6 parser rejects malformed groups; exclude zones and URL syntax.
    if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
    try { new URL(`http://[${value}]/`); return true; } catch { return false; }
  }
  return /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)
    && value.split(".").every((part) => Number(part) <= 255);
}
const ipHelp = "IPv4(예: 192.0.2.10) 또는 IPv6(예: 2001:db8::1) 주소 하나를 입력하세요. IPv4의 각 숫자는 0~255이며, 포트·CIDR(/24)은 사용할 수 없습니다.";

const eventTypes: Record<string, string> = {
  "cowrie.login.failed": "SSH · 로그인 실패",
  "cowrie.login.success": "SSH · 로그인 성공",
  "cowrie.session.connect": "SSH · 연결 시작",
  "cowrie.session.closed": "SSH · 연결 종료",
  "cowrie.client.version": "SSH · 클라이언트 버전",
  "cowrie.client.kex": "SSH · 키 교환",
  "cowrie.session.params": "SSH · 세션 설정",
  "cowrie.command.input": "SSH · 명령 입력",
  "cowrie.log.closed": "SSH · 세션 기록 종료",
  "web.request": "HTTP / HTTPS · 요청",
};
const knownEventType = (value: string) => Object.hasOwn(eventTypes, value);

type Filters = {
  detection_result: "" | "pending" | "no_match" | "evidence";
  source_ip: string;
  service: string;
  event_type: string;
  since: string;
  until: string;
  is_test: "" | "true" | "false";
};
const blankFilters: Filters = {
  detection_result: "",
  source_ip: "",
  service: "",
  event_type: "",
  since: "",
  until: "",
  is_test: "",
};
type Page = { filters: EventQuery; cursor: string; history: string[] };
type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: Event[]; next: string };
export function EventList({ client, summary, onRefresh, refreshing = false }: {
  client: ApiClient; summary?: ReactNode; onRefresh?: () => void; refreshing?: boolean;
}) {
  const initial = Object.fromEntries(
    new URLSearchParams(window.location.search),
  );
  const initialFilters: EventQuery = {
    ...(["pending", "no_match", "evidence"].includes(initial.detection_result) ? {detection_result: initial.detection_result as EventQuery["detection_result"]} : {}),
    ...Object.fromEntries(
      ["source_ip", "service", "event_type", "since", "until"]
        .filter((key) => initial[key])
        .map((key) => [key, initial[key]]),
    ),
    ...(initial.is_test === "true" || initial.is_test === "false"
      ? { is_test: initial.is_test }
      : {}),
  };
  const localTime = (value: string | undefined) => {
    if (!value) return "";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "";
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16);
  };
  const [draft, setDraft] = useState<Filters>({
    ...blankFilters,
    ...initialFilters,
    since: localTime(initialFilters.since),
    until: localTime(initialFilters.until),
  } as Filters);
  const [customEventType, setCustomEventType] = useState(
    !!initial.event_type && !knownEventType(initial.event_type),
  );
  const [page, setPage] = useState<Page>({
    filters: initialFilters,
    cursor: initial.cursor || "",
    history: Array.isArray(window.history.state?.eventHistory)
      ? window.history.state.eventHistory.filter(
          (value: unknown): value is string => typeof value === "string",
        )
      : [],
  });
  const [state, setState] = useState<State>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshError, setRefreshError] = useState('');
  const [filterError, setFilterError] = useState("");
  const [ipError, setIPError] = useState("");
  const ipInput = useRef<HTMLInputElement | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    const abort = new AbortController();
    let active = true;
    setLoading(true); setRefreshError('');
    setState(previous => previous.kind === 'ready' ? previous : { kind: "loading" });
    setSelected(null);
    client
      .events(
        {
          limit: 50,
          ...page.filters,
          ...(page.cursor ? { cursor: page.cursor } : {}),
        },
        abort.signal,
      )
      .then((result) => {
        if (active)
          setState({
            kind: "ready",
            items: result.items ?? [],
            next: result.next_cursor,
          });
      })
      .catch((error: unknown) => {
        if (active && !isCancelled(error)) {
          const message = error instanceof ApiError && error.status === 409 ? "보관 정리로 목록 기준이 만료되었습니다. 새로고침하여 첫 페이지부터 조회하세요." : errorMessage(
              error,
              "이벤트를 불러오지 못했습니다. 필터와 서버 상태를 확인하고 다시 시도하세요.",
            );
          setRefreshError(message);
          setState(previous => previous.kind === 'ready' ? previous : { kind: 'error', message });
        }
      }).finally(() => { if (active) setLoading(false); });
    return () => {
      active = false;
      abort.abort();
    };
  }, [client, page, revision]);
  function movePage(cursor: string, history: string[]) {
    const params = new URLSearchParams(window.location.search);
    if (cursor) params.set("cursor", cursor);
    else params.delete("cursor");
    window.history.pushState(
      { eventHistory: history },
      "",
      `/events?${params}`,
    );
    window.dispatchEvent(new PopStateEvent("popstate"));
    setPage((previous) => ({ ...previous, cursor, history }));
  }
  function change(key: keyof Filters, value: string) {
    setDraft((previous) => ({ ...previous, [key]: value }));
    if (key === "source_ip" && ipError) setIPError(validIP(value.trim()) ? "" : ipHelp);
  }
  function apply(event: FormEvent) {
    event.preventDefault();
    if (!validIP(draft.source_ip.trim())) {
      setIPError(ipHelp);
      ipInput.current?.focus();
      return;
    }
    setIPError("");
    const since = draft.since ? new Date(draft.since) : undefined;
    const until = draft.until ? new Date(draft.until) : undefined;
    if (
      (since && Number.isNaN(since.getTime())) ||
      (until && Number.isNaN(until.getTime())) ||
      (since && until && since >= until)
    ) {
      setFilterError(
        "수집 시작 시각은 종료 시각보다 빨라야 합니다. 시간 범위를 확인하세요.",
      );
      return;
    }
    setFilterError("");
    const filters: EventQuery = {
      ...(draft.detection_result ? {detection_result: draft.detection_result} : {}),
      ...(draft.source_ip.trim() ? { source_ip: draft.source_ip.trim() } : {}),
      ...(draft.service.trim() ? { service: draft.service.trim() } : {}),
      ...(draft.event_type.trim()
        ? { event_type: draft.event_type.trim() }
        : {}),
      ...(since ? { since: since.toISOString() } : {}),
      ...(until ? { until: until.toISOString() } : {}),
      ...(draft.is_test ? { is_test: draft.is_test } : {}),
    };
    window.history.pushState(
      {},
      "",
      `/events?${new URLSearchParams(Object.entries(filters).map(([key, value]) => [key, String(value)]))}`,
    );
    window.dispatchEvent(new PopStateEvent("popstate"));
    setPage({ filters, cursor: "", history: [] });
  }
  function reset() {
    window.history.pushState({}, "", "/events");
    window.dispatchEvent(new PopStateEvent("popstate"));
    setDraft(blankFilters);
    setCustomEventType(false);
    setIPError("");
    setFilterError("");
    setPage({ filters: {}, cursor: "", history: [] });
  }
  return (
    <section className="events-section" aria-labelledby="events-title">
      <div className="section-heading">
        <div>
          <h1 id="events-title">이벤트</h1>
          <p className="muted">수집된 이벤트를 조회하고 증거를 확인합니다.</p>
        </div>
        <button
          aria-label="이벤트 새로고침"
          onClick={() => { if (page.cursor) movePage("", []); setRevision((n) => n + 1); onRefresh?.(); }}
          disabled={loading || refreshing}
        >
          {loading || refreshing ? '갱신 중…' : '새로고침'}
        </button>
      </div>
      {summary}
      {state.kind === 'ready' && refreshError && <p className="error" role="alert">{refreshError} 이전 조회 결과를 표시합니다.</p>}
      <form className="filters" onSubmit={apply}>
        <div className="filter-fields">
          <div className="ip-filter">
          <label htmlFor="source-ip">출발지 IP</label>
            <input
              id="source-ip"
              ref={ipInput}
              aria-invalid={!!ipError}
              aria-describedby={ipError ? "source-ip-error" : undefined}
              value={draft.source_ip}
              onChange={(e) => change("source_ip", e.target.value)}
              placeholder="192.0.2.10"
              maxLength={64}
            />
            {ipError && <p id="source-ip-error" className="error field-error" role="alert">{ipError}</p>}
          </div>
          <label>
            서비스
            <input
              value={draft.service}
              onChange={(e) => change("service", e.target.value)}
              placeholder="ssh"
              maxLength={64}
            />
          </label>
          <div className="event-type-filter">
            <label>
              이벤트 유형
              <select
                value={customEventType ? "custom" : draft.event_type}
                onChange={(e) => {
                  setCustomEventType(e.target.value === "custom");
                  change("event_type", e.target.value === "custom" ? "" : e.target.value);
                }}
              >
                <option value="">전체</option>
                {Object.entries(eventTypes).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                <option value="custom">직접 입력…</option>
              </select>
            </label>
            {customEventType && <>
              <label>
              이벤트 유형 직접 입력
              <input value={draft.event_type} onChange={(e) => change("event_type", e.target.value)}
                placeholder="cowrie.login.failed" maxLength={128} aria-describedby="event-type-help" />
              </label>
              <span id="event-type-help" className="muted">전체 유형 이름과 정확히 일치하는 이벤트를 조회합니다.</span>
            </>}
          </div>
          <label>
            판정 결과
            <select value={draft.detection_result} onChange={(e) => change("detection_result", e.target.value)}>
              <option value="">전체</option>
              {Object.entries(resultLabels).map(([value,label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <label>
            테스트 이벤트
            <select
              value={draft.is_test}
              onChange={(e) => change("is_test", e.target.value)}
            >
              <option value="">전체</option>
              <option value="false">테스트 제외</option>
              <option value="true">테스트만</option>
            </select>
          </label>
          <label>
            수집 시작 (포함)
            <input
              type="datetime-local"
              value={draft.since}
              onChange={(e) => change("since", e.target.value)}
              aria-invalid={!!filterError}
              aria-describedby="filter-time-help"
            />
          </label>
          <label>
            수집 종료 (제외)
            <input
              type="datetime-local"
              value={draft.until}
              onChange={(e) => change("until", e.target.value)}
              aria-invalid={!!filterError}
              aria-describedby="filter-time-help"
            />
          </label>
        </div>
        <div className="filter-bottom">
          <p
            id="filter-time-help"
            className={filterError ? "error" : "muted"}
            role={filterError ? "alert" : undefined}
          >
            {filterError ||
              `시간 필터: 기기 현지 시각 (${Intl.DateTimeFormat().resolvedOptions().timeZone}) · 목록: UTC`}
          </p>
          <div className="filter-actions">
            <button className="quiet" type="button" onClick={reset}>
              초기화
            </button>
            <button className="primary" type="submit">
              필터 적용
            </button>
          </div>
        </div>
      </form>
      <p className="muted">판정 결과는 첫 페이지 조회 시점 기준입니다. 근거 없음은 안전함을 뜻하지 않으며 이후 판정에서 근거로 포함될 수 있습니다. 근거 포함은 규칙 판정의 증거 참조를 뜻하며, 신고 초안 생성과는 별개입니다.</p>
      <div className="event-workbench">
        <div className="event-results" aria-busy={loading}>
          {state.kind === "loading" && (
            <div className="result-message" role="status">
              이벤트를 불러오는 중…
            </div>
          )}
          {state.kind === "error" && (
            <div className="result-message">
              <p className="error" role="alert">
                {state.message}
              </p>
              <button onClick={() => setRevision((n) => n + 1)}>
                다시 시도
              </button>
            </div>
          )}
          {state.kind === "ready" && (
            <>
              <div className="results-meta">
                <span>
                  이 페이지 <strong>{state.items.length}</strong>건
                </span>
                <span>수집 순번 내림차순</span>
              </div>
              {state.items.length === 0 ? (
                <div className="result-message">
                  <h2>조건에 맞는 이벤트가 없습니다.</h2>
                  <p className="muted">
                    필터를 조정하거나 수집 후 새로고침하세요.
                  </p>
                </div>
              ) : (
                <table className="event-table">
                  <caption className="sr-only">수집 이벤트 목록</caption>
                  <thead>
                    <tr>
                      <th>수집 시각 (UTC)</th>
                      <th>출발지 IP</th>
                      <th>서비스 / 유형</th>
                      <th>판정 결과</th>
                      <th>품질</th>
                      <th>
                        <span className="sr-only">상세</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {state.items.map((event) => (
                      <Fragment key={event.event_id}>
                      <tr
                        className={
                          selected === event.event_id ? "selected" : undefined
                        }
                      >
                        <td
                          data-label="수집 시각 (UTC)"
                          className="mono timestamp"
                        >
                          <time dateTime={event.ingested_at}>
                            {utcTime(event.ingested_at, false)}
                          </time>
                        </td>
                        <td data-label="출발지 IP" className="mono">
                          {event.source_ip ? (
                            <a href={ipHref(event.source_ip)}>
                              {event.source_ip}
                            </a>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td data-label="서비스 / 유형">
                          <span className="service-name">{event.service}</span>
                          <span className="event-type">{event.event_type}</span>
                        </td>
                        <td data-label="판정 결과">{resultLabels[event.detection_result]}</td>
                        <td data-label="품질">
                          <span className="quality">
                            {event.is_test && (
                              <span className="tag">테스트</span>
                            )}
                            {(event.quality_flags?.length ?? 0) > 0 && (
                              <span className="tag warning">
                                품질 주의 {event.quality_flags!.length}
                              </span>
                            )}
                            {!event.is_test && !event.quality_flags?.length && (
                              <span className="muted">—</span>
                            )}
                          </span>
                        </td>
                        <td className="row-action">
                          <button
                            className="quiet"
                            aria-expanded={selected === event.event_id}
                            aria-controls={selected === event.event_id ? "selected-event-detail" : undefined}
                            onClick={(e) => {
                              e.currentTarget.focus();
                              setSelected((current) => current === event.event_id ? null : event.event_id);
                            }}
                          >
                            {selected === event.event_id ? "상세 접기" : "상세 보기"}
                          </button>
                        </td>
                      </tr>
                      {selected === event.event_id && (
                        <tr className="event-detail-row">
                          <td colSpan={6} id="selected-event-detail">
                            <EventDetail client={client} id={event.event_id} />
                          </td>
                        </tr>
                      )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              )}
              <div className="pagination">
                <span>
                  {page.history.length + 1} 페이지
                  {page.cursor && !page.history.length
                    ? " · 이전 페이지는 브라우저 뒤로가기로 이동"
                    : ""}
                </span>
                <div>
                  <button
                    disabled={loading || !!refreshError || page.history.length === 0}
                    onClick={() =>
                      movePage(
                        page.history.at(-1) ?? "",
                        page.history.slice(0, -1),
                      )
                    }
                  >
                    이전
                  </button>
                  <button
                    disabled={loading || !!refreshError || !state.next}
                    onClick={() =>
                      movePage(state.next, [...page.history, page.cursor])
                    }
                  >
                    다음
                  </button>
                </div>
              </div>
            </>
          )}
        </div>

      </div>
    </section>
  );
}
