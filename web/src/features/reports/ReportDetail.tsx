import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ApiClient,
  ApiError,
  errorMessage,
  isCancelled,
  type Schema,
} from "../../api/client";
import { useNavigationLock } from "../shared/useNavigationLock";
import { useRead, type ReadState } from "../shared/useRead";
import {
  contactCandidates,
  Field,
  ipHref,
  Pages,
  TextData,
} from "../shared/ui";
import { utcTime } from "../events/format";

type Operation = {
  action: "select" | "reject" | "refresh";
  body: Schema["SelectContactInputBody"] | Schema["ReportExpectation"];
  key: string;
};
export function ReportDetail({
  client,
  id,
}: {
  client: ApiClient;
  id: string;
}) {
  return <Review key={id} client={client} id={id} />;
}
function Review({ client, id }: { client: ApiClient; id: string }) {
  const [reload, setReload] = useState(0),
    [selected, setSelected] = useState(""),
    [recipient, setRecipient] = useState("");
  const [mutation, setMutation] = useState<
    "idle" | "busy" | "ambiguous" | "stale"
  >("idle");
  const [feedback, setFeedback] = useState(""),
    [success, setSuccess] = useState("");
  useNavigationLock(
    mutation === "busy" || mutation === "ambiguous",
  );
  const pending = useRef<Operation | null>(null),
    active = useRef(true),
    abort = useRef<AbortController | null>(null);
  const [data, setData] = useState<ReadState<Schema["ReportDetailOutputBody"]>>({
    kind: "loading",
  });
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let current = true;
    setLoading(true);
    setLoadError("");
    client.report(id, controller.signal)
      .then((report) => {
        if (current) setData({ kind: "ready", data: report });
      })
      .catch((error: unknown) => {
        if (!current || isCancelled(error)) return;
        const message = errorMessage(error, "신고를 불러오지 못했습니다. 다시 시도하세요.");
        setLoadError(message);
        setData(previous => previous.kind === "ready" ? previous : { kind: "error", message });
      })
      .finally(() => { if (current) setLoading(false); });
    return () => {
      current = false;
      controller.abort();
    };
  }, [client, id, reload]);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      abort.current?.abort();
    };
  }, [client, id]);
  function reset() {
    setLoading(true);
    setLoadError("");
    setSelected("");
    setRecipient("");
    setFeedback("");
    setSuccess("");
    pending.current = null;
    setMutation("idle");
    setReload((n) => n + 1);
  }
  async function execute(operation: Operation) {
    if (mutation === "busy") return;
    pending.current = operation;
    setMutation("busy");
    setFeedback("");
    setSuccess("");
    abort.current = new AbortController();
    try {
      if (operation.action === "select")
        await client.selectContact(
          id,
          operation.body as Schema["SelectContactInputBody"],
          operation.key,
          abort.current.signal,
        );
      else if (operation.action === "reject")
        await client.rejectReport(
          id,
          operation.body,
          operation.key,
          abort.current.signal,
        );
      else
        await client.refreshContact(
          id,
          operation.body,
          operation.key,
          abort.current.signal,
        );
      if (!active.current) return;
      reset();
      setSuccess(
        operation.action === "refresh"
          ? "등록기관 연락처 재조회 요청이 접수되었습니다. 아직 완료된 것은 아닙니다. ‘신고 상태 새로고침’으로 결과를 확인하세요."
          : operation.action === "select"
            ? `${(operation.body as Schema["SelectContactInputBody"]).recipient}을 수신자로 저장했습니다. 새 개정의 본문과 연락처를 다시 검토하세요. 메일은 발송하지 않았습니다.`
            : "초안을 제외했습니다.",
      );
    } catch (error) {
      if (!active.current || isCancelled(error)) return;
      if (error instanceof ApiError && error.status === 409) {
        setMutation("stale");
        setFeedback(
          "다른 변경이 있거나 요청이 충돌했습니다. 최신 정보를 다시 불러온 후 검토하세요.",
        );
      } else if (!(error instanceof ApiError) || error.status >= 500) {
        setMutation("ambiguous");
        setFeedback(
          "처리 결과를 확인할 수 없습니다. 동일 요청을 재시도하여 결과를 확인하세요.",
        );
      } else {
        pending.current = null;
        setMutation("idle");
        setFeedback("변경하지 못했습니다. 입력과 현재 상태를 확인하세요.");
      }
    }
  }
  function start(action: Operation["action"]) {
    if (
      data.kind !== "ready" ||
      loading ||
      loadError ||
      mutation !== "idle" ||
      selected
    )
      return;
    const body: Schema["SelectContactInputBody"] | Schema["ReportExpectation"] =
      {
        expected_version: data.data.version,
        current_revision_id: data.data.current_revision_id,
        ...(action === "select" ? { recipient } : {}),
      };
    void execute({ action, body, key: crypto.randomUUID() });
  }
  const locked =
    (data.kind === "ready" && !["held", "needs_review"].includes(data.data.state)) ||
    mutation !== "idle" || loading || !!loadError;
  const result = (
    <div className="review-feedback">
      {success && <p role="status" className="notice">{success}</p>}
      {feedback && <p role="alert" className="error">{feedback}</p>}
      {mutation === "ambiguous" && (
        <button onClick={() => pending.current && void execute(pending.current)}>
          동일 요청 재시도
        </button>
      )}
      {data.kind === "ready" && loading && <p role="status">최신 신고 상태를 불러오는 중…</p>}
      {data.kind === "ready" && loadError && (
        <p role="alert" className="error">
          {loadError} 현재 표시된 내용은 이전 정보입니다. 신고 상태를 새로고침한 후 처리하세요.
        </p>
      )}
      {(mutation === "stale" || loadError) && data.kind === "ready" && (
        <button disabled={loading} onClick={reset}>신고 상태 다시 불러오기</button>
      )}
    </div>
  );
  return (
    <section className="review-page">
      <div className="section-heading">
        <div>
          <p className="eyebrow">증거와 연락처 확인</p><h1>신고 검토</h1>
          <p className="muted">
            증거와 연락처를 확인한 후 현재 개정을 처리합니다.
          </p>
        </div>
        <button
          disabled={
            mutation === "busy" ||
            mutation === "ambiguous" ||
            loading
          }
          onClick={reset}
        >
          {loading && data.kind === "ready" ? "신고 상태 불러오는 중…" : "신고 상태 새로고침"}
        </button>
      </div>
      {data.kind === "loading" && <p role="status">신고를 불러오는 중…</p>}
      {data.kind === "error" && (
        <p role="alert" className="error">
          {data.message}
        </p>
      )}
      {data.kind === "ready" && (
        <>
          {data.data.state === "archived" && (
            <p role="status" className="notice">
              과거 처리 또는 복원 기록입니다. 이미 전달됐을 가능성이 있으므로 외부 신고 전에 별도 기록과 대조하세요. 이 기록은 읽기 전용입니다.
            </p>
          )}
          <dl className="detail-fields review-summary">
            <Field name="출발지 IP">
              <a href={ipHref(data.data.source_ip)}>{data.data.source_ip}</a>
            </Field>
            <Field name="현재 상태">{data.data.state}</Field>
            <Field name="현재 버전">{data.data.version}</Field>
          </dl>
          {selected ? (
            <>
              <div className="section-heading">
                <p className="notice">이전 개정 · 읽기 전용</p>
                <button onClick={() => setSelected("")}>
                  현재 개정으로 돌아가기
                </button>
              </div>
              <Historical
                key={selected}
                client={client}
                id={id}
                revisionID={selected}
              />
            </>
          ) : (
            <>
              <RevisionContent client={client} value={data.data.revision}>
              <section className="review-section review-controls" aria-label="현재 개정 작업">
                <h2>수신자와 신고 처리</h2>
                {result}
                <p className="muted" id="contact-save-help">후보를 수신자로 저장하면 새 개정이 만들어집니다. 초안을 검토한 후 외부 도구에서 직접 사용하세요. Cheesetrap은 메일을 발송하지 않습니다.</p>
                <div className="inline-actions">
                  <label>
                    연락처 후보
                    <select
                      disabled={
                        locked ||
                        data.data.state === "rejected"
                      }
                      value={recipient}
                      aria-describedby="contact-save-help"
                      onChange={(e) => setRecipient(e.target.value)}
                    >
                      <option value="">후보를 선택하세요</option>
                      {contactCandidates(
                        data.data.revision.registry,
                        data.data.source_ip,
                      ).map((email) => (
                        <option key={email} value={email}>
                          {email}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    disabled={
                      !recipient ||
                      locked ||
                      data.data.state === "rejected"
                    }
                    onClick={() => start("select")}
                  >
                    수신자로 저장
                  </button>
                  <button
                    disabled={
                      locked ||
                      data.data.state === "rejected"
                    }
                    onClick={() => start("reject")}
                  >
                    초안 제외
                  </button>
                </div>
                {contactCandidates(
                  data.data.revision.registry,
                  data.data.source_ip,
                ).length === 0 && (
                  <p className="muted">선택할 연락처 후보가 없습니다.</p>
                )}
                {mutation === "busy" && (
                  <p role="status">변경을 처리하는 중…</p>
                )}
                <details className="review-disclosure contact-lookup">
                  <summary>연락처 후보 다시 찾기</summary>
                  <p className="muted" id="contact-refresh-help">등록기관에서 연락처 후보를 다시 조회합니다. 완료되면 새 개정이 만들어질 수 있으므로 수신자를 다시 확인하세요. ‘신고 상태 새로고침’은 저장된 결과만 읽습니다.</p>
                  <p>조회 상태: {refreshStatus(data.data.latest_refresh?.status)}</p>
                  <button disabled={locked || data.data.state === "rejected" || data.data.latest_refresh?.status === "queued"} aria-describedby="contact-refresh-help" onClick={() => start("refresh")}>등록기관 연락처 다시 조회</button>
                </details>
              </section>
              </RevisionContent>
            </>
          )}
          <details className="review-disclosure">
            <summary>개정 이력과 신고 정보</summary>
            <dl className="detail-fields review-summary">
              <Field name="현재 개정">{data.data.current_revision_id}</Field>
              <Field name="생성 시각 (UTC)">{utcTime(data.data.created_at)}</Field>
            </dl>
            <RevisionHistory client={client} id={id} reload={reload} onSelect={setSelected} disabled={locked} />
          </details>
        </>
      )}
    </section>
  );
}
function refreshStatus(status?: string) {
  const labels: Record<string, string> = {
    queued: "조회 대기 중",
    completed: "재조회 처리 완료",
    superseded: "다른 변경으로 대체됨",
  };
  return status ? labels[status] || status : "요청 없음";
}
function Historical({
  client,
  id,
  revisionID,
}: {
  client: ApiClient;
  id: string;
  revisionID: string;
}) {
  const [retry, setRetry] = useState(0);
  const state = useRead(
    (signal) => client.revision(id, revisionID, signal),
    [client, id, revisionID, retry],
  );
  return state.kind === "ready" ? (
    <RevisionContent client={client} value={state.data} />
  ) : state.kind === "loading" ? (
    <p role="status">개정을 불러오는 중…</p>
  ) : (
    <div>
      <p role="alert">{state.message}</p>
      <button onClick={() => setRetry((n) => n + 1)}>개정 다시 시도</button>
    </div>
  );
}
function RevisionHistory({
  client,
  id,
  reload,
  onSelect,
  disabled,
}: {
  client: ApiClient;
  id: string;
  reload: number;
  onSelect: (id: string) => void;
  disabled: boolean;
}) {
  const [cursor, setCursor] = useState(""),
    [history, setHistory] = useState<string[]>([]),
    [retry, setRetry] = useState(0);
  const state = useRead(
    (signal) => client.revisions(id, cursor, signal),
    [client, id, cursor, reload, retry],
  );
  return (
    <section className="review-section">
      <h2>개정 이력</h2>
      {state.kind === "loading" ? (
        <p role="status">이력을 불러오는 중…</p>
      ) : state.kind === "error" ? (
        <>
          <p role="alert">{state.message}</p>
          <button onClick={() => setRetry((n) => n + 1)}>이력 다시 시도</button>
        </>
      ) : (
        <>
          <div className="revision-list">
            {state.data.items?.length ? (
              state.data.items.map((item) => (
                <button
                  key={item.revision_id}
                  disabled={disabled}
                  onClick={() => onSelect(item.revision_id)}
                >
                  개정 {item.version} 보기
                </button>
              ))
            ) : (
              <p className="muted">개정 이력이 없습니다.</p>
            )}
          </div>
          <Pages
            next={state.data.next_cursor}
            previous={history.length > 0}
            onNext={() => {
              setHistory([...history, cursor]);
              setCursor(state.data.next_cursor);
            }}
            onPrevious={() => {
              setCursor(history.at(-1) || "");
              setHistory(history.slice(0, -1));
            }}
          />
        </>
      )}
    </section>
  );
}
function RevisionContent({
  client,
  value: r,
  children,
}: {
  client: ApiClient;
  value: Schema["RevisionView"];
  children?: ReactNode;
}) {
  return (
    <div className={`revision-content${children ? " review-workbench" : ""}`}>
      <section className="review-section review-draft">
        <h2>{r.subject}</h2>
        <dl className="detail-fields review-summary">
          <Field name="수신자">{r.recipient || "미선택"}</Field>
          <Field name="회신 주소">{r.reply_to || "미설정"}</Field>
          <Field name="증거 수">{r.evidence_count}</Field>
          <Field name="규칙 수">{r.rule_count}</Field>
        </dl>
        <h3>보류 사유</h3>
        {r.hold_reasons?.length ? (
          <ul className="flag-list">
            {r.hold_reasons.map((reason, i) => (
              <li key={i}>{reason}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">보류 사유 없음</p>
        )}
        {r.delayed_collection && (
          <p className="notice">
            지연 수집 포함 · 관측 시각과 수집 시각을 구분하여 검토하세요.
          </p>
        )}
        {r.body_edited && <p className="notice">수정된 본문</p>}
        <h3>신고 본문</h3>
        <pre className="evidence report-body" tabIndex={0} aria-label="신고 본문">{r.body}</pre>
      </section>
      {children}
      <div className="review-reference">
        <details className="review-disclosure">
          <summary>증거 · {r.evidence_count}건</summary>
          <Evidence key={r.revision_id} client={client} id={r.report_id} revisionID={r.revision_id} />
        </details>
        <details className="review-disclosure">
          <summary>탐지 규칙 · {r.rule_count}건</summary>
          <Rules key={r.revision_id} client={client} id={r.report_id} revisionID={r.revision_id} />
        </details>
        <details className="review-disclosure">
          <summary>등록기관 조회 원문{r.registry_truncated ? " · 잘림 있음" : ""}</summary>
          {r.registry_truncated && <p className="notice">등록기관 정보가 잘렸습니다.</p>}
          <TextData value={r.registry} />
        </details>
        <details className="review-disclosure">
          <summary>개정 상세 정보</summary>
          <dl className="detail-fields review-summary">
            <Field name="개정 버전">{r.version}</Field>
            <Field name="관측 구간 (UTC)">{r.observed_start} → {r.observed_end}</Field>
            <Field name="보고 구간 (UTC)">{r.window_start} → {r.window_end}</Field>
            <Field name="내용 해시">{r.content_digest}</Field>
          </dl>
        </details>
      </div>
    </div>
  );
}
function Evidence({
  client,
  id,
  revisionID,
}: {
  client: ApiClient;
  id: string;
  revisionID: string;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [cursor, setCursor] = useState(""),
    [history, setHistory] = useState<string[]>([]),
    [retry, setRetry] = useState(0);
  const state = useRead(
    (signal) => client.evidence(id, revisionID, cursor, signal),
    [client, id, revisionID, cursor, retry],
  );
  return (
    <section className="review-section">
      <h2>증거</h2>
      {state.kind === "loading" ? (
        <p role="status">증거를 불러오는 중…</p>
      ) : state.kind === "error" ? (
        <>
          <p role="alert">{state.message}</p>
          <button onClick={() => setRetry((n) => n + 1)}>증거 다시 시도</button>
        </>
      ) : (
        <>
          <p className="muted">
            전체 {state.data.total}건 · 이 페이지{" "}
            {state.data.items?.length ?? 0}건
          </p>
          {state.data.items?.length ? (
            state.data.items.map((e) => (
              <article className="evidence-entry" key={e.event_id}>
                <div className="evidence-summary">
                  <div>
                    <h3>{e.service} / {e.event_type}</h3>
                    <p className="muted">{utcTime(e.observed_at)} (UTC) · 이벤트 #<span className="mono">{e.ingestion_seq}</span></p>
                    <p>품질: {e.quality_flags?.join(", ") || "표시 없음"}{e.is_test ? " · 테스트" : ""}</p>
                    {e.entry_truncated && <p className="notice">증거 항목이 잘렸습니다.</p>}
                  </div>
                  <button className="quiet" aria-expanded={selected === e.event_id} aria-controls={`evidence-${e.event_id}`} aria-label={`이벤트 #${e.ingestion_seq} 증거 ${selected === e.event_id ? "접기" : "보기"}`} onClick={() => setSelected(selected === e.event_id ? null : e.event_id)}>{selected === e.event_id ? "접기" : "증거 보기"}</button>
                </div>
                {selected === e.event_id && <div id={`evidence-${e.event_id}`} role="region" aria-label={`이벤트 #${e.ingestion_seq} 증거 상세`}>
                  <dl className="detail-fields review-summary">
                    <Field name="관측 시각 (UTC)">{utcTime(e.observed_at)}</Field>
                    <Field name="수집 시각 (UTC)">{utcTime(e.ingested_at)}</Field>
                  </dl>
                  <TextData value={e} />
                </div>}
              </article>
            ))
          ) : (
            <p className="muted">증거가 없습니다.</p>
          )}
          <Pages
            next={state.data.next_cursor}
            previous={history.length > 0}
            onNext={() => {
              setSelected(null);
              setHistory([...history, cursor]);
              setCursor(state.data.next_cursor);
            }}
            onPrevious={() => {
              setSelected(null);
              setCursor(history.at(-1) || "");
              setHistory(history.slice(0, -1));
            }}
          />
        </>
      )}
    </section>
  );
}
function Rules({
  client,
  id,
  revisionID,
}: {
  client: ApiClient;
  id: string;
  revisionID: string;
}) {
  const [cursor, setCursor] = useState(""),
    [history, setHistory] = useState<string[]>([]),
    [retry, setRetry] = useState(0);
  const state = useRead(
    (signal) => client.rules(id, revisionID, cursor, signal),
    [client, id, revisionID, cursor, retry],
  );
  return (
    <section className="review-section">
      <h2>탐지 규칙</h2>
      {state.kind === "loading" ? (
        <p role="status">규칙을 불러오는 중…</p>
      ) : state.kind === "error" ? (
        <>
          <p role="alert">{state.message}</p>
          <button onClick={() => setRetry((n) => n + 1)}>규칙 다시 시도</button>
        </>
      ) : (
        <>
          <p className="muted">전체 {state.data.total}건</p>
          {state.data.items?.length ? (
            state.data.items.map((r) => (
              <article className="evidence-entry" key={r.detection_id}>
                <h3>
                  {r.rule_id} · {r.rule_version}
                </h3>
                <p>
                  첨부 {r.attached_count} · 문맥 {r.context_count} · 증거{" "}
                  {r.evidence_eligible ? "적격" : "부적격"}
                </p>
                {r.entry_truncated && (
                  <p className="notice">규칙 항목이 잘렸습니다.</p>
                )}
                <TextData value={r} />
              </article>
            ))
          ) : (
            <p className="muted">규칙이 없습니다.</p>
          )}
          <Pages
            next={state.data.next_cursor}
            previous={history.length > 0}
            onNext={() => {
              setHistory([...history, cursor]);
              setCursor(state.data.next_cursor);
            }}
            onPrevious={() => {
              setCursor(history.at(-1) || "");
              setHistory(history.slice(0, -1));
            }}
          />
        </>
      )}
    </section>
  );
}
