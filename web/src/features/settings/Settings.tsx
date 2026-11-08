import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ApiClient,
  ApiError,
  NetworkError,
  isCancelled,
} from "../../api/client";
import type { components } from "../../api/schema";
import { useNavigationLock } from "../shared/useNavigationLock";

type Snapshot = components["schemas"]["SettingsOutputBody"];
type Patch = components["schemas"]["SettingsPatchInputBody"];
type Draft = {
  raw_days: string;
  raw_bytes: string;
  event_days: string;
  history_days: string;
  job_days: string;
  reply_to: string;
  timezone: string;
  period_days: string;
  ssh_repeat_threshold: string;
  web_repeat_threshold: string;
  web_distinct_path_threshold: string;
};
type Mode = "idle" | "submitting" | "unknown" | "conflict" | "review";
const draftOf = (s: Snapshot): Draft => ({
  raw_days: String(s.retention.raw_days),
  raw_bytes: s.retention.raw_bytes,
  event_days: String(s.retention.event_days),
  history_days: String(s.retention.history_days),
  job_days: String(s.retention.job_days),
  reply_to: s.reply_to,
  timezone: s.timezone,
  period_days: String(s.period_days),
  ssh_repeat_threshold: String(s.rules.ssh_repeat_threshold),
  web_repeat_threshold: String(s.rules.web_repeat_threshold),
  web_distinct_path_threshold: String(s.rules.web_distinct_path_threshold),
});
function valid(d: Draft) {
  const integer = (value: string, min: number, max: number) =>
    /^\d+$/.test(value) && Number(value) >= min && Number(value) <= max;
  if (
    d.reply_to.length > 254 ||
    (d.reply_to !== "" && !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(d.reply_to))
  )
    return false;
  if (!d.timezone || d.timezone.length > 100 || d.timezone === "Local")
    return false;
  try {
    new Intl.DateTimeFormat("en", { timeZone: d.timezone });
  } catch {
    return false;
  }
  return (
    integer(d.raw_days, 1, 365) &&
    /^[1-9][0-9]*$/.test(d.raw_bytes) && integer(d.raw_bytes, 33554432, 1099511627776) &&
    integer(d.event_days, 1, 3650) && integer(d.history_days, 1, 3650) && integer(d.job_days, 1, 365) &&
    integer(d.period_days, 1, 31) &&
    integer(d.ssh_repeat_threshold, 2, 10000) &&
    integer(d.web_repeat_threshold, 2, 10000) &&
    integer(d.web_distinct_path_threshold, 1, 5) &&
    Number(d.web_repeat_threshold) >= Number(d.web_distinct_path_threshold)
  );
}
function Schedule({
  title,
  value,
}: {
  title: string;
  value: Snapshot["active_schedule"] | null;
}) {
  return (
    <section className="inspector" aria-label={title}>
      <h2>{title}</h2>
      {value ? (
        <dl className="detail-fields">
          <div>
            <dt>스케줄 버전</dt>
            <dd className="mono">{value.version}</dd>
          </div>
          <div>
            <dt>시간대 / 주기</dt>
            <dd>
              {value.timezone} / {value.period_days}일
            </dd>
          </div>
          <div>
            <dt>적용 시각</dt>
            <dd>
              {value.effective_from === "-infinity"
                ? "초기 적용"
                : value.effective_from}
            </dd>
          </div>
        </dl>
      ) : (
        <p className="muted">예약된 변경이 없습니다.</p>
      )}
    </section>
  );
}
export function Settings({ client }: { client: ApiClient }) {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [draft, setDraft] = useState<Draft>();
  const [mode, setMode] = useState<Mode>("idle");
  useNavigationLock(mode === "submitting" || mode === "unknown");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const request = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const frozen = useRef<{ body: Patch; key: string } | null>(null);
  const modeRef = useRef<Mode>("idle");
  function changeMode(value: Mode) {
    modeRef.current = value;
    setMode(value);
  }
  async function load(review = false) {
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    const ticket = ++request.current;
    setLoading(true);
    setError("");
    setSnapshot(undefined);
    setDraft(undefined);
    try {
      const result = await client.settings(abort.signal);
      if (ticket !== request.current || abort.signal.aborted) return;
      setSnapshot(result);
      setDraft(draftOf(result));
      frozen.current = null;
      changeMode(review ? "review" : "idle");
    } catch (err) {
      if (
        ticket === request.current &&
        !abort.signal.aborted &&
        !isCancelled(err)
      )
        setError("설정을 불러오지 못했습니다. 다시 시도하세요.");
    } finally {
      if (ticket === request.current && !abort.signal.aborted)
        setLoading(false);
    }
  }
  useEffect(() => {
    frozen.current = null;
    changeMode("idle");
    setNotice("");
    void load();
    return () => {
      request.current++;
      controller.current?.abort();
    };
    // Each client owns a session; cleanup invalidates all reads and writes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);
  async function mutate() {
    const operation = frozen.current;
    if (!operation || modeRef.current === "submitting") return;
    changeMode("submitting");
    setError("");
    setNotice("");
    const abort = new AbortController();
    controller.current?.abort();
    controller.current = abort;
    const ticket = ++request.current;
    try {
      await client.patchSettings(operation.body, operation.key, abort.signal);
      if (ticket !== request.current || abort.signal.aborted) return;
      frozen.current = null;
      changeMode("idle");
      setNotice("설정을 저장했습니다.");
      await load();
    } catch (err) {
      if (
        ticket !== request.current ||
        abort.signal.aborted ||
        isCancelled(err)
      )
        return;
      if (err instanceof ApiError && err.status === 409) {
        changeMode("conflict");
        setError(
          "설정 버전 충돌이 발생했습니다. 최신 설정을 불러온 뒤 검토하세요.",
        );
      } else if (
        err instanceof NetworkError ||
        (err instanceof ApiError && err.status >= 500)
      ) {
        changeMode("unknown");
        setError(
          "저장 결과를 확인할 수 없습니다. 동일 요청을 재시도하여 결과를 확인하세요.",
        );
      } else {
        frozen.current = null;
        changeMode("idle");
        setError("설정을 저장하지 못했습니다. 입력 내용을 확인하세요.");
      }
    }
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    if (modeRef.current !== "idle" || !draft || !snapshot) return;
    if (!valid(draft)) {
      setError(
        "입력값을 확인하세요. 유효한 이메일·시간대와 허용 범위의 정수가 필요하며 웹 반복 임계값은 경로 수 이상이어야 합니다.",
      );
      return;
    }
    frozen.current = {
      key: crypto.randomUUID(),
      body: {
        retention: { raw_days: Number(draft.raw_days), raw_bytes: draft.raw_bytes, event_days: Number(draft.event_days), history_days: Number(draft.history_days), job_days: Number(draft.job_days) },
        expected_version: snapshot.version,
        reply_to: draft.reply_to,
        timezone: draft.timezone,
        period_days: Number(draft.period_days),
        rules: {
          ssh_repeat_threshold: Number(draft.ssh_repeat_threshold),
          web_repeat_threshold: Number(draft.web_repeat_threshold),
          web_distinct_path_threshold: Number(
            draft.web_distinct_path_threshold,
          ),
        },
      },
    };
    void mutate();
  }
  const fields: [
    keyof Draft,
    string,
    number?,
    number?,
  ][] = [
    ["raw_days", "원본 보관 (일)", 1, 365],
    ["raw_bytes", "원본 한도 (bytes/센서)", 33554432, 1099511627776],
    ["event_days", "이벤트·판정 보관 (일)", 1, 3650],
    ["history_days", "종료 이력 보관 (일)", 1, 3650],
    ["job_days", "완료 작업 보관 (일)", 1, 365],
    ["reply_to", "Reply-To"],
    ["timezone", "시간대"],
    ["period_days", "초안 집계 주기 (일)", 1, 31],
    ["ssh_repeat_threshold", "SSH 반복 임계값", 2, 10000],
    ["web_repeat_threshold", "웹 반복 임계값", 2, 10000],
    ["web_distinct_path_threshold", "웹 경로 수 임계값", 1, 5],
  ];
  return (
    <section className="settings-page" aria-labelledby="settings-heading">
      <div className="section-heading">
        <div><p className="eyebrow">운영 정책</p><h1 id="settings-heading">설정</h1>
        <p className="muted">보관 정책·초안 집계 일정·탐지 임계값</p></div>
      </div>
      {loading && <p role="status">설정을 불러오는 중…</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {!loading && !snapshot && (
        <button
          onClick={() =>
            void load(
              modeRef.current === "conflict" || modeRef.current === "review",
            )
          }
        >
          다시 시도
        </button>
      )}
      {!loading && snapshot && draft && (
        <>
          <dl className="detail-fields">
            <div>
              <dt>설정 버전</dt>
              <dd className="mono">{snapshot.version}</dd>
            </div>
            <div>
              <dt>규칙 적용 시작 수집 순번</dt>
              <dd className="mono">{snapshot.rule_effective_from_seq}</dd>
            </div>
          </dl>
          <p className="notice">
            규칙은 적용 시작 순번부터 사용됩니다. 예약된 초안 집계 일정은 적용 시각
            이후 활성화됩니다.
          </p>
          <form className="settings-form" noValidate onSubmit={submit}>
            {[
              { title: '보관 기간과 용량', keys: ['raw_days', 'raw_bytes', 'event_days', 'history_days', 'job_days'] },
              { title: '회신 주소와 초안 집계 일정', keys: ['reply_to', 'timezone', 'period_days'] },
              { title: '판정 기준', keys: ['ssh_repeat_threshold', 'web_repeat_threshold', 'web_distinct_path_threshold'] },
            ].map(group => <fieldset className="settings-group" key={group.title}>
              <legend>{group.title}</legend>
              {group.title === '보관 기간과 용량' && <>
                <p className="notice">보관 변경은 다음 정리 실행부터 적용합니다. 기간을 줄이면 기존 자료도 삭제 대상이 됩니다. 미처리·미복사 증거와 진행 중·미해결 결과 불명 신고는 보호합니다. 결과 불명 종료는 기존 최소 180일 보존 약속을 유지하며 이미 시작된 정리는 완료합니다.</p>
                <p className="settings-help">원본 정리는 호스트 타이머가 필요하고 센서당 archive 64개 제한을 유지합니다. 설정값은 용량 보장이 아닙니다. 디스크 80% 경고·90% 제한은 유지됩니다. <a href="/overview">현재 운영 상태</a></p>
              </>}
              {group.title === '회신 주소와 초안 집계 일정' && <div className="settings-schedules">
                <Schedule title="현재 초안 집계 일정" value={snapshot.active_schedule} />
                <Schedule title="예약된 초안 집계 일정" value={snapshot.pending_schedule} />
              </div>}
              <div className="settings-fields">
              {fields.filter(([key]) => group.keys.includes(key)).map(([key, label, min, max]) => (
                <label key={key}>
                  {label}
                  <input
                    aria-label={label}
                    name={key}
                    autoComplete="off"
                    spellCheck={false}
                    value={draft[key]}
                    disabled={mode !== "idle"}
                    type={min === undefined ? "text" : "number"}
                    min={min}
                    max={max}
                    step={min === undefined ? undefined : 1}
                    maxLength={
                      key === "reply_to"
                        ? 254
                        : key === "timezone"
                          ? 100
                          : undefined
                    }
                    onChange={(e) =>
                      setDraft({ ...draft, [key]: e.target.value })
                    }
                  />
                  {min !== undefined && (
                    <span>
                      {min}–{max}
                    </span>
                  )}
                </label>
              ))}
            </div></fieldset>)}
            <div className="filter-bottom">
              <p className="muted">
                Reply-To는 비워둘 수 있습니다. 시간대 예: Asia/Tokyo, UTC
              </p>
              <button
                className="primary"
                disabled={mode !== "idle"}
                type="submit"
              >
                {mode === "submitting" ? "저장 중…" : "설정 저장"}
              </button>
            </div>
          </form>
          {mode === "unknown" && (
            <button onClick={() => void mutate()}>동일 요청 재시도</button>
          )}
          {mode === "conflict" && (
            <button onClick={() => void load(true)}>최신 설정 불러오기</button>
          )}
          {mode === "review" && (
            <>
              <p className="notice">
                최신 설정을 검토한 뒤 변경을 다시 입력하세요.
              </p>
              <button onClick={() => changeMode("idle")}>
                최신 설정 검토 완료
              </button>
            </>
          )}
        </>
      )}
    </section>
  );
}
