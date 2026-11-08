import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiClient } from "../../api/client";
import { deferred, fetcher, json } from "../../test/fixtures";
import { Settings } from "./Settings";
import { navigationLocked } from "../shared/useNavigationLock";

const sample = {
  delivery_limits: { daily: 100, recipient_daily: 20 },
  retention: { raw_days: 7, raw_bytes: "1073741824", event_days: 30, history_days: 180, job_days: 7 },
  version: "9007199254740993",
  reply_to: "ops@example.org",
  timezone: "Asia/Tokyo",
  period_days: 7,
  schedule_version: "4",
  rule_effective_from_seq: "9007199254740995",
  rules: {
    ssh_repeat_threshold: 10,
    web_repeat_threshold: 20,
    web_distinct_path_threshold: 5,
  },
  active_schedule: {
    version: "3",
    timezone: "UTC",
    period_days: 7,
    effective_from: "-infinity",
  },
  pending_schedule: {
    version: "4",
    timezone: "Asia/Tokyo",
    period_days: 7,
    effective_from: "2026-11-01T00:00:00Z",
  },
};
const save = () =>
  fireEvent.click(screen.getByRole("button", { name: "설정 저장" }));
describe("Settings", () => {
  it("edits retention without sending controls or sending fields", async () => {
    const mutations: RequestInit[] = [];
    render(<Settings client={new ApiClient(fetcher((url, init) => {
      if (url.pathname.endsWith("/csrf")) return json({ csrf_token: "token" });
      if (init?.method === "PATCH") mutations.push(init);
      return json(sample);
    }))} />);
    await screen.findByLabelText("Reply-To");
    expect(screen.queryByText("자동 승인 활성화")).not.toBeInTheDocument();
    expect(screen.queryByText("발송 한도")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("이벤트·판정 보관 (일)"), {target: {value: "60"}});
    save();
    await waitFor(() => expect(mutations).toHaveLength(1));
    const body=JSON.parse(String(mutations[0].body));
    expect(body).not.toHaveProperty("delivery_limits");
    expect(body).not.toHaveProperty("automatic_mode");
    expect(body.retention.event_days).toBe(60);
  });

  it("locks pending writes and browser unload, then removes its lock on unmount", async () => {
    const pending = deferred<Response>();
    const view = render(
      <Settings
        client={
          new ApiClient(
            fetcher((url, init) => {
              if (url.pathname.endsWith("/csrf"))
                return json({ csrf_token: "token" });
              return init?.method === "PATCH" ? pending.promise : json(sample);
            }),
          )
        }
      />,
    );
    await screen.findByLabelText("Reply-To");
    save();
    expect(navigationLocked()).toBe(true);
    const unloading = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unloading);
    expect(unloading.defaultPrevented).toBe(true);
    view.unmount();
    expect(navigationLocked()).toBe(false);
    const unlocked = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unlocked);
    expect(unlocked.defaultPrevented).toBe(false);
    await act(async () => pending.resolve(json(sample)));
  });
  it("shows exact versions and active/pending schedules including initial boundary", async () => {
    render(<Settings client={new ApiClient(fetcher(() => json(sample)))} />);
    expect(await screen.findByText("9007199254740993")).toBeInTheDocument();
    expect(screen.getByText("9007199254740995")).toBeInTheDocument();
    expect(screen.getByText("초기 적용")).toBeInTheDocument();
    expect(screen.getByText("2026-11-01T00:00:00Z")).toBeInTheDocument();
  });
  it.each(["network", "503"])(
    "freezes exact request and idempotency key after ambiguous %s and reuses them",
    async (failure) => {
      const mutations: RequestInit[] = [];
      const network = fetcher((url, init) => {
        if (url.pathname.endsWith("/csrf"))
          return json({ csrf_token: "token" });
        if (init?.method === "PATCH") {
          mutations.push(init);
          if (mutations.length === 1) {
            if (failure === "network")
              return Promise.reject(new Error("offline"));
            return json({}, 503);
          }
        }
        return json(sample);
      });
      render(<Settings client={new ApiClient(network)} />);
      await screen.findByLabelText("Reply-To");
      fireEvent.change(screen.getByLabelText("Reply-To"), {
        target: { value: "new@example.org" },
      });
      save();
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "결과를 확인할 수 없습니다",
      );
      expect(screen.getByLabelText("Reply-To")).toBeDisabled();
      expect(navigationLocked()).toBe(true);
      expect(screen.getByRole("button", { name: "설정 저장" })).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "동일 요청 재시도" }));
      await waitFor(() => expect(mutations).toHaveLength(2));
      expect(mutations[0].body).toBe(mutations[1].body);
      expect(JSON.parse(String(mutations[0].body)).expected_version).toBe(
        sample.version,
      );
      expect(
        new Headers(mutations[0].headers).get("Idempotency-Key"),
      ).toBeTruthy();
      expect(new Headers(mutations[0].headers).get("Idempotency-Key")).toBe(
        new Headers(mutations[1].headers).get("Idempotency-Key"),
      );
      await waitFor(() =>
        expect(screen.getByLabelText("Reply-To")).toBeEnabled(),
      );
      expect(navigationLocked()).toBe(false);
    },
  );
  it("requires explicit reload and review after 409", async () => {
    let reads = 0;
    render(
      <Settings
        client={
          new ApiClient(
            fetcher((url, init) => {
              if (url.pathname.endsWith("/csrf"))
                return json({ csrf_token: "token" });
              if (init?.method === "PATCH") return json({}, 409);
              reads++;
              return json({
                ...sample,
                version: reads === 1 ? sample.version : "9007199254740994",
              });
            }),
          )
        }
      />,
    );
    await screen.findByLabelText("Reply-To");
    save();
    expect(await screen.findByRole("alert")).toHaveTextContent("충돌");
    expect(screen.getByLabelText("Reply-To")).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "최신 설정 불러오기" }));
    await screen.findByText("9007199254740994");
    expect(screen.getByRole("button", { name: "설정 저장" })).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "최신 설정 검토 완료" }),
    );
    expect(screen.getByRole("button", { name: "설정 저장" })).toBeEnabled();
  });
  it.each([
    ["초안 집계 주기 (일)", "32"],
    ["SSH 반복 임계값", "1"],
    ["웹 반복 임계값", "4"],
    ["웹 경로 수 임계값", "6"],
    ["시간대", "Local"],
    ["Reply-To", "invalid"],
  ])("rejects invalid %s without mutation", async (label, value) => {
    const network = fetcher(() => json(sample));
    render(<Settings client={new ApiClient(network)} />);
    await screen.findByLabelText(label);
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    save();
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(network).toHaveBeenCalledOnce();
  });
  it("shows a retryable read failure", async () => {
    let fail = true;
    render(
      <Settings
        client={
          new ApiClient(fetcher(() => (fail ? json({}, 503) : json(sample))))
        }
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "설정을 불러오지 못했습니다",
    );
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "다시 시도" }));
    expect(await screen.findByLabelText("Reply-To")).toHaveValue(
      sample.reply_to,
    );
  });
  it("aborts on unmount and ignores old client response", async () => {
    const late = deferred<Response>();
    let signal: AbortSignal | null | undefined;
    const old = new ApiClient(
      fetcher((_url, init) => {
        signal = init?.signal;
        return late.promise;
      }),
    );
    const view = render(<Settings client={old} />);
    view.rerender(
      <Settings
        client={
          new ApiClient(
            fetcher(() => json({ ...sample, reply_to: "fresh@example.org" })),
          )
        }
      />,
    );
    expect(await screen.findByLabelText("Reply-To")).toHaveValue(
      "fresh@example.org",
    );
    expect(signal?.aborted).toBe(true);
    await act(async () => late.resolve(json(sample)));
    expect(screen.getByLabelText("Reply-To")).toHaveValue("fresh@example.org");
  });
});
