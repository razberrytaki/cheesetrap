import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { ApiClient } from "./api/client";
import {
  deferred,
  fetcher,
  json,
  identity,
  overview,
  sampleEvent,
} from "./test/fixtures";
import { CollectionStatus } from "./features/status/CollectionStatus";
import { report, refresh } from "./features/reports/fixtures";
afterEach(() => window.history.replaceState({}, "", "/"));
const net = () =>
  fetcher((url) => {
    if (url.pathname.endsWith("/me")) return json(identity);
    if (url.pathname.endsWith("/overview")) return json(overview);
    if (url.pathname.includes("/ips/"))
      return json({
        address: "192.0.2.10",
        detections: [],
        reports: [report],
        next_cursor: "",
        next_detection_cursor: "",
        registry: { candidates: [] },
        registry_expired: true,
        registry_truncated: true,
        registry_expires_at: null,
        latest_refresh: refresh,
      });
    if (url.pathname.endsWith("/events"))
      return json({ items: [sampleEvent], next_cursor: "" });
    if (url.pathname.endsWith("/reports"))
      return json({ items: [report], next_cursor: "" });
    return json(report);
  });
describe("dashboard navigation and states", () => {
  it("shows recovery counts without treating unknown as success", async () => {
    window.history.replaceState({}, "", "/overview");
    render(<App client={new ApiClient(net())} />);
    await screen.findByRole("region", { name: "검토 대기 신고" });
    expect(screen.queryByText("SMTP 접수 완료")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /발송/ })).not.toBeInTheDocument();
  });

  it("navigates overview to events to IP and report list with native URLs", async () => {
    window.history.replaceState({}, "", "/overview");
    const network = net();
    render(<App client={new ApiClient(network)} />);
    expect(
      await screen.findByRole("heading", { name: "개요" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("link", { name: "이벤트" })[0]);
    fireEvent.click(await screen.findByRole("link", { name: "192.0.2.10" }));
    expect(
      await screen.findByRole("heading", { name: "IP 상세" }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe("/ips/192.0.2.10");
    expect(screen.getByText(/등록기관 캐시가 만료/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "이 IP의 신고" }));
    expect(
      await screen.findByRole("heading", { name: "신고 목록" }),
    ).toBeInTheDocument();
    expect(window.location.search).toContain("source_ip=192.0.2.10");
  });
  it("restores event URL filters on direct links and writes applied filters", async () => {
    window.history.replaceState(
      {},
      "",
      "/events?source_ip=192.0.2.10&service=ssh",
    );
    const network = net();
    render(<App client={new ApiClient(network)} />);
    expect(await screen.findByLabelText("출발지 IP")).toHaveValue("192.0.2.10");
    fireEvent.change(screen.getByLabelText("서비스"), {
      target: { value: "http" },
    });
    fireEvent.click(screen.getByRole("button", { name: "필터 적용" }));
    await waitFor(() =>
      expect(window.location.search).toContain("service=http"),
    );
    expect(
      network.mock.calls.some(([path]) =>
        String(path).includes("service=http"),
      ),
    ).toBe(true);
  });
  it("renders report empty state and request failure without fake counts", async () => {
    window.history.replaceState({}, "", "/reports");
    let fail = false;
    const network = fetcher((url) =>
      url.pathname.endsWith("/me")
        ? json(identity)
        : fail
          ? json({}, 503)
          : json({ items: null, next_cursor: "" }),
    );
    render(<App client={new ApiClient(network)} />);
    expect(
      await screen.findByText("조건에 맞는 신고가 없습니다."),
    ).toBeInTheDocument();
    fail = true;
    fireEvent.click(screen.getByRole("button", { name: "신고 목록 새로고침" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
it("keeps an ambiguous report operation mounted when internal navigation is attempted", async () => {
  window.history.replaceState({}, "", `/reports/${report.report_id}`);
  const network = fetcher((url, init) =>
    url.pathname.endsWith("/me")
      ? json(identity)
      : url.pathname.endsWith("/csrf")
        ? json({ csrf_token: "csrf" })
        : init?.method === "POST"
          ? json({}, 503)
          : url.pathname.endsWith("/revisions")
            ? json({ items: [], next_cursor: "" })
            : url.pathname.endsWith("/evidence") ||
                url.pathname.endsWith("/rules")
              ? json({ items: [], next_cursor: "", total: "0" })
              : json(report),
  );
  render(<App client={new ApiClient(network)} />);
  fireEvent.click(await screen.findByRole("button", { name: "초안 제외" }));
  await screen.findByRole("button", { name: "동일 요청 재시도" });
  fireEvent.click(screen.getByRole("link", { name: "이벤트" }));
  expect(
    screen.getByRole("button", { name: "동일 요청 재시도" }),
  ).toBeInTheDocument();
  expect(window.location.pathname).toBe(`/reports/${report.report_id}`);
});
it("keeps event cursor and previous page history in the URL across detail navigation", async () => {
  window.history.replaceState({}, "", "/events?service=ssh");
  const network = fetcher((url) =>
    url.pathname.endsWith("/me")
      ? json(identity)
      : url.pathname.endsWith("/overview")
        ? json(overview)
        : url.pathname.includes("/ips/")
          ? json({
              address: "192.0.2.10",
              reports: [],
              detections: [],
              next_cursor: "",
              next_detection_cursor: "",
              registry: null,
              latest_refresh: refresh,
            })
          : json({
              items: [sampleEvent],
              next_cursor: url.searchParams.has("cursor") ? "" : "second-page",
            }),
  );
  render(<App client={new ApiClient(network)} />);
  await screen.findByRole("link", { name: "192.0.2.10" });
  fireEvent.click(screen.getByRole("button", { name: "다음" }));
  await waitFor(() =>
    expect(window.location.search).toContain("cursor=second-page"),
  );
  expect(await screen.findByText("2 페이지")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("link", { name: "192.0.2.10" }));
  await screen.findByRole("heading", { name: "IP 상세" });
  window.history.back();
  await waitFor(() =>
    expect(screen.getByRole("heading", { name: "이벤트" })).toBeInTheDocument(),
  );
  expect(window.location.search).toContain("cursor=second-page");
  expect(await screen.findByRole("button", { name: "이전" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "이전" }));
  await waitFor(() => expect(window.location.search).not.toContain("cursor="));
});

it.each(["report", "settings"])(
  "keeps the %s mutation body/key through blocked busy and ambiguous logout, then allows logout after resolution",
  async (kind) => {
    const pending = deferred<Response>();
    const mutations: RequestInit[] = [];
    let logoutCalls = 0;
    const settings = {
      retention: { raw_days:7,raw_bytes:"1073741824",event_days:30,history_days:180,job_days:7 },
      version: "9007199254740993",
      reply_to: "ops@example.org",
      timezone: "UTC",
      period_days: 7,
      rules: {
        ssh_repeat_threshold: 10,
        web_repeat_threshold: 20,
        web_distinct_path_threshold: 5,
      },
      rule_effective_from_seq: "9007199254740995",
      schedule_version: "1",
      active_schedule: {
        version: "1",
        timezone: "UTC",
        period_days: 7,
        effective_from: "-infinity",
      },
      pending_schedule: null,
    };
    window.history.replaceState(
      {},
      "",
      kind === "report" ? `/reports/${report.report_id}` : "/settings",
    );
    const network = fetcher((url, init) => {
      if (url.pathname.endsWith("/me")) return json(identity);
      if (url.pathname.endsWith("/csrf")) return json({ csrf_token: "csrf" });
      if (url.pathname.endsWith("/logout")) {
        logoutCalls++;
        return json({ logged_out: true });
      }
      if (init?.method === "POST" || init?.method === "PATCH") {
        mutations.push(init);
        return mutations.length === 1
          ? pending.promise
          : json(kind === "report" ? report : settings);
      }
      if (url.pathname.endsWith("/settings")) return json(settings);
      if (url.pathname.endsWith("/revisions"))
        return json({ items: [], next_cursor: "" });
      if (url.pathname.endsWith("/evidence") || url.pathname.endsWith("/rules"))
        return json({ items: [], next_cursor: "", total: "0" });
      return json(report);
    });
    render(<App client={new ApiClient(network)} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: kind === "report" ? "초안 제외" : "설정 저장",
      }),
    );
    await waitFor(() => expect(mutations).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "계정 메뉴: operator" }));
    fireEvent.click(screen.getByRole("button", { name: "로그아웃" }));
    await waitFor(() =>
      expect(
        screen.getByText(/처리 결과를 확인한 후 로그아웃/),
      ).toBeInTheDocument(),
    );
    expect(logoutCalls).toBe(0);
    await act(async () => pending.resolve(json({}, 503)));
    await screen.findByRole("button", { name: "동일 요청 재시도" });
    fireEvent.click(screen.getByRole("button", { name: "계정 메뉴: operator" }));
    fireEvent.click(screen.getByRole("button", { name: "로그아웃" }));
    expect(logoutCalls).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "동일 요청 재시도" }));
    await waitFor(() => expect(mutations).toHaveLength(2));
    expect(mutations[1].body).toBe(mutations[0].body);
    expect(new Headers(mutations[1].headers).get("Idempotency-Key")).toBe(
      new Headers(mutations[0].headers).get("Idempotency-Key"),
    );
    await screen.findByText(
      kind === "report"
        ? "초안을 제외했습니다."
        : "설정을 저장했습니다.",
    );
    fireEvent.click(screen.getByRole("button", { name: "계정 메뉴: operator" }));
    fireEvent.click(screen.getByRole("button", { name: "로그아웃" }));
    expect(
      await screen.findByRole("button", { name: "로그인" }),
    ).toBeInTheDocument();
    expect(logoutCalls).toBe(1);
  },
);

it("shows operational limits, pending work and distinct sensor observations", async () => {
 window.history.replaceState({}, "", "/overview");
 const network = fetcher((url) => url.pathname.endsWith("/me") ? json(identity) : json({...overview, operations: {
 storage_state: "restricted", disk_used_percent: 93, storage_sampled_at: "2026-10-21T01:00:00Z",
 storage_backlog: true, protected_events: "123", collection_lag_seconds: 120, detection_lag_seconds: 45,
 oldest_queue_age_seconds: 300, lookup_failures: "7", report_states: {held:"4"},
 sensors: [{name:"cowrie", collector_state:"degraded", last_engine_log_at:null, last_observation_at:"2026-10-21T00:59:00Z", gap_count:"9"}],
 retention: {raw_days:7, raw_bytes:1073741824, event_days:30, history_days:180, job_days:7}
 }}));
 render(<App client={new ApiClient(network)} />);
 expect(await screen.findByText("용량 제한 중", {exact: true, selector: "span"})).toBeVisible();
 const disclosure = screen.getByText("수집 상태 상세");
 expect(disclosure.closest("details")).not.toHaveAttribute("open");
 expect(screen.getByText("보호 중인 이벤트")).not.toBeVisible();
 fireEvent.click(disclosure);
 expect(disclosure.closest("details")).toHaveAttribute("open");
 expect(screen.getByText("보호 중인 이벤트")).toBeVisible();
 expect(screen.getByText("123")).toBeInTheDocument();
 expect(screen.getByText("큐 최고 대기 시간")).toBeInTheDocument();
 expect(screen.getByText("엔진 로그 확인")).toBeInTheDocument();
 expect(screen.getByText("수집기 관측")).toBeInTheDocument();
 expect(screen.getByText(/공백 기록은 유지/)).toBeInTheDocument();
});

it("does not invent healthy capacity or zero lag before observations", async () => {
 window.history.replaceState({}, "", "/overview");
 render(<App client={new ApiClient(net())} />);
 expect(await screen.findByText("용량 확인 불가", {exact: true, selector: "span"})).toBeVisible();
 expect(screen.getAllByText("관측 없음").length).toBeGreaterThan(0);
 expect(screen.queryByText(/0\.0%/)).not.toBeInTheDocument();
});

it('uses recent gaps for the dashboard summary and alert', async () => {
 const client=new ApiClient(fetcher(()=>json({...overview,sensors_with_gaps:'99',sensors_recent_gaps:'2'})));
 render(<CollectionStatus client={client} dashboard />);
 expect(await screen.findByText('최근 24시간 수집 공백 2')).toBeVisible();
 expect(screen.queryByText('99')).not.toBeInTheDocument();
 expect(screen.getAllByText('최근 24시간 수집 공백').length).toBeGreaterThan(0);
});
