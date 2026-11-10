import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ApiClient } from "../../api/client";
import { fetcher, json, deferred } from "../../test/fixtures";
import { ReportDetail } from "./ReportDetail";
import { report, reportID, revision, revisionID } from "./fixtures";

it("keeps the review visible and locks actions until the saved recipient is reloaded", async () => {
  const refreshed = deferred<Response>();
  let saved = false;
  const net = fetcher((url, init) => {
    if (url.pathname.endsWith("/csrf")) return json({ csrf_token: "token" });
    if (init?.method === "POST") {
      saved = true;
      return json({ ...report, version: "9007199254740994", current_revision_id: "new" });
    }
    if (url.pathname === `/api/v1/reports/${reportID}`)
      return saved ? refreshed.promise : json(report);
    return json({ items: [], next_cursor: "", total: "0" });
  });
  render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
  await screen.findByText(revision.body);
  fireEvent.change(screen.getByLabelText("연락처 후보"), { target: { value: "abuse@example.net" } });
  fireEvent.click(screen.getByRole("button", { name: "수신자로 저장" }));
  await screen.findByText(/수신자로 저장했습니다/);
  expect(screen.getByText(revision.body)).toBeVisible();
  expect(screen.getByRole("button", { name: "초안 제외" })).toBeDisabled();
  await act(async () => refreshed.resolve(json({ ...report, version: "9007199254740994", current_revision_id: "new", revision: { ...revision, recipient: "abuse@example.net", revision_id: "new" } })));
  expect(screen.getByRole("button", { name: "초안 제외" })).toBeEnabled();
  expect(screen.getByText("abuse@example.net", { selector: "dd" })).toBeVisible();
});

it("keeps old content visible but blocks mutations after a refresh fails", async () => {
  let reads = 0;
  const net = fetcher((url) => url.pathname === `/api/v1/reports/${reportID}`
    ? (++reads === 1 ? json(report) : json({}, 500))
    : json({ items: [], next_cursor: "", total: "0" }));
  render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
  await screen.findByText(revision.body);
  fireEvent.click(screen.getByRole("button", { name: "신고 상태 새로고침" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("이전 정보");
  expect(screen.getByText(revision.body)).toBeVisible();
  expect(screen.getByRole("button", { name: "초안 제외" })).toBeDisabled();
});

function network(
  mutate?: (init?: RequestInit) => Response | Promise<Response>,
) {
  return fetcher((url, init) => {
    if (url.pathname.endsWith("/csrf")) return json({ csrf_token: "token" });
    if (init?.method === "POST")
      return mutate ? mutate(init) : json({ ...report, state: "rejected" });
    if (url.pathname.endsWith("/evidence"))
      return json({
        items: [
          {
            event_id: "event",
            ingestion_seq: "9007199254740994",
            observed_at: "2026-10-17T00:00:00Z",
            ingested_at: "2026-10-18T00:00:00Z",
            service: "ssh",
            event_type: "login",
            source_ip: "192.0.2.10",
            quality_flags: ["delayed"],
            command: "<svg onload=attack()>",
            entry_truncated: true,
            is_test: false,
          },
        ],
        next_cursor: "",
        total: "1",
      });
    if (url.pathname.endsWith("/rules"))
      return json({
        items: [
          {
            detection_id: "d",
            rule_id: "ssh-repeat",
            rule_version: "1",
            explanation: { reason: "<script>rule()</script>" },
            attached_count: 1,
            context_count: 1,
            entry_truncated: false,
            evidence_eligible: true,
          },
        ],
        next_cursor: "",
        total: "1",
      });
    if (url.pathname.endsWith("/revisions"))
      return json({
        items: [{ ...revision, revision_id: "old", version: "1" }],
        next_cursor: "",
      });
    if (url.pathname.endsWith("/old"))
      return json({
        ...revision,
        revision_id: "old",
        body: "Old immutable body",
      });
    return json(report);
  });
}
describe("report review", () => {
  it("shows holds, safe text, contacts and evidence quality without sending actions", async () => {
    const { container } = render(
      <ReportDetail client={new ApiClient(network())} id={reportID} />,
    );
    expect(
      await screen.findByText("<script>attack()</script>"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("연락처 후보가 여러 개임").length).toBeGreaterThan(0);
    expect(
      screen.getByRole("option", { name: "abuse@example.net" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "security@example.net" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("9007199254740994")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "승인 및 발송" })).toBeNull();
    fireEvent.click(screen.getByText("증거 · 1건", { selector: "summary" }));
    expect(screen.getByText("증거 항목이 잘렸습니다.")).toBeVisible();
    expect(screen.queryByRole("region", { name: /증거 상세/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "이벤트 #9007199254740994 증거 보기" }));
    expect(screen.getByRole("region", { name: /증거 상세/ })).toHaveTextContent("<svg onload=attack()>");
    expect(container.querySelector("script,img,svg")).toBeNull();
  });
  it("freezes the exact expectation and idempotency key for ambiguous retry", async () => {
    const calls: RequestInit[] = [];
    const net = network((init) => {
      calls.push(init!);
      return json({}, 503);
    });
    render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
    await screen.findByText("<script>attack()</script>");
    fireEvent.change(screen.getByLabelText("연락처 후보"), {
      target: { value: "abuse@example.net" },
    });
    fireEvent.click(screen.getByRole("button", { name: "수신자로 저장" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "동일 요청 재시도" }),
    );
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0].body).toBe(calls[1].body);
    expect(JSON.parse(String(calls[0].body))).toEqual({
      expected_version: "9007199254740993",
      current_revision_id: revisionID,
      recipient: "abuse@example.net",
    });
    expect(new Headers(calls[0].headers).get("Idempotency-Key")).toBeTruthy();
    expect(new Headers(calls[1].headers).get("Idempotency-Key")).toBe(
      new Headers(calls[0].headers).get("Idempotency-Key"),
    );
    expect(screen.getByRole("button", { name: "초안 제외" })).toBeDisabled();
  });
  it("blocks stale 409 actions until explicit reloading and review", async () => {
    const net = network(() => json({}, 409));
    render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
    await screen.findByText("<script>attack()</script>");
    fireEvent.click(screen.getByRole("button", { name: "초안 제외" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("다른 변경");
    expect(screen.getByRole("button", { name: "초안 제외" })).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "동일 요청 재시도" }),
    ).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "신고 상태 새로고침" }),
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "초안 제외" })).toBeEnabled(),
    );
  });
  it("makes previous revisions strictly read only", async () => {
    render(<ReportDetail client={new ApiClient(network())} id={reportID} />);
    fireEvent.click(await screen.findByText("개정 이력과 신고 정보", { selector: "summary" }));
    fireEvent.click(await screen.findByRole("button", { name: "개정 1 보기" }));
    expect(await screen.findByText("Old immutable body")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "초안 제외" })).toBeNull();
    expect(screen.getByText(/이전 개정.*읽기 전용/)).toBeInTheDocument();
  });
  it("shows an error without mutation controls when report load fails", async () => {
    render(
      <ReportDetail
        client={new ApiClient(fetcher(() => json({}, 500)))}
        id={reportID}
      />,
    );
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "초안 제외" })).toBeNull();
  });
  it("ignores a late report response after identity changes", async () => {
    const late = deferred<Response>();
    const net = fetcher((url) =>
      url.pathname.endsWith("/first")
        ? late.promise
        : json({
            ...report,
            subject: "Newest",
            revision: { ...revision, subject: "Newest" },
          }),
    );
    const view = render(
      <ReportDetail client={new ApiClient(net)} id="first" />,
    );
    view.rerender(<ReportDetail client={new ApiClient(net)} id="second" />);
    await screen.findByText("Newest");
    await act(async () => late.resolve(json(report)));
    expect(screen.queryByText(revision.subject)).toBeNull();
  });
});
it("keeps empty revision evidence and rules explicit", async () => {
  const net = fetcher((url) =>
    url.pathname.endsWith("/revisions")
      ? json({ items: null, next_cursor: "" })
      : url.pathname.endsWith("/rules") || url.pathname.endsWith("/evidence")
        ? json({ items: null, total: "0", next_cursor: "" })
        : json({
            ...report,
            revision: { ...revision, registry: null, hold_reasons: null },
          }),
  );
  render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
  expect(await screen.findByText("증거가 없습니다.")).toBeInTheDocument();
  expect(await screen.findByText("규칙이 없습니다.")).toBeInTheDocument();
  expect(screen.getByText("개정 이력이 없습니다.")).toBeInTheDocument();
  expect(
    screen.getByText("선택할 연락처 후보가 없습니다."),
  ).toBeInTheDocument();
});
it("paginates evidence and rules independently for the selected immutable revision", async () => {
  const net = fetcher((url) =>
    url.pathname.endsWith("/evidence") || url.pathname.endsWith("/rules")
      ? json({
          items: [],
          total: "9007199254740999",
          next_cursor: url.searchParams.has("cursor") ? "" : "page-2",
        })
      : url.pathname.endsWith("/revisions")
        ? json({ items: [], next_cursor: "" })
        : json(report),
  );
  render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
  await screen.findByText("증거가 없습니다.");
  fireEvent.click(screen.getByText("증거 · 1건", { selector: "summary" }));
  const next = screen
    .getAllByRole("button", { name: "다음" })
    .filter((button) => !button.hasAttribute("disabled"));
  fireEvent.click(next[0]);
  await waitFor(() =>
    expect(
      net.mock.calls.some(([path]) =>
        String(path).includes(
          `/revisions/${revisionID}/evidence?limit=50&cursor=page-2`,
        ),
      ),
    ).toBe(true),
  );
  expect(
    net.mock.calls.some(([path]) =>
      String(path).includes("/rules?limit=50&cursor=page-2"),
    ),
  ).toBe(false);
});
it("shows contact refresh acceptance separately from background completion", async () => {
  render(
    <ReportDetail
      client={
        new ApiClient(
          network(() => json({ ...report, refresh_request_id: "refresh-id" })),
        )
      }
      id={reportID}
    />,
  );
  fireEvent.click(await screen.findByText("연락처 후보 다시 찾기", { selector: "summary" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "등록기관 연락처 다시 조회" }),
  );
  expect(
    await screen.findByText(
      "등록기관 연락처 재조회 요청이 접수되었습니다. 아직 완료된 것은 아닙니다. ‘신고 상태 새로고침’으로 결과를 확인하세요.",
    ),
  ).toBeInTheDocument();
});

it("keeps archived legacy drafts read only without sending actions", async () => {
 render(<ReportDetail client={new ApiClient(fetcher(() => json({...report,state:"archived"})))} id={reportID} />);
 await screen.findByText("archived");
 expect(screen.getByText(/이미 전달됐을 가능성/)).toBeInTheDocument();
 expect(screen.getByRole("button", {name:"초안 제외"})).toBeDisabled();
 expect(screen.getByRole("combobox", {name:"연락처 후보"})).toBeDisabled();
 expect(screen.queryByRole("button", {name:/승인|발송|재전송/})).toBeNull();
});

it("labels collection-gap holds and displays incident ranges and causes", async () => {
 const net = fetcher(url => {
 if(url.pathname.endsWith('/evidence')) return json({items:[{event_id:'gap-event',ingestion_seq:'1',service:'ssh',event_type:'login',quality_flags:[],collection_gap:{started_at:'2026-10-17T01:00:00Z',observed_through:'2026-10-17T02:00:00Z',incidents:[{started_at:'2026-10-17T01:00:00Z',observed_through:'2026-10-17T02:00:00Z',causes:['retention_cleanup']}]}}],total:'1',next_cursor:''});
 if(url.pathname.endsWith('/rules')) return json({items:[],total:'0',next_cursor:''});
 return json({...report,revision:{...revision,hold_reasons:['collection_gap','future_reason']}});
 });
 render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
 expect(await screen.findByText('수집 공백 기록')).toBeVisible();
 expect(screen.getByText('future_reason')).toBeVisible();
 fireEvent.click(screen.getByText(/증거 ·/));
 expect(await screen.findByText('보관 정리로 원본 삭제(미확인 손실 가능)')).toBeVisible();
 expect(screen.getByText(/신고 기간과 겹치는 수집 공백/)).toBeVisible();
 expect(screen.getByText(/2026-10-17 01:00:00/)).toBeVisible();
 expect(screen.getByText(/2026-10-17 02:00:00/)).toBeVisible();
});

it("does not claim a report-window overlap for gaps copied by earlier versions", async () => {
 const net = fetcher(url => {
 if(url.pathname.endsWith('/evidence')) return json({items:[{event_id:'old-gap-event',ingestion_seq:'1',service:'ssh',event_type:'login',quality_flags:['collection_gap'],collection_gap:{started_at:'2026-01-02T01:00:00Z',observed_through:'2026-01-02T02:00:00Z'}}],total:'1',next_cursor:''});
 if(url.pathname.endsWith('/rules')) return json({items:[],total:'0',next_cursor:''});
 return json({...report,revision:{...revision,hold_reasons:['collection_gap']}});
 });
 render(<ReportDetail client={new ApiClient(net)} id={reportID} />);
 expect(await screen.findByText('수집 공백 기록')).toBeVisible();
 fireEvent.click(screen.getByText(/증거 ·/));
 expect(await screen.findByText(/이전 방식으로 복사된 센서 수집 공백/)).toBeVisible();
 expect(screen.queryByText(/신고 기간과 겹치는/)).toBeNull();
});
