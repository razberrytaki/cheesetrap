import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, it, expect } from "vitest";
import { IPDetail } from "./IPDetail";
import { ApiClient } from "../../api/client";
import { fetcher, json } from "../../test/fixtures";
import { refresh } from "../reports/fixtures";
describe("IP detail boundaries", () => {
  beforeEach(() => window.history.replaceState({}, '', '/ips/192.0.2.10'));
  it('shows compact detection pages, opens one detail at a time, and preserves both cursors', async () => {
    window.history.replaceState({}, '', '/ips/192.0.2.10?cursor=reports-page');
    const queries: URLSearchParams[] = [];
    const detections = Array.from({ length: 10 }, (_, i) => ({
      detection_id: `detection-${i}`, rule_id: 'SSH-REPEAT', rule_version: '1',
      processing_ingestion_seq: String(100 - i), evidence_count: 88, evidence_eligible: true,
      settings_version: '1', window_end: '2026-10-20T12:00:00Z',
      explanation: { detail: `synthetic evidence ${i}`, input: '<img src=x onerror=alert(1)>' },
    }));
    const { container } = render(<IPDetail ip="192.0.2.10" client={new ApiClient(fetcher(url => {
      queries.push(url.searchParams);
      return json({ registry: null, reports: [], detections, next_cursor: 'reports-next', next_detection_cursor: 'detections-next' });
    }))} />);
    const table = await screen.findByRole('table', { name: 'IP 탐지 목록' });
    expect(queries[0].get('detection_limit')).toBe('10');
    expect(screen.getByText('이 페이지 10건 · 페이지당 최대 10건')).toBeInTheDocument();
    expect(screen.queryByText(/synthetic evidence/)).not.toBeInTheDocument();
    const buttons = within(table).getAllByRole('button', { name: '상세 보기' });
    fireEvent.click(buttons[0]);
    expect(screen.getByText(/synthetic evidence 0/)).toBeInTheDocument();
    fireEvent.click(buttons[1]);
    expect(screen.queryByText(/synthetic evidence 0/)).not.toBeInTheDocument();
    expect(screen.getByText(/synthetic evidence 1/)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '상세 접기' }));
    expect(buttons[1]).toHaveFocus();
    expect(screen.queryByText(/synthetic evidence/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: '다음 탐지' })).toHaveAttribute('href', '/ips/192.0.2.10?cursor=reports-page&detection_cursor=detections-next');
    expect(screen.getByRole('link', { name: '이 IP의 SSH 로그인 실패' })).toHaveAttribute('href', '/events?source_ip=192.0.2.10&event_type=cowrie.login.failed');
  });
  it("shows empty data and narrows arbitrary registry data as text", async () => {
    const { container } = render(
      <IPDetail
        client={
          new ApiClient(
            fetcher(() =>
              json({
                address: "2001:db8::1",
                registry: ['<a href="https://evil.invalid">bad</a>'],
                reports: null,
                detections: null,
                latest_refresh: refresh,
                next_cursor: "",
                next_detection_cursor: "",
              }),
            ),
          )
        }
        ip="2001:db8::1"
      />,
    );
    expect(
      await screen.findByText("관련 신고가 없습니다."),
    ).toBeInTheDocument();
    expect(screen.getByText("탐지가 없습니다.")).toBeInTheDocument();
    expect(
      container.querySelector('a[href="https://evil.invalid"]'),
    ).toBeNull();
    expect(
      screen.getByRole("link", { name: "이 IP의 이벤트" }),
    ).toHaveAttribute("href", "/events?source_ip=2001%3Adb8%3A%3A1");
  });
  it("retries an unavailable IP without inventing registry state", async () => {
    let failing = true;
    render(
      <IPDetail
        client={
          new ApiClient(
            fetcher(() =>
              failing
                ? json({}, 503)
                : json({
                    registry: null,
                    reports: [],
                    detections: [],
                    latest_refresh: refresh,
                    next_cursor: "",
                    next_detection_cursor: "",
                  }),
            ),
          )
        }
        ip="192.0.2.10"
      />,
    );
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText("등록기관 및 연락처")).toBeNull();
    failing = false;
    fireEvent.click(screen.getByRole("button", { name: "IP 새로고침" }));
    expect(
      await screen.findByText("관련 신고가 없습니다."),
    ).toBeInTheDocument();
  });
});
