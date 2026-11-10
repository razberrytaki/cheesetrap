import { Brand } from "./features/shared/Brand";
import { useEffect, useRef, useState } from "react";
import {
  ApiClient,
  ApiError,
  errorMessage,
  isCancelled,
  type Identity,
} from "./api/client";
import { Login } from "./features/auth/Login";
import { EventsPage } from "./features/events/EventsPage";
import { AccountMenu } from "./features/auth/AccountMenu";
import { navigationLocked } from "./features/shared/useNavigationLock";
import { Overview } from "./features/overview/Overview";
import { IPDetail } from "./features/ips/IPDetail";
import { ReportList } from "./features/reports/ReportList";
import { ReportDetail } from "./features/reports/ReportDetail";
import { Settings } from "./features/settings/Settings";

type Session =
  | { kind: "checking" }
  | { kind: "error"; message: string }
  | { kind: "anonymous"; expired: boolean }
  | { kind: "authenticated"; identity: Identity };
export function App({ client }: { client: ApiClient }) {
  const [location, setLocation] = useState(
    () => window.location.pathname + window.location.search,
  );
  const currentLocation = useRef(location);
  const [navigationError, setNavigationError] = useState("");
  currentLocation.current = location;
  useEffect(() => {
    const update = () => {
      if (navigationLocked()) {
        window.history.pushState({}, "", currentLocation.current);
        setNavigationError(
          "처리 결과를 확인한 후 페이지를 이동하세요. 동일 요청 재시도로 결과를 확인할 수 있습니다.",
        );
        return;
      }
      setNavigationError("");
      setLocation(window.location.pathname + window.location.search);
    };
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  const path = location.split("?")[0];
  const title =
    path === "/overview"
      ? "개요"
      : path.startsWith("/ips/")
        ? "IP 상세"
        : path.startsWith("/reports")
          ? "신고 검토"
            : path === "/settings"
              ? "설정"
              : "이벤트 탐색";
  const [session, setSession] = useState<Session>({ kind: "checking" });
  useEffect(() => {
    document.title = `cheesetrap · ${session.kind === "authenticated" ? title : "관리자 접속"}`;
    if (session.kind === "authenticated") document.getElementById("workspace")?.focus();
  }, [path, title, session.kind]);
  const [attempt, setAttempt] = useState(0);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  useEffect(
    () =>
      client.onUnauthorized(() => {
        setSession((previous) => ({
          kind: "anonymous",
          expired:
            previous.kind === "authenticated" ||
            (previous.kind === "anonymous" && previous.expired),
        }));
        setLogoutError("");
      }),
    [client],
  );
  useEffect(() => {
    let active = true;
    setSession({ kind: "checking" });
    client
      .me()
      .then((identity) => {
        if (active) setSession({ kind: "authenticated", identity });
      })
      .catch((error: unknown) => {
        if (!active || isCancelled(error)) return;
        if (error instanceof ApiError && error.status === 401)
          setSession({ kind: "anonymous", expired: false });
        else
          setSession({
            kind: "error",
            message: errorMessage(
              error,
              "세션을 확인하지 못했습니다. 잠시 후 다시 시도하세요.",
            ),
          });
      });
    return () => {
      active = false;
    };
  }, [client, attempt]);
  async function logout() {
    if (navigationLocked()) {
      setNavigationError(
        "처리 결과를 확인한 후 로그아웃하세요. 동일 요청 재시도로 결과를 확인할 수 있습니다.",
      );
      return;
    }
    setNavigationError("");
    setLoggingOut(true);
    setLogoutError("");
    try {
      await client.logout();
      setSession({ kind: "anonymous", expired: false });
    } catch (error) {
      if (
        !isCancelled(error) &&
        !(error instanceof ApiError && error.status === 401)
      )
        setLogoutError(
          errorMessage(error, "로그아웃하지 못했습니다. 다시 시도하세요."),
        );
    } finally {
      setLoggingOut(false);
    }
  }
  if (session.kind === "checking")
    return (
      <main className="session-page">
        <p role="status">세션을 확인하는 중…</p>
      </main>
    );
  if (session.kind === "error")
    return (
      <main className="session-page">
        <h1>cheesetrap</h1>
        <p className="error" role="alert">
          {session.message}
        </p>
        <button onClick={() => setAttempt((n) => n + 1)}>다시 시도</button>
      </main>
    );
  if (session.kind === "anonymous")
    return (
      <Login
        client={client}
        expired={session.expired}
        onLogin={(identity) => setSession({ kind: "authenticated", identity })}
      />
    );
  return (
    <div
      className="app-shell"
      onClick={(event) => {
        const link = (event.target as HTMLElement).closest("a");
        if (
          !link ||
          event.button !== 0 ||
          event.ctrlKey ||
          event.metaKey ||
          event.shiftKey ||
          event.altKey ||
          link.target ||
          link.hasAttribute("download")
        )
          return;
        const url = new URL(link.href, window.location.href);
        if (url.origin !== window.location.origin || url.hash) return;
        event.preventDefault();
        if (navigationLocked()) {
          setNavigationError(
            "처리 결과를 확인한 후 페이지를 이동하세요. 동일 요청 재시도로 결과를 확인할 수 있습니다.",
          );
          return;
        }
        setNavigationError("");
        window.history.pushState({}, "", url.pathname + url.search);
        setLocation(url.pathname + url.search);
      }}
    >
      <a className="skip-link" href="#workspace">
        본문으로 건너뛰기
      </a>
      <header className="side-rail" aria-label="관리 콘솔">
        <div className="wordmark"><Brand /></div>
        <nav aria-label="주 메뉴">
          {[
            ["/overview", "개요"],
            ["/events", "이벤트"],
            ["/reports", "신고"],
            ["/settings", "설정"],
          ].map(([href, label]) => (
            <a
              key={href}
              href={href}
              aria-current={
                path === href ||
                (href === "/events" && (path === "/" || path.startsWith("/ips/"))) ||
                (href === "/reports" && path.startsWith("/reports/"))
                  ? "page"
                  : undefined
              }
            >
              {label}
            </a>
          ))}
        </nav>
        <AccountMenu username={session.identity.username} loggingOut={loggingOut} onLogout={logout} />
      </header>
      <div className="main-shell">
        <main id="workspace" className="workspace" tabIndex={-1}>
          {navigationError && (
            <p className="error" role="alert">
              {navigationError}
            </p>
          )}
          {logoutError && (
            <p className="error" role="alert">
              {logoutError}
            </p>
          )}
          {path === "/overview" ? (
            <Overview client={client} />
          ) : path === "/settings" ? (
            <Settings client={client} />
          ) : path === "/reports" ? (
            <ReportList key={location} client={client} />
          ) : path.startsWith("/reports/") ? (
            <ReportDetail
              client={client}
              id={decodeURIComponent(path.slice(9))}
            />
          ) : path.startsWith("/ips/") ? (
            <IPDetail
              key={location}
              client={client}
              ip={decodeURIComponent(path.slice(5))}
            />
          ) : path === "/" || path === "/events" ? (
            <EventsPage client={client} location={location} />
          ) : (
            <h1>페이지를 찾을 수 없습니다.</h1>
          )}
        </main>
        <footer className="app-footer">
          <span>cheesetrap</span>
          <span>조회 시점의 데이터 · 수동 새로고침</span>
        </footer>
      </div>
    </div>
  );
}
