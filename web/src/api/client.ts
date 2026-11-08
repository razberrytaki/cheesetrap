import type { components, operations } from "./schema";

export type Identity = components["schemas"]["Identity"];
export type Event = components["schemas"]["Event"];
export type EventPage = components["schemas"]["EventListOutputBody"];
export type Overview = components["schemas"]["OverviewOutputBody"];
export type EventQuery = NonNullable<
  operations["events-list"]["parameters"]["query"]
>;
export type Schema = components["schemas"];
export type ReportQuery = NonNullable<
  operations["reports-list"]["parameters"]["query"]
>;
export type IPQuery = NonNullable<operations["ips-get"]["parameters"]["query"]>;
type MutationBody =
  | Record<string, never>
  | Schema["LoginInputBody"]
  | Schema["ReportExpectation"]
  | Schema["SelectContactInputBody"]
  | Schema["SettingsPatchInputBody"];
type LoginResult = components["schemas"]["LoginOutputBody"];
type CSRF = components["schemas"]["CsrfOutputBody"];

export class ApiError extends Error {
  constructor(public readonly status: number) {
    super(`Request failed (${status})`);
  }
}
export class StaleRequestError extends Error {}
export class NetworkError extends Error {}
export const isCancelled = (error: unknown) =>
  error instanceof StaleRequestError ||
  (error instanceof Error && error.name === "AbortError");
export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof NetworkError)
    return "서버에 연결할 수 없습니다. 연결을 확인하고 다시 시도하세요.";
  return fallback;
}

// Session cookies stay HttpOnly. CSRF exists only in this instance's memory.
// Epoch checks cover both fetch and body reads: an expired session cannot be
// resurrected by a request started before logout, login, or a protected 401.
export class ApiClient {
  private epoch = 0;
  private csrf = "";
  private listeners = new Set<() => void>();
  constructor(
    private readonly fetcher: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}

  onUnauthorized(listener: () => void) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
  private invalidate() {
    this.epoch++;
    this.csrf = "";
  }
  private current(epoch: number) {
    if (epoch !== this.epoch) throw new StaleRequestError();
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
    authenticated = true,
    epoch = this.epoch,
  ): Promise<T> {
    let response: Response;
    try {
      response = await this.fetcher(`/api/v1${path}`, {
        ...init,
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json", ...init.headers },
      });
    } catch (error) {
      this.current(epoch);
      if (isCancelled(error)) throw error;
      throw new NetworkError();
    }
    this.current(epoch);
    if (!response.ok) {
      if (response.status === 401 && authenticated) {
        this.invalidate();
        this.listeners.forEach((listener) => listener());
      }
      throw new ApiError(response.status);
    }
    let body: T;
    try {
      body = (await response.json()) as T;
    } catch {
      this.current(epoch);
      throw new ApiError(502);
    }
    this.current(epoch);
    return body;
  }

  private async unsafe<T>(
    path: string,
    body: MutationBody | undefined,
    authenticated: boolean,
    epoch: number,
    key?: string,
    signal?: AbortSignal,
    method = "POST",
  ): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      // A server restart changes its CSRF signing key. Obtain a fresh token
      // before every unsafe action; a concurrent restart gets one bounded retry.
      const fresh = await this.request<CSRF>(
        "/auth/csrf",
        { signal },
        false,
        epoch,
      );
      this.csrf = fresh.csrf_token;
      try {
        return await this.request<T>(
          path,
          {
            method,
            signal,
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": this.csrf,
              ...(key ? { "Idempotency-Key": key } : {}),
            },
            ...(body ? { body: JSON.stringify(body) } : {}),
          },
          authenticated,
          epoch,
        );
      } catch (error) {
        if (
          !(error instanceof ApiError && error.status === 403 && attempt === 0)
        )
          throw error;
      }
    }
  }
  me(): Promise<Identity> {
    return this.request("/auth/me");
  }
  async login(username: string, password: string): Promise<Identity> {
    this.invalidate();
    const result = await this.unsafe<LoginResult>(
      "/auth/login",
      { username, password },
      false,
      this.epoch,
    );
    this.csrf = result.csrf_token;
    return result.admin;
  }
  async logout(): Promise<void> {
    // Keep reads valid if revocation fails; successful logout invalidates all
    // outstanding responses before the UI can return to the login form.
    await this.unsafe<components["schemas"]["LogoutOutputBody"]>(
      "/auth/logout",
      undefined,
      true,
      this.epoch,
    );
    this.invalidate();
  }
  events(query: EventQuery, signal?: AbortSignal): Promise<EventPage> {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value !== undefined && value !== "") search.set(key, String(value));
    return this.request(`/events?${search}`, { signal });
  }
  event(id: string, signal?: AbortSignal): Promise<Event> {
    return this.request(`/events/${encodeURIComponent(id)}`, { signal });
  }
  private query(query: Record<string, string | number | undefined>) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query))
      if (value !== undefined && value !== "") params.set(key, String(value));
    return params.toString();
  }
  reports(
    query: ReportQuery,
    signal?: AbortSignal,
  ): Promise<Schema["ReportListOutputBody"]> {
    return this.request(`/reports?${this.query(query)}`, { signal });
  }
  ip(
    ip: string,
    query: IPQuery = {},
    signal?: AbortSignal,
  ): Promise<Schema["IpOutputBody"]> {
    return this.request(`/ips/${encodeURIComponent(ip)}?${this.query(query)}`, {
      signal,
    });
  }
  report(
    id: string,
    signal?: AbortSignal,
  ): Promise<Schema["ReportDetailOutputBody"]> {
    return this.request(`/reports/${encodeURIComponent(id)}`, { signal });
  }
  revisions(
    id: string,
    cursor = "",
    signal?: AbortSignal,
  ): Promise<Schema["RevisionListOutputBody"]> {
    return this.request(
      `/reports/${encodeURIComponent(id)}/revisions?${this.query({ limit: 50, cursor })}`,
      { signal },
    );
  }
  revision(
    id: string,
    revision: string,
    signal?: AbortSignal,
  ): Promise<Schema["RevisionView"]> {
    return this.request(
      `/reports/${encodeURIComponent(id)}/revisions/${encodeURIComponent(revision)}`,
      { signal },
    );
  }
  evidence(
    id: string,
    revision: string,
    cursor = "",
    signal?: AbortSignal,
  ): Promise<Schema["EvidencePageOutputBody"]> {
    return this.request(
      `/reports/${encodeURIComponent(id)}/revisions/${encodeURIComponent(revision)}/evidence?${this.query({ limit: 50, cursor })}`,
      { signal },
    );
  }
  rules(
    id: string,
    revision: string,
    cursor = "",
    signal?: AbortSignal,
  ): Promise<Schema["RulePageOutputBody"]> {
    return this.request(
      `/reports/${encodeURIComponent(id)}/revisions/${encodeURIComponent(revision)}/rules?${this.query({ limit: 50, cursor })}`,
      { signal },
    );
  }
  selectContact(
    id: string,
    body: Schema["SelectContactInputBody"],
    key: string,
    signal?: AbortSignal,
  ): Promise<Schema["ReportMutation"]> {
    return this.unsafe(
      `/reports/${encodeURIComponent(id)}/select-contact`,
      body,
      true,
      this.epoch,
      key,
      signal,
    );
  }
  rejectReport(
    id: string,
    body: Schema["ReportExpectation"],
    key: string,
    signal?: AbortSignal,
  ): Promise<Schema["ReportMutation"]> {
    return this.unsafe(
      `/reports/${encodeURIComponent(id)}/reject`,
      body,
      true,
      this.epoch,
      key,
      signal,
    );
  }
  refreshContact(
    id: string,
    body: Schema["ReportExpectation"],
    key: string,
    signal?: AbortSignal,
  ): Promise<Schema["ReportMutation"]> {
    return this.unsafe(
      `/reports/${encodeURIComponent(id)}/refresh-contact`,
      body,
      true,
      this.epoch,
      key,
      signal,
    );
  }
  settings(signal?: AbortSignal): Promise<Schema["SettingsOutputBody"]> {
    return this.request("/settings", { signal });
  }
  patchSettings(
    body: Schema["SettingsPatchInputBody"],
    key: string,
    signal?: AbortSignal,
  ): Promise<Schema["Settings"]> {
    return this.unsafe(
      "/settings",
      body,
      true,
      this.epoch,
      key,
      signal,
      "PATCH",
    );
  }
  overview(signal?: AbortSignal): Promise<Overview> {
    return this.request("/overview", { signal });
  }
}
