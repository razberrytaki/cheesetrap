import { describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError, StaleRequestError } from './client';
import { deferred, fetcher, identity, json, overview } from '../test/fixtures';

describe('same-origin API client', () => {
  it('fetches fresh CSRF before each unsafe operation and retries a restart 403 only once', async () => {
    let token = 0; let attempts = 0;
    const sent: string[] = [];
    const network = fetcher((url, init) => {
      if (url.pathname.endsWith('/csrf')) return json({ csrf_token: `fresh-${++token}` });
      sent.push(new Headers(init?.headers).get('X-CSRF-Token') ?? '');
      if (url.pathname.endsWith('/login')) return ++attempts === 1 ? json({}, 403) : json({ admin: identity, csrf_token: 'rotated' });
      return json({ logged_out: true });
    });
    const client = new ApiClient(network);
    await expect(client.login('operator', 'password')).resolves.toEqual(identity);
    await client.logout();
    expect(sent).toEqual(['fresh-1', 'fresh-2', 'fresh-3']);
    expect(network.mock.calls.every(([url, init]) => String(url).startsWith('/api/v1/') && init?.credentials === 'same-origin')).toBe(true);
    const forbidden = new ApiClient(fetcher((url) => url.pathname.endsWith('/csrf') ? json({ csrf_token: 'x' }) : json({}, 403)));
    await expect(forbidden.login('operator', 'password')).rejects.toMatchObject({ status: 403 });
  });
  it('invalidates outstanding successful responses after a protected 401', async () => {
    const late = deferred<Response>();
    const client = new ApiClient(fetcher((url) => url.pathname.endsWith('/overview') ? late.promise : json({}, 401)));
    const expired = vi.fn(); client.onUnauthorized(expired);
    const pending = client.overview();
    void pending.catch(() => {});
    await expect(client.events({})).rejects.toBeInstanceOf(ApiError);
    late.resolve(json(overview));
    await expect(pending).rejects.toBeInstanceOf(StaleRequestError);
    expect(expired).toHaveBeenCalledOnce();
  });
  it('keeps in-flight reads usable if logout fails, then discards them after successful logout', async () => {
    const late = deferred<Response>();
    let fail = true;
    const client = new ApiClient(fetcher((url) => {
      if (url.pathname.endsWith('/overview')) return late.promise;
      if (url.pathname.endsWith('/csrf')) return json({ csrf_token: 'fresh' });
      if (fail) throw new TypeError('offline');
      return json({ logged_out: true });
    }));
    const pending = client.overview(); void pending.catch(() => {});
    await expect(client.logout()).rejects.toThrow();
    late.resolve(json(overview));
    await expect(pending).resolves.toEqual(overview);
    fail = false;
    const delayedBody = deferred<unknown>();
    const second = new ApiClient(fetcher((url) => url.pathname.endsWith('/overview')
      ? { ok: true, json: () => delayedBody.promise } as Response
      : url.pathname.endsWith('/csrf') ? json({ csrf_token: 'fresh' }) : json({ logged_out: true })));
    const old = second.overview(); void old.catch(() => {});
    await second.logout();
    delayedBody.resolve(overview);
    await expect(old).rejects.toBeInstanceOf(StaleRequestError);
  });
  it('invalidates an old identity lookup when a newer login begins', async () => {
    const late = deferred<Response>();
    const client = new ApiClient(fetcher((url) => url.pathname.endsWith('/me') ? late.promise : url.pathname.endsWith('/csrf') ? json({ csrf_token: 'fresh' }) : json({ admin: identity, csrf_token: 'rotated' })));
    const pending = client.me();
    void pending.catch(() => {});
    await client.login('operator', 'password');
    late.resolve(json({ ...identity, username: 'stale' }));
    await expect(pending).rejects.toBeInstanceOf(StaleRequestError);
  });
});
