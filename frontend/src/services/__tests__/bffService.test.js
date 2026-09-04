import { beforeEach, describe, expect, it, vi } from 'vitest';

import { authenticatedFetch, bffAuth, getCsrfToken } from '../bffService';


describe('BFF authentication service', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    document.cookie = 'csrf_token=; Max-Age=0; Path=/';
  });

  it('uses cookie credentials and CSRF without a bearer token', async () => {
    document.cookie = 'csrf_token=csrf-value; Path=/';
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));

    await authenticatedFetch('/admin/actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    expect(fetchMock).toHaveBeenCalledWith('/admin/actions', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'csrf-value',
      },
    });
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBeUndefined();
  });

  it('does not manufacture a CSRF header when the cookie is absent', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));

    await authenticatedFetch('/dashboard/profile');

    expect(fetchMock.mock.calls[0][1]).toEqual({ credentials: 'include', headers: {} });
    expect(getCsrfToken()).toBeNull();
  });

  it('logs in without returning or persisting browser-readable tokens', async () => {
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ authenticated: true, user: { id: 'user-1', is_admin: false } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await bffAuth.login('user@example.com', 'password', 'user', true);

    expect(result).toEqual({ authenticated: true, user: { id: 'user-1', is_admin: false } });
    expect(storageSpy).not.toHaveBeenCalled();
    const [, options] = fetchMock.mock.calls[0];
    expect(options.credentials).toBe('include');
    expect(options.body).not.toContain('access_token');
    expect(options.body).not.toContain('refresh_token');
  });
});
