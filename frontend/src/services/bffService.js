const API_URL = import.meta.env.VITE_API_URL || '';

export function getCsrfToken() {
  const entry = document.cookie
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith('csrf_token='));
  return entry ? decodeURIComponent(entry.slice('csrf_token='.length)) : null;
}

export function csrfHeaders(headers = {}) {
  const csrfToken = getCsrfToken();
  return csrfToken ? { ...headers, 'X-CSRF-Token': csrfToken } : headers;
}

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    credentials: 'include',
    ...options,
    headers: csrfHeaders({
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.detail || body.message || 'Request failed');
    error.status = response.status;
    throw error;
  }
  return body;
}

export function authenticatedFetch(url, options = {}) {
  return fetch(url, {
    credentials: 'include',
    ...options,
    headers: csrfHeaders(options.headers || {}),
  });
}

export class BFFAuthService {
  login(email, password, portal = 'user', rememberMe = false) {
    return request('/bff/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, portal, remember_me: rememberMe }),
    });
  }

  getCurrentUser() {
    return request('/bff/me');
  }

  getSessionStatus() {
    return request('/bff/session-status').catch(() => ({ authenticated: false }));
  }

  refreshToken() {
    return request('/bff/refresh', { method: 'POST' });
  }

  logout() {
    return request('/bff/logout', { method: 'POST' });
  }
}

export const bffAuth = new BFFAuthService();
export default bffAuth;
