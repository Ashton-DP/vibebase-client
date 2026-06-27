/**
 * Vibebase Browser SDK
 * Usage:
 *   import { createBrowserClient } from 'vibebase-client/browser.mjs';
 *   const vb = createBrowserClient('https://vibebase.io', 'curly-butterfly-57402810', 'vbpk_...');
 *   const rows = await vb.from('courses').select();
 *   const { user, token } = await vb.auth.signIn('a@b.com', 'secret');
 */
export function createBrowserClient(baseUrl, ref, publishableKey) {
  let _token = null;

  function headers(extra = {}) {
    return {
      apikey: publishableKey,
      'content-type': 'application/json',
      ...(_token ? { authorization: `Bearer ${_token}` } : {}),
      ...extra,
    };
  }

  async function request(method, url, body) {
    const opts = { method, headers: headers() };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(data?.error || `HTTP ${res.status}`), { status: res.status, data });
    return data;
  }

  function restUrl(table, params) {
    const u = `${baseUrl}/rest/${ref}/${table}`;
    if (!params || !Object.keys(params).length) return u;
    return u + '?' + new URLSearchParams(params).toString();
  }

  function authUrl(action) {
    return `${baseUrl}/auth/${ref}/${action}`;
  }

  function from(table) {
    return {
      /** GET rows. Pass { col: val } filters, select: 'col1,col2', limit: n */
      select: (params = {}) => request('GET', restUrl(table, params)),
      /** POST a new row. Returns the inserted row. */
      insert: (data) => request('POST', restUrl(table), data),
      /** PATCH rows matching filter params with `data`. */
      update: (data, params = {}) => request('PATCH', restUrl(table, params), data),
      /** DELETE rows matching filter params. */
      delete: (params = {}) => request('DELETE', restUrl(table, params)),
    };
  }

  const auth = {
    /** Create a new user. Stores the session token. Returns { user, token }. */
    async signUp(email, password) {
      const res = await request('POST', authUrl('signup'), { email, password });
      _token = res.token;
      return res;
    },
    /** Sign in with email + password. Stores the session token. Returns { user, token }. */
    async signIn(email, password) {
      const res = await request('POST', authUrl('signin'), { email, password });
      _token = res.token;
      return res;
    },
    /** Get the current user (uses stored token). Returns { user } or throws 401. */
    async getUser() {
      return request('GET', authUrl('user'));
    },
    /** Sign out (revokes the current session token). */
    async signOut() {
      const res = await request('POST', authUrl('signout'));
      _token = null;
      return res;
    },
    /** Manually set a token (e.g. from sessionStorage on page reload). */
    setToken(token) { _token = token; },
    /** Get the current in-memory token (persist it yourself if needed). */
    getToken() { return _token; },
  };

  return { from, auth };
}
