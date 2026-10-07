import { ZegaError } from '@zegadb/lib/client';

export type User = { uid: string; email: string; emailVerified: boolean; isAnonymous: boolean; providers?: string[]; aal?: number };
export type Session = { access_token: string; refresh_token: string; expires_in: number; token_type: 'bearer'; user: User; expires_at?: number };
export type AuthEvent = 'SIGNED_IN' | 'SIGNED_OUT' | 'TOKEN_REFRESHED' | 'USER_UPDATED';
const ZegaErrorBase = ZegaError as unknown as new (
  code: string,
  message: string,
  details?: { status?: number; serverCode?: string; retryAfter?: number },
) => Error & { code: string; status: number; retryAfter?: number };
export class ZegaAuthError extends ZegaErrorBase {
  constructor(code: string, message: string, details: { status?: number; retryAfter?: number } = {}) {
    super(code, message, { ...details, serverCode: code });
    this.name = 'ZegaAuthError';
  }
}
export interface AuthConfig { url: string; publishableKey: string; storage?: Storage; fetch?: typeof fetch }
export interface Storage { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void }
const STORAGE_KEY = 'zega.auth.session';
const base64url = (s: string) => Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));

export function createAuth(config: AuthConfig) {
  if (!/^https?:\/\//.test(config.url) || !/^zp_[123456789abcdefghjkmnpqrstuvwxyz]{32}$/.test(config.publishableKey)) throw new ZegaAuthError('config', 'createAuth requires a graph URL and a zp_ publishable key.');
  const fetcher = config.fetch ?? fetch;
  const storage = config.storage ?? (typeof localStorage === 'undefined' ? memoryStorage() : localStorage);
  const listeners = new Set<(event: AuthEvent, session: Session | null) => void>();
  let refreshPromise: Promise<Session | null> | null = null;
  const endpoint = (path: string) => `${config.url.replace(/\/$/, '')}/auth/v1/${path}`;
  const current = (): Session | null => { try { const raw = storage.getItem(STORAGE_KEY); return raw ? JSON.parse(raw) as Session : null; } catch { return null; } };
  const save = (session: Session | null, event: AuthEvent) => {
    if (session) storage.setItem(STORAGE_KEY, JSON.stringify(session)); else storage.removeItem(STORAGE_KEY);
    for (const listener of listeners) listener(event, session);
  };
  async function request(path: string, body?: unknown, token?: string, method = body === undefined ? 'GET' : 'POST'): Promise<any> {
    const response = await fetcher(endpoint(path), { method, headers: { authorization: `Bearer ${token ?? config.publishableKey}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const data = await response.json().catch(() => ({})) as any;
    if (!response.ok) throw new ZegaAuthError(data.error?.code ?? 'auth_error', data.error?.message ?? 'Authentication request failed.', { status: response.status, retryAfter: data.error?.retryAfter });
    return data;
  }
  async function refreshSession(): Promise<Session | null> {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const old = current(); if (!old?.refresh_token) return null;
      try {
        const next = await request('token', { grant_type: 'refresh_token', refresh_token: old.refresh_token });
        const session = { ...next, expires_at: Math.floor(Date.now() / 1000) + next.expires_in } as Session;
        save(session, 'TOKEN_REFRESHED'); return session;
      } catch { save(null, 'SIGNED_OUT'); return null; }
    })();
    try { return await refreshPromise; } finally { refreshPromise = null; }
  }
  async function getSession(): Promise<Session | null> {
    const session = current(); if (!session) return null;
    if (session.expires_at && session.expires_at < Date.now() / 1000 + 30) return refreshSession();
    return session;
  }
  const auth = {
    async signUp(options: { email: string; password: string; data?: Record<string, unknown>; redirectTo?: string }) {
      const result = await request('signup', { email: options.email, password: options.password, data: options.data, redirectTo: options.redirectTo });
      const session = result.session ? { ...result.session, expires_at: Date.now() / 1000 + result.session.expires_in } as Session : null;
      if (session) save(session, 'SIGNED_IN'); return { user: result.user as User | null, session };
    },
    async signInWithPassword(options: { email: string; password: string }) {
      const result = await request('token', { grant_type: 'password', email: options.email, password: options.password });
      const session = { ...result, expires_at: Math.floor(Date.now() / 1000) + result.expires_in } as Session;
      save(session, 'SIGNED_IN'); return { user: session.user, session };
    },
    async signInWithOtp(options: { email: string; redirectTo?: string }) { return request('magiclink', { email: options.email, redirectTo: options.redirectTo }); },
    async verifyOtp(options: { email?: string; token?: string; code?: string; type?: 'email' | 'recovery' }) {
      const result = await request('verify', { email: options.email, token: options.token ?? options.code });
      const session = { ...result, expires_at: Math.floor(Date.now() / 1000) + result.expires_in } as Session;
      save(session, 'SIGNED_IN'); return { user: session.user, session };
    },
    async signOut(options: { scope?: 'local' | 'global' | 'others' } = {}) {
      const session = current();
      const scope = options.scope ?? 'local';
      try {
        if (session) await request('logout', { refresh_token: session.refresh_token, scope }, session.access_token);
      } finally {
        if (scope !== 'others') save(null, 'SIGNED_OUT');
      }
    },
    async getUser(options: { verify?: 'local' | 'server' } = {}): Promise<User | null> {
      const session = await getSession(); if (!session) return null;
      if (options.verify === 'server') {
        try { return (await request('user', undefined, session.access_token)).user as User; }
        catch { return null; }
      }
      const claims = await verifyJwt(session.access_token, config.url, fetcher, config.publishableKey);
      return claims ? session.user : null;
    },
    getSession,
    refreshSession,
    onAuthStateChange(callback: (event: AuthEvent, session: Session | null) => void) { listeners.add(callback); return { data: { subscription: { unsubscribe: () => listeners.delete(callback) } } }; },
    async resetPasswordForEmail(email: string, options: { redirectTo?: string } = {}) { return request('recover', { email, redirectTo: options.redirectTo }); },
    async updateUser(attributes: { password?: string; data?: Record<string, unknown> }) {
      const session = await getSession(); if (!session) throw new ZegaAuthError('session_expired', 'Sign in again to update your account.', { status: 401 });
      const result = await request('user', attributes, session.access_token, 'PUT'); listeners.forEach(cb => cb('USER_UPDATED', session)); return result;
    },
    async graph(options: { schema?: string } = {}) {
      const session = await getSession();
      const { connect } = await import('@zegadb/lib/client');
      return connect({ url: config.url, key: async () => (await getSession())?.access_token ?? config.publishableKey, schema: options.schema });
    },
    key: async () => (await getSession())?.access_token ?? config.publishableKey,
  };
  return auth;
}

function memoryStorage(): Storage { const values = new Map<string, string>(); return { getItem: k => values.get(k) ?? null, setItem: (k, v) => { values.set(k, v); }, removeItem: k => { values.delete(k); } }; }
async function verifyJwt(token: string, url: string, fetcher: typeof fetch, publishableKey: string): Promise<Record<string, unknown> | null> {
  const [head, body, sig] = token.split('.'); if (!head || !body || !sig) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(base64url(head))) as { kid: string; alg: string };
    const claims = JSON.parse(new TextDecoder().decode(base64url(body))) as Record<string, any>;
    if (header.alg !== 'ES256' || claims.exp <= Date.now() / 1000 || claims.iss !== `${url.replace(/\/$/, '')}/auth/v1`) return null;
    const response = await fetcher(`${url.replace(/\/$/, '')}/auth/v1/.well-known/jwks.json`, { headers: { authorization: `Bearer ${publishableKey}` } });
    const keys = (await response.json() as { keys: JsonWebKey[] }).keys;
    const jwk = keys.find(key => (key as JsonWebKey & { kid?: string }).kid === header.kid); if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, base64url(sig), new TextEncoder().encode(`${head}.${body}`));
    return ok ? claims : null;
  } catch { return null; }
}
