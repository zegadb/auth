import { argon2id, setWASMModules } from 'argon2-wasm-edge';
// @ts-expect-error Wrangler imports these as compiled WebAssembly modules.
import argon2WASM from 'argon2-wasm-edge/wasm/argon2.wasm';
// @ts-expect-error Wrangler imports these as compiled WebAssembly modules.
import blake2bWASM from 'argon2-wasm-edge/wasm/blake2b.wasm';

interface Db {
  prepare(sql: string): any;
  batch(statements: any[]): Promise<any>;
}
/** Every tenant D1 statement must explicitly carry the scoped project column. */
class ProjectScope {
  constructor(private readonly db: Db, readonly projectId: string) {}
  prepare(sql: string): any {
    if (!/\bproject_id\b/i.test(sql)) throw new Error('ProjectScope refuses SQL without project_id');
    return this.db.prepare(sql);
  }
  batch(statements: any[]): Promise<any> { return this.db.batch(statements); }
}
interface Env {
  AUTH_DB: Db;
  AUTH_RATES: DurableObjectNamespace;
  GATE_CONTEXT_SECRET: string;
  KEY_SEALING_KEY: string;
  RESEND_API_KEY: string;
  RESEND_API_ORIGIN?: string;
  EMAIL_FROM?: string;
  ALLOW_UNSIGNED_GATE_CONTEXT?: string;
}
type Project = { project_id: string; graph_id: string; enabled: number; allow_signups: number; confirm_email: number; strict_sessions: number; site_url: string; redirect_allowlist: string; jwt_seconds: number };
const encoder = new TextEncoder();
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
const hex = (v: Uint8Array) => Array.from(v, x => x.toString(16).padStart(2, '0')).join('');
const unhex = (v: string) => Uint8Array.from(v.match(/.{2}/g) ?? [], x => parseInt(x, 16));
const b64url = (v: Uint8Array) => btoa(String.fromCharCode(...v)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const fromB64url = (v: string) => Uint8Array.from(atob(v.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const asBuffer = (v: Uint8Array): ArrayBuffer => Uint8Array.from(v).buffer;
const random = (n = 32) => { const b = crypto.getRandomValues(new Uint8Array(n)); return b64url(b); };
function randomBase32(length: number): string {
  const alphabet = '123456789abcdefghjkmnpqrstuvwxyz';
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(length * 5 / 8)));
  let bits = 0; let value = 0; let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5 && out.length < length) { bits -= 5; out += alphabet[(value >>> bits) & 31]; value &= (1 << bits) - 1; }
  }
  return out;
}
const publishable = () => `zp_${randomBase32(32)}`;
async function sha(value: string): Promise<string> { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))); }
async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value))));
}
async function gateClaims(request: Request, env: Env): Promise<{ projectId: string; graphId: string } | Response> {
  const projectId = request.headers.get('x-zega-project');
  const graphId = request.headers.get('x-zega-graph');
  if (!projectId || !graphId) return json({ error: { code: 'unauthorized', message: 'Missing gate context.' } }, 401);
  if (env.ALLOW_UNSIGNED_GATE_CONTEXT !== 'true') {
    const issued = request.headers.get('x-zega-gate-time') ?? '';
    const signature = request.headers.get('x-zega-gate-signature') ?? '';
    const timestamp = Number(issued);
    if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > 30_000 || !signature) return json({ error: { code: 'unauthorized', message: 'Invalid gate context.' } }, 401);
    const expected = await hmac(env.GATE_CONTEXT_SECRET, `${projectId}\n${graphId}\n${issued}`);
    if (expected !== signature) return json({ error: { code: 'unauthorized', message: 'Invalid gate context.' } }, 401);
  }
  return { projectId, graphId };
}
async function gateProject(request: Request, env: Env, claims?: { projectId: string; graphId: string }): Promise<{ project: Project; graph: string } | Response> {
  if (!claims) {
    const resolved = await gateClaims(request, env);
    if (resolved instanceof Response) return resolved;
    claims = resolved;
  }
  const scope = new ProjectScope(env.AUTH_DB, claims.projectId);
  const project = await scope.prepare('SELECT * FROM auth_projects WHERE project_id = ? AND graph_id = ?').bind(scope.projectId, claims.graphId).first() as Project | null;
  if (!project || !project.enabled) return json({ error: { code: 'auth_not_enabled', message: 'Authentication is not enabled.' } }, 404);
  return { project, graph: claims.graphId };
}
function redirectAllowed(project: Project, value: unknown): string | null {
  const candidate = typeof value === 'string' ? value : project.site_url;
  let target: URL;
  try { target = new URL(candidate); } catch { return null; }
  if (target.username || target.password || target.hash) return null;
  const rules = JSON.parse(project.redirect_allowlist) as string[];
  const allowed = [project.site_url, ...rules].some(rule => {
    try {
      if (!rule.includes('*')) { const exact = new URL(rule); return exact.origin === target.origin && exact.pathname === target.pathname; }
      const match = rule.match(/^(https?):\/\/(.+?)(\/.*)?$/); if (!match) return false;
      const host = match[2]!; const path = match[3] ?? '/';
      if (host.includes('**') || host.split('.').some(label => label === '*')) return false;
      const escape = (s: string) => s.replace(/[\\^$+?.()|{}\[\]]/g, '\\$&');
      const hostPattern = `^${host.split('*').map(escape).join('[a-zA-Z0-9-]+')}$`;
      const pathPattern = `^${escape(path.replaceAll('**', '\u0000').replaceAll('*', '\u0001')).replaceAll('\u0000', '.*').replaceAll('\u0001', '[^/]*')}$`;
      return target.protocol === `${match[1]}:` && new RegExp(hostPattern).test(target.hostname) && new RegExp(pathPattern).test(target.pathname);
    } catch { return false; }
  });
  return allowed ? target.href : null;
}
function corsOriginAllowed(project: Project, value: string): boolean {
  let origin: URL;
  try { origin = new URL(value); if (origin.origin !== value || origin.username || origin.password) return false; } catch { return false; }
  const rules = [project.site_url, ...JSON.parse(project.redirect_allowlist) as string[]];
  return rules.some(rule => {
    try {
      const match = rule.match(/^(https?):\/\/([^/]+)(?:\/.*)?$/); if (!match || match[2]!.includes('**')) return false;
      const host = match[2]!;
      const escape = (s: string) => s.replace(/[\\^$+?.()|{}\[\]]/g, '\\$&');
      const hostname = host.includes('*') ? new RegExp(`^${host.split('*').map(escape).join('[a-zA-Z0-9-]+')}$`).test(origin.hostname) : host === origin.hostname;
      return origin.protocol === `${match[1]}:` && hostname;
    } catch { return false; }
  });
}
function withCors(response: Response, project: Project, origin: string | null): Response {
  const headers = new Headers(response.headers);
  if (origin && corsOriginAllowed(project, origin)) {
    headers.set('access-control-allow-origin', origin);
    headers.set('access-control-allow-methods', 'GET, POST, PUT, OPTIONS');
    headers.set('access-control-allow-headers', 'Authorization, Content-Type');
    headers.set('access-control-max-age', '600');
    headers.append('vary', 'Origin');
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
async function rate(env: Env, project: string, bucket: string, max: number, windowSeconds: number): Promise<boolean> {
  try {
    const object = env.AUTH_RATES.get(env.AUTH_RATES.idFromName(`${project}:${bucket}`));
    const response = await object.fetch('https://auth-rate-limit/check', { method: 'POST', body: JSON.stringify({ max, windowSeconds }) });
    if (!response.ok) return false;
    return (await response.json() as { allowed: boolean }).allowed;
  } catch { return false; }
}
function ip(request: Request): string { return request.headers.get('cf-connecting-ip') ?? 'unknown'; }
const ARGON2_OPTIONS = { iterations: 2, memorySize: 19_456, parallelism: 1, hashLength: 32, outputType: 'encoded' as const };
async function hashPassword(password: string): Promise<{ alg: string; parameters: string; salt: string; verifier: string }> {
  await setWASMModules({ argon2WASM, blake2bWASM });
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const start = performance.now();
  const verifier = await argon2id({ password, salt, ...ARGON2_OPTIONS });
  const elapsed = performance.now() - start;
  return { alg: 'argon2id', parameters: JSON.stringify({ memoryKiB: ARGON2_OPTIONS.memorySize, iterations: ARGON2_OPTIONS.iterations, parallelism: ARGON2_OPTIONS.parallelism, hashLength: ARGON2_OPTIONS.hashLength, cpuMs: Math.round(elapsed * 100) / 100 }), salt: hex(salt), verifier };
}
async function verifyPassword(password: string, row: { salt: string; verifier: string; alg: string; parameters: string } | null): Promise<boolean> {
  await setWASMModules({ argon2WASM, blake2bWASM });
  const usable = row && row.alg === 'argon2id' && /^\$argon2id\$/.test(row.verifier) && /^[0-9a-f]{32}$/.test(row.salt);
  const credential = usable ? row : null;
  const salt = credential ? unhex(credential.salt) : crypto.getRandomValues(new Uint8Array(16));
  const calculated = await argon2id({ password, salt, ...ARGON2_OPTIONS });
  if (!credential) return false;
  const left = encoder.encode(calculated); const right = encoder.encode(credential.verifier);
  let difference = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) difference |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return difference === 0;
}
async function verifyAccessToken(env: Env, project: Project, token: string, requestOrigin: string): Promise<boolean> {
  const [head, body, sig] = token.split('.'); if (!head || !body || !sig) return false;
  try {
    const header = JSON.parse(new TextDecoder().decode(fromB64url(head))) as { kid: string; alg: string };
    const claims = JSON.parse(new TextDecoder().decode(fromB64url(body))) as { iss: string; exp: number; sid: string; sub: string };
    if (header.alg !== 'ES256' || claims.iss !== `${requestOrigin}/auth/v1` || claims.exp <= Date.now()/1000) return false;
    const scope = new ProjectScope(env.AUTH_DB, project.project_id);
    const row = await scope.prepare('SELECT public_jwk FROM auth_keys_signing WHERE project_id=? AND kid=?').bind(scope.projectId, header.kid).first() as { public_jwk: string } | null;
    if (!row) return false;
    const key = await crypto.subtle.importKey('jwk', JSON.parse(row.public_jwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, asBuffer(fromB64url(sig)), encoder.encode(`${head}.${body}`));
    if (!valid) return false;
    if (project.strict_sessions) {
      const session = await scope.prepare('SELECT 1 AS active FROM auth_sessions s JOIN auth_users u ON u.project_id=s.project_id AND u.uid=s.uid WHERE s.project_id=? AND s.sid=? AND s.uid=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status="active"').bind(scope.projectId, claims.sid, claims.sub, Math.floor(Date.now()/1000)).first();
      if (!session) return false;
    }
    return true;
  } catch { return false; }
}
async function sealingKey(env: Env): Promise<CryptoKey> {
  if (!env.KEY_SEALING_KEY || env.KEY_SEALING_KEY.length < 32) throw new Error('KEY_SEALING_KEY must be set as a Worker secret');
  const raw = await crypto.subtle.digest('SHA-256', encoder.encode(env.KEY_SEALING_KEY));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(env: Env, value: Uint8Array): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await sealingKey(env), asBuffer(value));
  return `${b64url(nonce)}.${b64url(new Uint8Array(encrypted))}`;
}
async function unseal(env: Env, value: string): Promise<Uint8Array> {
  const [nonce, ciphertext] = value.split('.');
  if (!nonce || !ciphertext) throw new Error('invalid sealed key');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: asBuffer(fromB64url(nonce)) }, await sealingKey(env), asBuffer(fromB64url(ciphertext))));
}
async function signingKey(env: Env, project: Project) {
  const scope = new ProjectScope(env.AUTH_DB, project.project_id);
  let row = await scope.prepare('SELECT kid, public_jwk, private_sealed FROM auth_keys_signing WHERE project_id = ? ORDER BY created_at DESC LIMIT 1').bind(scope.projectId).first() as { kid: string; public_jwk: string; private_sealed: string } | null;
  if (!row) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const [pub, priv] = await Promise.all([crypto.subtle.exportKey('jwk', pair.publicKey), crypto.subtle.exportKey('pkcs8', pair.privateKey)]);
    const kid = random(9);
    row = { kid, public_jwk: JSON.stringify({ ...pub, kid, alg: 'ES256', use: 'sig' }), private_sealed: await seal(env, new Uint8Array(priv)) };
    await scope.prepare('INSERT INTO auth_keys_signing (project_id,kid,public_jwk,private_sealed,created_at) VALUES (?,?,?,?,?)').bind(scope.projectId, row.kid, row.public_jwk, row.private_sealed, Math.floor(Date.now() / 1000)).run();
  }
  const privateKey = await crypto.subtle.importKey('pkcs8', asBuffer(await unseal(env, row.private_sealed)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return { kid: row.kid, publicJwk: JSON.parse(row.public_jwk), privateKey };
}
async function accessToken(env: Env, project: Project, user: { uid: string; email: string; email_verified: number }, sid: string, issuer: string): Promise<string> {
  const key = await signingKey(env, project);
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(encoder.encode(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: key.kid })));
  const claims = b64url(encoder.encode(JSON.stringify({ iss: `${issuer}/auth/v1`, sub: user.uid, aud: 'authenticated', exp: now + project.jwt_seconds, iat: now, sid, email: user.email, emailVerified: !!user.email_verified, isAnonymous: false, aal: 1, amr: ['password'] })));
  const content = `${head}.${claims}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, encoder.encode(content));
  return `${content}.${b64url(new Uint8Array(sig))}`;
}
async function startSession(env: Env, project: Project, user: { uid: string; email: string; email_verified: number }, issuer: string) {
  const scope = new ProjectScope(env.AUTH_DB, project.project_id);
  const sid = random(18);
  const refresh = `zr_${randomBase32(32)}`;
  const hash = await hmac(env.GATE_CONTEXT_SECRET, refresh);
  const now = Math.floor(Date.now() / 1000);
  await scope.batch([
    scope.prepare('INSERT INTO auth_sessions(project_id,sid,uid,created_at,expires_at) VALUES (?,?,?,?,?)').bind(scope.projectId, sid, user.uid, now, now + 90 * 86400),
    scope.prepare('INSERT INTO auth_refresh_tokens(project_id,token_hash,sid,issued_at) VALUES (?,?,?,?)').bind(scope.projectId, hash, sid, now),
  ]);
  return { access_token: await accessToken(env, project, user, sid, issuer), refresh_token: refresh, expires_in: project.jwt_seconds, token_type: 'bearer', user: { uid: user.uid, email: user.email, emailVerified: !!user.email_verified } };
}
async function sendEmail(env: Env, project: Project, to: string, subject: string, html: string): Promise<boolean> {
  const scope = new ProjectScope(env.AUTH_DB, project.project_id);
  if (!env.RESEND_API_KEY) throw new Error('RESEND_API_KEY is not configured');
  const day = new Date().toISOString().slice(0, 10);
  const reservation = await scope.prepare('INSERT INTO auth_email_daily(project_id,day,sent) VALUES (?,?,1) ON CONFLICT(project_id,day) DO UPDATE SET sent=sent+1 WHERE sent<100').bind(scope.projectId, day).run();
  if (Number(reservation.meta?.changes ?? 0) === 0) return false;
  const response = await fetch(`${env.RESEND_API_ORIGIN ?? 'https://api.resend.com'}/emails`, { method: 'POST', headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' }, body: JSON.stringify({ from: env.EMAIL_FROM ?? 'Zega <noreply@auth.zega.dev>', to, subject, html }) });
  return response.ok;
}
async function challenge(env: Env, project: Project, user: { uid: string }, purpose: 'confirm'|'magic'|'reset', redirect: string) {
  const scope = new ProjectScope(env.AUTH_DB, project.project_id);
  const token = random(32); const code = String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0');
  const hash = await hmac(env.GATE_CONTEXT_SECRET, token);
  await scope.prepare('INSERT INTO auth_challenges(project_id,challenge_hash,uid,purpose,code_hash,redirect_to,expires_at) VALUES (?,?,?,?,?,?,?)').bind(scope.projectId, hash, user.uid, purpose, await hmac(env.GATE_CONTEXT_SECRET, code), redirect, Math.floor(Date.now()/1000)+900).run();
  return { token, code };
}
async function route(request: Request, env: Env, project: Project): Promise<Response> {
  const scope = new ProjectScope(env.AUTH_DB, project.project_id);
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/auth\/v1\/?/, '');
  const ipHash = await sha(ip(request));
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (path === '.well-known/jwks.json' && request.method === 'GET') {
    const rows = await scope.prepare('SELECT public_jwk FROM auth_keys_signing WHERE project_id = ?').bind(project.project_id).all() as { results: { public_jwk: string }[] };
    return json({ keys: (rows.results ?? []).map(row => JSON.parse(row.public_jwk)) });
  }
  let input: Record<string, unknown> = {};
  if (request.method === 'POST') {
    const contentType = request.headers.get('content-type') ?? '';
    const body = await request.text();
    if (contentType.includes('application/x-www-form-urlencoded')) input = Object.fromEntries(new URLSearchParams(body).entries());
    else { try { input = JSON.parse(body) as Record<string, unknown>; } catch { /* invalid JSON remains an empty input */ } }
  }
  const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
  if (path === 'signup' && request.method === 'POST') {
    if (!project.allow_signups) return json({ error: { code: 'signups_disabled' } }, 403);
    if (!await rate(env, project.project_id, `signup:${ipHash}`, 10, 3600)) return json({ error: { code: 'rate_limited', retryAfter: 3600 } }, 429);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof input.password !== 'string' || input.password.length < 10) return json({ error: { code: 'weak_password' } }, 400);
    const exists = await scope.prepare('SELECT uid FROM auth_users WHERE project_id = ? AND email = ?').bind(project.project_id, email).first();
    if (exists) return json({ user: null, session: null, message: 'Check your email to continue.' }, 200);
    const uid = `a_${randomBase32(18)}`; const now = Math.floor(Date.now()/1000); const verifier = await hashPassword(input.password);
    await scope.batch([
      scope.prepare('INSERT INTO auth_users(project_id,uid,email,created_at) VALUES (?,?,?,?)').bind(project.project_id, uid, email, now),
      scope.prepare('INSERT INTO auth_credentials(project_id,uid,alg,parameters,salt,verifier) VALUES (?,?,?,?,?,?)').bind(project.project_id, uid, verifier.alg, verifier.parameters, verifier.salt, verifier.verifier),
    ]);
    let session = null;
    if (project.confirm_email) {
      const redirect = redirectAllowed(project, input.redirectTo);
      if (!redirect) return json({ error: { code: 'redirect_not_allowed' } }, 400);
      const c = await challenge(env, project, { uid }, 'confirm', redirect);
      const link = `${url.origin}/auth/v1/confirm?token=${encodeURIComponent(c.token)}`;
      const sent = await sendEmail(env, project, email, 'Confirm your email', `<p>Confirm your email for Zega.</p><p><a href="${link}">Confirm email</a></p>`);
      if (!sent) return json({ error: { code: 'email_allowance_exhausted' } }, 429);
    } else session = await startSession(env, project, { uid, email, email_verified: 0 }, url.origin);
    return json({ user: { uid, email, emailVerified: false }, session, message: project.confirm_email ? 'Check your email to continue.' : undefined }, 201);
  }
  if (path === 'token' && request.method === 'POST' && input.grant_type === 'password') {
    const emailLimit = await rate(env, project.project_id, `signin:email:${await sha(email)}`, 5, 900);
    const ipLimit = await rate(env, project.project_id, `signin:ip:${ipHash}`, 30, 900);
    if (!emailLimit || !ipLimit) return json({ error: { code: 'rate_limited', retryAfter: 900 } }, 429);
    const user = await scope.prepare('SELECT * FROM auth_users WHERE project_id = ? AND email = ?').bind(project.project_id, email).first() as { uid: string; email: string; email_verified: number; status: string } | null;
    const credential = user ? await scope.prepare('SELECT alg,parameters,salt,verifier FROM auth_credentials WHERE project_id = ? AND uid = ?').bind(project.project_id, user.uid).first() : null;
    const valid = await verifyPassword(String(input.password ?? ''), credential);
    if (!user || !valid || user.status === 'banned') return json({ error: { code: user?.status === 'banned' ? 'user_banned' : 'invalid_credentials' } }, 401);
    if (project.confirm_email && !user.email_verified) return json({ error: { code: 'email_not_confirmed' } }, 403);
    await scope.prepare('UPDATE auth_users SET last_sign_in = ? WHERE project_id = ? AND uid = ?').bind(Math.floor(Date.now()/1000), project.project_id, user.uid).run();
    return json(await startSession(env, project, user, url.origin));
  }
  if (path === 'token' && request.method === 'POST' && input.grant_type === 'refresh_token') {
    if (!await rate(env, project.project_id, `refresh:${ipHash}`, 150, 300)) return json({ error: { code: 'rate_limited', retryAfter: 300 } }, 429);
    const token = typeof input.refresh_token === 'string' ? input.refresh_token : '';
    const hash = await hmac(env.GATE_CONTEXT_SECRET, token);
    const row = await scope.prepare('SELECT r.*,s.uid,s.revoked_at,s.expires_at,u.email,u.email_verified,u.status FROM auth_refresh_tokens r JOIN auth_sessions s ON s.project_id=r.project_id AND s.sid=r.sid JOIN auth_users u ON u.project_id=s.project_id AND u.uid=s.uid WHERE r.project_id=? AND r.token_hash=?').bind(project.project_id, hash).first() as any;
    if (!row) return json({ error: { code: 'session_expired' } }, 401);
    if (row.used_at !== null) {
      const now = Math.floor(Date.now()/1000);
      if (now - row.used_at > 10) await scope.prepare('UPDATE auth_sessions SET revoked_at=? WHERE project_id=? AND sid=? AND revoked_at IS NULL').bind(now, project.project_id, row.sid).run();
      return json({ error: { code: 'session_expired', reason: 'refresh_reuse_detected' } }, 401);
    }
    if (row.revoked_at !== null || row.expires_at < Date.now()/1000 || row.status !== 'active') return json({ error: { code: 'session_expired' } }, 401);
    const next = `zr_${randomBase32(32)}`; const nextHash = await hmac(env.GATE_CONTEXT_SECRET, next); const now = Math.floor(Date.now()/1000);
    const rotation = await scope.batch([
      scope.prepare('UPDATE auth_refresh_tokens SET used_at=? WHERE project_id=? AND token_hash=? AND used_at IS NULL').bind(now, project.project_id, hash),
      scope.prepare('INSERT INTO auth_refresh_tokens(project_id,token_hash,sid,parent_hash,issued_at) SELECT project_id, ?, sid, token_hash, ? FROM auth_refresh_tokens WHERE project_id=? AND token_hash=? AND used_at=? AND changes()=1').bind(nextHash, now, project.project_id, hash, now),
    ]);
    if (Number(rotation[1]?.meta?.changes ?? 0) !== 1) return json({ error: { code: 'session_expired' } }, 401);
    const session = await accessToken(env, project, row, row.sid, url.origin);
    return json({ access_token: session, refresh_token: next, expires_in: project.jwt_seconds, token_type: 'bearer', user: { uid: row.uid, email: row.email, emailVerified: !!row.email_verified } });
  }
  if (path === 'logout' && request.method === 'POST') {
    const token = typeof input.refresh_token === 'string' ? input.refresh_token : '';
    if (token) {
      const row = await scope.prepare('SELECT sid FROM auth_refresh_tokens WHERE project_id=? AND token_hash=?').bind(project.project_id, await hmac(env.GATE_CONTEXT_SECRET, token)).first() as { sid: string } | null;
      const authorization = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
      const [, payload] = authorization.split('.');
      let claims: { sid?: string; sub?: string } = {};
      try { if (payload) claims = JSON.parse(new TextDecoder().decode(fromB64url(payload))); } catch { /* already authenticated above */ }
      const logoutScope = input.scope === 'global' || input.scope === 'others' ? input.scope : 'local';
      if (claims.sub && logoutScope !== 'local') {
        await scope.prepare(logoutScope === 'global'
          ? 'UPDATE auth_sessions SET revoked_at=? WHERE project_id=? AND uid=? AND revoked_at IS NULL'
          : 'UPDATE auth_sessions SET revoked_at=? WHERE project_id=? AND uid=? AND sid<>? AND revoked_at IS NULL')
          .bind(...(logoutScope === 'global' ? [Math.floor(Date.now()/1000), project.project_id, claims.sub] : [Math.floor(Date.now()/1000), project.project_id, claims.sub, claims.sid])).run();
      } else if (row) await scope.prepare('UPDATE auth_sessions SET revoked_at=? WHERE project_id=? AND sid=?').bind(Math.floor(Date.now()/1000), project.project_id, row.sid).run();
    }
    return json({ ok: true });
  }
  if ((path === 'magiclink' || path === 'recover') && request.method === 'POST') {
    const purpose = path === 'recover' ? 'reset' : 'magic';
    const addressHash = await sha(email);
    const allowed = purpose === 'magic'
      ? await rate(env, project.project_id, `${purpose}:minute:${addressHash}`, 1, 60) && await rate(env, project.project_id, `${purpose}:hour:${addressHash}`, 5, 3600)
      : await rate(env, project.project_id, `${purpose}:${addressHash}`, 3, 3600);
    if (!allowed) return json({ error: { code: 'rate_limited', retryAfter: purpose === 'magic' ? 60 : 3600 } }, 429);
    const redirect = redirectAllowed(project, input.redirectTo); if (!redirect) return json({ error: { code: 'redirect_not_allowed' } }, 400);
    const user = await scope.prepare('SELECT uid FROM auth_users WHERE project_id=? AND email=? AND status="active"').bind(project.project_id, email).first() as { uid: string } | null;
    if (user) {
      const c = await challenge(env, project, user, purpose, redirect);
      const link = `${url.origin}/auth/v1/verify?token=${encodeURIComponent(c.token)}`;
      const sent = await sendEmail(env, project, email, purpose === 'reset' ? 'Reset your password' : 'Sign in to Zega', `<p>Your one-time code is <strong>${c.code}</strong>.</p><p><a href="${link}">Continue</a></p>`);
      if (!sent) return json({ error: { code: 'email_allowance_exhausted' } }, 429);
    }
    return json({ message: 'Check your email to continue.' });
  }
  if ((path === 'confirm' || path === 'verify') && request.method === 'GET') {
    const token = url.searchParams.get('token');
    if (!token || !/^[A-Za-z0-9_-]{32,64}$/.test(token)) return json({ error: { code: 'invalid_otp' } }, 400);
    const label = path === 'confirm' ? 'Confirm email' : 'Continue';
    return new Response(`<!doctype html><meta charset="utf-8"><title>${label}</title><form method="post" action="/auth/v1/${path}"><input type="hidden" name="token" value="${token}"><button>${label}</button></form>`, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
  }
  if ((path === 'verify' || path === 'confirm') && request.method === 'POST') {
    const verifyInput = input;
    const code = typeof verifyInput.token === 'string' ? verifyInput.token : '';
    const emailForCode = typeof verifyInput.email === 'string' ? verifyInput.email.trim().toLowerCase() : '';
    if (!await rate(env, project.project_id, `verify:ip:${await sha(ip(request))}`, 30, 900)) return json({ error: { code: 'rate_limited', retryAfter: 900 } }, 429);
    const challengeHash = await hmac(env.GATE_CONTEXT_SECRET, code);
    const row = await scope.prepare('SELECT * FROM auth_challenges WHERE project_id=? AND (challenge_hash=? OR (code_hash IS NOT NULL AND ?<>"" AND uid=(SELECT uid FROM auth_users WHERE project_id=? AND email=?))) AND consumed_at IS NULL AND expires_at>? AND attempts<5 ORDER BY CASE WHEN challenge_hash=? OR code_hash=? THEN 0 ELSE 1 END LIMIT 1').bind(project.project_id, challengeHash, emailForCode, project.project_id, emailForCode, Math.floor(Date.now()/1000), challengeHash, challengeHash).first() as any;
    if (!row) return json({ error: { code: 'invalid_otp' } }, 400);
    if (emailForCode && !await rate(env, project.project_id, `verify:email:${await sha(emailForCode)}`, 5, 900)) return json({ error: { code: 'rate_limited', retryAfter: 900 } }, 429);
    if (row.code_hash && row.code_hash !== challengeHash && row.challenge_hash !== challengeHash) {
      await scope.prepare('UPDATE auth_challenges SET attempts=attempts+1 WHERE project_id=? AND challenge_hash=? AND consumed_at IS NULL AND expires_at>? AND attempts<5').bind(project.project_id, row.challenge_hash, Math.floor(Date.now()/1000)).run();
      return json({ error: { code: 'invalid_otp' } }, 400);
    }
    const consumed = await scope.prepare('UPDATE auth_challenges SET consumed_at=? WHERE project_id=? AND challenge_hash=? AND consumed_at IS NULL AND expires_at>? AND attempts<5').bind(Math.floor(Date.now()/1000), project.project_id, row.challenge_hash, Math.floor(Date.now()/1000)).run();
    if (Number(consumed.meta?.changes ?? 0) !== 1) return json({ error: { code: 'invalid_otp' } }, 400);
    if (row.purpose === 'confirm') await scope.prepare('UPDATE auth_users SET email_verified=1 WHERE project_id=? AND uid=?').bind(project.project_id, row.uid).run();
    if (row.purpose === 'reset') {
      const user = await scope.prepare('SELECT uid,email,email_verified FROM auth_users WHERE project_id=? AND uid=?').bind(project.project_id, row.uid).first() as any;
      return json({ ...(await startSession(env, project, user, url.origin)), redirect_to: row.redirect_to });
    }
    const user = await scope.prepare('SELECT uid,email,email_verified FROM auth_users WHERE project_id=? AND uid=?').bind(project.project_id, row.uid).first() as any;
    return json({ ...(await startSession(env, project, user, url.origin)), redirect_to: row.redirect_to });
  }
  if (path === 'user' && request.method === 'GET') {
    const auth = request.headers.get('authorization')?.replace(/^Bearer /i, '') ?? '';
    const [, payload] = auth.split('.');
    try {
      const claims = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
      const user = await scope.prepare('SELECT u.uid,u.email,u.email_verified,u.status,s.revoked_at,s.expires_at FROM auth_sessions s JOIN auth_users u ON u.project_id=s.project_id AND u.uid=s.uid WHERE s.project_id=? AND s.sid=? AND s.uid=?').bind(project.project_id, claims.sid, claims.sub).first() as any;
      if (!user || user.revoked_at || user.expires_at <= Date.now()/1000 || user.status !== 'active') return json({ error: { code: 'session_expired' } }, 401);
      return json({ user: { uid: user.uid, email: user.email, emailVerified: !!user.email_verified, isAnonymous: false } });
    } catch { return json({ error: { code: 'session_expired' } }, 401); }
  }
  if (path === 'user' && request.method === 'PUT') {
    const auth = request.headers.get('authorization')?.replace(/^Bearer /i, '') ?? '';
    const [, payload] = auth.split('.');
    if (!payload) return json({ error: { code: 'session_expired' } }, 401);
    try {
      const claims = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
      const session = await scope.prepare('SELECT s.revoked_at,u.status FROM auth_sessions s JOIN auth_users u ON u.project_id=s.project_id AND u.uid=s.uid WHERE s.project_id=? AND s.sid=? AND s.uid=?').bind(project.project_id, claims.sid, claims.sub).first() as any;
      if (!session || session.revoked_at || session.status !== 'active') return json({ error: { code: 'session_expired' } }, 401);
      if (typeof input.password === 'string') {
        if (input.password.length < 10) return json({ error: { code: 'weak_password' } }, 400);
        const verifier = await hashPassword(input.password);
        await scope.prepare('UPDATE auth_credentials SET alg=?,parameters=?,salt=?,verifier=? WHERE project_id=? AND uid=?').bind(verifier.alg, verifier.parameters, verifier.salt, verifier.verifier, project.project_id, claims.sub).run();
      }
      return json({ ok: true });
    } catch { return json({ error: { code: 'session_expired' } }, 401); }
  }
  return json({ error: { code: 'not_found', message: 'Unknown auth route.' } }, 404);
}
async function control(request: Request, env: Env, claims: { projectId: string; graphId: string }): Promise<Response> {
  const scope = new ProjectScope(env.AUTH_DB, claims.projectId);
  const path = new URL(request.url).pathname;
  if (request.method !== 'POST') return json({ error: { code: 'not_found' } }, 404);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  if (path === '/auth/v1/control/user') {
    const uid = typeof body.uid === 'string' ? body.uid : '';
    if (!/^a_[A-Za-z0-9_-]{12,32}$/.test(uid) || typeof body.banned !== 'boolean') return json({ error: { code: 'bad_request' } }, 400);
    const now = Math.floor(Date.now()/1000);
    const updated = await scope.prepare('UPDATE auth_users SET status=? WHERE project_id=? AND uid=? AND status<>"deleted"').bind(body.banned ? 'banned' : 'active', claims.projectId, uid).run();
    if (Number(updated.meta?.changes ?? 0) === 0) return json({ error: { code: 'user_not_found' } }, 404);
    if (body.banned) await scope.prepare('UPDATE auth_sessions SET revoked_at=? WHERE project_id=? AND uid=? AND revoked_at IS NULL').bind(now, claims.projectId, uid).run();
    return json({ uid, banned: body.banned });
  }
  if (path !== '/auth/v1/control/enable') return json({ error: { code: 'not_found' } }, 404);
  const site = typeof body.siteUrl === 'string' ? body.siteUrl : '';
  try { const parsed = new URL(site); if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error(); }
  catch { return json({ error: { code: 'invalid_site_url' } }, 400); }
  const redirects = Array.isArray(body.redirectAllowlist) ? body.redirectAllowlist.filter((value): value is string => typeof value === 'string' && value.length <= 2048) : [];
  const confirmEmail = body.confirmEmail === false ? 0 : 1;
  const allowSignups = body.allowSignups === false ? 0 : 1;
  const strictSessions = body.strictSessions === true ? 1 : 0;
  const jwtSeconds = typeof body.jwtSeconds === 'number' && Number.isInteger(body.jwtSeconds) && body.jwtSeconds >= 300 && body.jwtSeconds <= 86400 ? body.jwtSeconds : 3600;
  const now = Math.floor(Date.now()/1000);
  const existing = await scope.prepare('SELECT project_id FROM auth_projects WHERE project_id=?').bind(claims.projectId).first();
  await scope.prepare('INSERT INTO auth_projects(project_id,graph_id,site_url,redirect_allowlist,allow_signups,confirm_email,strict_sessions,jwt_seconds,created_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET graph_id=excluded.graph_id,site_url=excluded.site_url,redirect_allowlist=excluded.redirect_allowlist,allow_signups=excluded.allow_signups,confirm_email=excluded.confirm_email,strict_sessions=excluded.strict_sessions,jwt_seconds=excluded.jwt_seconds').bind(claims.projectId, claims.graphId, site, JSON.stringify(redirects), allowSignups, confirmEmail, strictSessions, jwtSeconds, now).run();
  const activeKey = await scope.prepare('SELECT 1 AS active FROM auth_keys WHERE project_id=? AND kind="publishable" AND revoked_at IS NULL LIMIT 1').bind(claims.projectId).first();
  let key: string | null = null;
  if (!activeKey) {
    key = publishable();
    await scope.prepare('INSERT INTO auth_keys(project_id,key_id,kind,digest,created_at) VALUES (?,?,?,?,?)').bind(claims.projectId, random(9), 'publishable', await hmac(env.GATE_CONTEXT_SECRET, key), now).run();
  }
  return json({ enabled: true, created: !existing, ...(key ? { publishableKey: key, shownOnce: true } : { shownOnce: false }) }, existing ? 200 : 201);
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const claims = await gateClaims(request, env);
    if (claims instanceof Response) return claims;
    if (new URL(request.url).pathname.startsWith('/auth/v1/control/')) return control(request, env, claims);
    const context = await gateProject(request, env, claims);
    if (context instanceof Response) return context;
    const scope = new ProjectScope(env.AUTH_DB, context.project.project_id);
    const authorization = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }), context.project, request.headers.get('origin'));
    const emailChallengeRoute = ['/confirm', '/verify'].some(path => new URL(request.url).pathname.endsWith(path)) && ['GET', 'POST'].includes(request.method);
    if (!authorization && emailChallengeRoute) {
      try { return withCors(await route(request, env, context.project), context.project, request.headers.get('origin')); }
      catch (error) { console.error('zega-auth request failed', error instanceof Error ? error.message : 'unknown'); return json({ error: { code: 'internal_error', message: 'The auth request failed.' } }, 500); }
    }
    if (authorization.startsWith('zk_')) return json({ error: { code: 'key_type_invalid', message: 'The graph secret key cannot call public auth routes.' } }, 403);
    if (authorization.startsWith('zp_')) {
      const valid = await scope.prepare('SELECT 1 AS active FROM auth_keys WHERE project_id=? AND kind="publishable" AND digest=? AND revoked_at IS NULL').bind(context.project.project_id, await hmac(env.GATE_CONTEXT_SECRET, authorization)).first();
      if (!valid) return json({ error: { code: 'invalid_key' } }, 401);
    } else if (!await verifyAccessToken(env, context.project, authorization, new URL(request.url).origin)) return json({ error: { code: 'invalid_key' } }, 401);
    try { return withCors(await route(request, env, context.project), context.project, request.headers.get('origin')); }
    catch (error) { console.error('zega-auth request failed', error instanceof Error ? error.message : 'unknown'); return json({ error: { code: 'internal_error', message: 'The auth request failed.' } }, 500); }
  },
};

export class AuthRateLimit {
  constructor(private readonly state: DurableObjectState) {}
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') return new Response(null, { status: 405 });
    const input = await request.json().catch(() => ({})) as { max?: number; windowSeconds?: number };
    if (!Number.isInteger(input.max) || !Number.isInteger(input.windowSeconds) || input.max! < 1 || input.windowSeconds! < 1) return json({ error: 'bad_request' }, 400);
    const now = Date.now();
    const allowed = await this.state.storage.transaction(async transaction => {
      const prior = await transaction.get<number[]>('attempts') ?? [];
      const attempts = prior.filter(at => at > now - input.windowSeconds! * 1000);
      if (attempts.length >= input.max!) { await transaction.put('attempts', attempts); return false; }
      attempts.push(now);
      await transaction.put('attempts', attempts);
      return true;
    });
    return json({ allowed });
  }
}
