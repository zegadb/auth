import assert from 'node:assert/strict';
import { mkdir, readFile, symlink } from 'node:fs/promises';
import { test } from 'node:test';
import { Miniflare } from 'miniflare';
import { build } from 'esbuild';

const sent = [];
await mkdir('.tmp', { recursive: true });
await symlink('../node_modules/argon2-wasm-edge', '.tmp/argon2-wasm-edge', 'dir').catch(error => { if (error.code !== 'EEXIST') throw error; });
await build({ entryPoints: ['src/index.ts'], outfile: '.tmp/worker.mjs', bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['argon2-wasm-edge/wasm/*.wasm'] });
const mf = new Miniflare({
  name: 'zega-auth-test', scriptPath: '.tmp/worker.mjs', modules: true,
  compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'],
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  d1Databases: { AUTH_DB: 'zega-auth-test' },
  d1Persist: false,
  durableObjectsPersist: false,
  durableObjects: { AUTH_RATES: { className: 'AuthRateLimit', useSQLite: true } },
  bindings: {
    GATE_CONTEXT_SECRET: 'test-gate-context-secret-that-is-long-enough',
    KEY_SEALING_KEY: 'test-key-sealing-secret-that-is-long-enough',
    RESEND_API_KEY: 're_test_fake', RESEND_API_ORIGIN: 'https://api.resend.test',
    EMAIL_FROM: 'Zega <noreply@auth.zega.dev>', ALLOW_UNSIGNED_GATE_CONTEXT: 'true',
  },
  outboundService: async request => {
    if (new URL(request.url).hostname === 'api.resend.test') { sent.push(await request.json()); return Response.json({ id: `mail-${sent.length}` }, { status: 200 }); }
    return new Response('not found', { status: 404 });
  },
});
const db = await mf.getD1Database('AUTH_DB');
for (const statement of (await readFile(new URL('../migrations/0001_auth.sql', import.meta.url), 'utf8')).split(';').map(sql => sql.trim()).filter(Boolean)) await db.prepare(statement).run();
const ctx = { 'x-zega-project': 'project-a', 'x-zega-graph': 'graph-a' };
const req = (path, body, key, options = {}) => mf.dispatchFetch(`https://graph-a.zegadb.com/auth/v1/${path}`, {
  method: options.method ?? (body === undefined ? 'GET' : 'POST'),
  headers: { ...ctx, ...(key ? { authorization: `Bearer ${key}` } : {}), ...(options.headers ?? {}), ...(body === undefined ? {} : { 'content-type': options.contentType ?? 'application/json' }) },
  body: body === undefined ? undefined : options.rawBody ?? JSON.stringify(body),
});
const json = response => response.json();
let publishableKey;
let openedSession;
let openedEmail;

test('workerd: project provisioning returns a one-time zp_ key and public routes reject wrong key types', async () => {
  const enabled = await req('control/enable', { siteUrl: 'https://app.example.test', redirectAllowlist: ['https://*-preview.example.test/**'] }, undefined);
  assert.equal(enabled.status, 201);
  const result = await json(enabled);
  publishableKey = result.publishableKey;
  assert.match(publishableKey, /^zp_[123456789abcdefghjkmnpqrstuvwxyz]{32}$/);
  assert.equal(result.shownOnce, true);
  assert.equal((await req('magiclink', { email: 'nobody@example.test' })).status, 401);
  const secretKey = await req('magiclink', { email: 'nobody@example.test' }, 'zk_existing_secret_key');
  assert.equal(secretKey.status, 403);
  assert.equal((await req('magiclink', { email: 'nobody@example.test' }, 'zp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).status, 401);
  assert.equal((await req('magiclink', { email: 'nobody@example.test' }, publishableKey)).status, 200);
});

test('workerd: sign-up, mail confirmation, password sign-in, ES256 JWKS, rotation and reuse revoke the family, then sign out', async () => {
  sent.length = 0;
  const signup = await req('signup', { email: 'Ada@Example.test', password: 'correct horse battery staple', redirectTo: 'https://app.example.test/' }, publishableKey);
  assert.equal(signup.status, 201);
  const signedUp = await json(signup);
  assert.equal(signedUp.session, null);
  openedEmail = sent.at(-1);
  const link = openedEmail.html.match(/href="([^"]+\/confirm\?token=[^"]+)"/)[1];
  const getLink = await mf.dispatchFetch(link, { headers: ctx });
  assert.equal(getLink.status, 200);
  assert.match(await getLink.text(), /Confirm email/);
  const token = new URL(link).searchParams.get('token');
  const confirm = await req('confirm', { token }, publishableKey);
  assert.equal(confirm.status, 200);
  assert.equal((await json(confirm)).user.emailVerified, true);

  const signIn = await req('token', { grant_type: 'password', email: 'ada@example.test', password: 'correct horse battery staple' }, publishableKey);
  assert.equal(signIn.status, 200);
  openedSession = await json(signIn);
  assert.match(openedSession.access_token, /^ey/);
  assert.match(openedSession.refresh_token, /^zr_[123456789abcdefghjkmnpqrstuvwxyz]{32}$/);
  const credential = await db.prepare('SELECT alg,parameters FROM auth_credentials WHERE project_id=? AND uid=?').bind('project-a', openedSession.user.uid).first();
  const cost = JSON.parse(credential.parameters);
  assert.equal(credential.alg, 'argon2id');
  assert.equal(cost.memoryKiB, 19_456);
  assert.equal(cost.iterations, 2);
  console.log(`ARGON2_WORKER_CPU_MS=${cost.cpuMs} MEMORY_KIB=${cost.memoryKiB} ITERATIONS=${cost.iterations} PARALLELISM=${cost.parallelism}`);

  const [header, claims, signature] = openedSession.access_token.split('.');
  const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());
  const decodedClaims = JSON.parse(Buffer.from(claims, 'base64url').toString());
  const jwks = await json(await req('.well-known/jwks.json', undefined, publishableKey));
  const jwk = jwks.keys.find(item => item.kid === decodedHeader.kid);
  assert.ok(jwk, 'JWT kid is present in the tenant JWKS');
  assert.equal(decodedClaims.aud, 'authenticated');
  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, Buffer.from(signature, 'base64url'), new TextEncoder().encode(`${header}.${claims}`)), true);

  const refreshes = await Promise.all([
    req('token', { grant_type: 'refresh_token', refresh_token: openedSession.refresh_token }, publishableKey),
    req('token', { grant_type: 'refresh_token', refresh_token: openedSession.refresh_token }, publishableKey),
  ]);
  assert.deepEqual(refreshes.map(response => response.status).sort(), [200, 401]);
  const rotated = await json(refreshes.find(response => response.status === 200));
  assert.notEqual(rotated.refresh_token, openedSession.refresh_token);
  const refreshCount = await db.prepare('SELECT COUNT(*) AS n FROM auth_refresh_tokens WHERE project_id=? AND sid=?').bind('project-a', decodedClaims.sid).first();
  assert.equal(refreshCount.n, 2, 'the concurrent loser does not create a second refresh branch');
  await db.prepare('UPDATE auth_refresh_tokens SET used_at=? WHERE project_id=? AND sid=? AND parent_hash IS NULL').bind(Math.floor(Date.now()/1000)-11, 'project-a', decodedClaims.sid).run();
  const reuse = await req('token', { grant_type: 'refresh_token', refresh_token: openedSession.refresh_token }, publishableKey);
  assert.equal(reuse.status, 401);
  assert.equal((await json(reuse)).error.reason, 'refresh_reuse_detected');
  const revoked = await db.prepare('SELECT revoked_at FROM auth_sessions WHERE project_id=? AND sid=?').bind('project-a', decodedClaims.sid).first();
  assert.ok(revoked.revoked_at, 'refresh reuse revokes the session family');
  assert.equal((await req('token', { grant_type: 'refresh_token', refresh_token: rotated.refresh_token }, publishableKey)).status, 401);
  const signout = await req('logout', { refresh_token: rotated.refresh_token }, openedSession.access_token);
  assert.equal(signout.status, 200);
});

test('workerd: redirect allow-list and default email request rate limits are enforced', async () => {
  assert.equal((await req('recover', { email: 'any@example.test', redirectTo: 'https://evil.example.test/' }, publishableKey)).status, 400);
  const preview = await req('recover', { email: 'unknown@example.test', redirectTo: 'https://pr-123-preview.example.test/recover' }, publishableKey, { headers: { origin: 'https://pr-123-preview.example.test' } });
  assert.equal(preview.status, 200);
  assert.equal(preview.headers.get('access-control-allow-origin'), 'https://pr-123-preview.example.test');
  assert.equal((await req('magiclink', { email: 'limited@example.test', redirectTo: 'https://app.example.test/' }, publishableKey)).status, 200);
  const limited = await req('magiclink', { email: 'limited@example.test', redirectTo: 'https://app.example.test/' }, publishableKey);
  assert.equal(limited.status, 429);
});

test('workerd: gate control ban ends sessions and blocks later password sign-in', async () => {
  const configured = await req('control/enable', { siteUrl: 'https://app.example.test', confirmEmail: false, strictSessions: true });
  assert.equal(configured.status, 200);
  assert.equal((await json(configured)).shownOnce, false, 'enabling settings does not mint a new active publishable key');
  const signIn = await req('token', { grant_type: 'password', email: 'ada@example.test', password: 'correct horse battery staple' }, publishableKey);
  assert.equal(signIn.status, 200);
  const strictSession = await json(signIn);
  const ban = await req('control/user', { uid: openedSession.user.uid, banned: true });
  assert.equal(ban.status, 200);
  const user = await db.prepare('SELECT status FROM auth_users WHERE project_id=? AND uid=?').bind('project-a', openedSession.user.uid).first();
  assert.equal(user.status, 'banned');
  const session = await db.prepare('SELECT revoked_at FROM auth_sessions WHERE project_id=? AND sid=?').bind('project-a', JSON.parse(Buffer.from(strictSession.access_token.split('.')[1], 'base64url').toString()).sid).first();
  assert.ok(session.revoked_at);
  const strictRefusal = await req('user', {}, strictSession.access_token, { method: 'PUT' });
  assert.equal(strictRefusal.status, 401, 'strict sessions refuses the revoked access JWT immediately');
  const blocked = await req('token', { grant_type: 'password', email: 'ada@example.test', password: 'correct horse battery staple' }, publishableKey);
  assert.equal(blocked.status, 401);
  assert.equal((await json(blocked)).error.code, 'user_banned');
});

test('workerd: shared sender allowance stops at 100 messages per project per UTC day', async () => {
  await db.prepare('INSERT OR IGNORE INTO auth_users(project_id,uid,email,email_verified,created_at) VALUES (?,?,?,?,?)').bind('project-a', 'a_allowance', 'budget@example.test', 1, Math.floor(Date.now()/1000)).run();
  await db.prepare('INSERT INTO auth_email_daily(project_id,day,sent) VALUES (?,?,100) ON CONFLICT(project_id,day) DO UPDATE SET sent=100').bind('project-a', new Date().toISOString().slice(0, 10)).run();
  const before = sent.length;
  const response = await req('magiclink', { email: 'budget@example.test', redirectTo: 'https://app.example.test/' }, publishableKey);
  assert.equal(response.status, 429);
  assert.equal((await json(response)).error.code, 'email_allowance_exhausted');
  assert.equal(sent.length, before);
});

test('workerd: missing signed gate context is refused outside local dev', async () => {
  const response = await mf.dispatchFetch('https://graph-a.zegadb.com/auth/v1/.well-known/jwks.json', { headers: { authorization: `Bearer ${publishableKey}` } });
  assert.equal(response.status, 401);
});

test.after(async () => { await mf.dispose(); });
