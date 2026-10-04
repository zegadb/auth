# Zega Auth

The multi-tenant auth Worker and `@zegadb/auth` core package for APS 48.

## Service

The Worker serves the graph-host `/auth/v1/*` routes. Production requests require the gate to add the signed headers `x-zega-project`, `x-zega-graph`, `x-zega-gate-time` (Unix milliseconds), and `x-zega-gate-signature` (`HMAC-SHA-256` over `projectId + "\n" + graphId + "\n" + timestamp`). The service rejects unsigned or stale context. Local dev alone can set `ALLOW_UNSIGNED_GATE_CONTEXT=true`.

The control routes under `/auth/v1/control/*` are gate-only and require the same signed context. `POST /control/enable` sets project URL/session settings and returns a `zp_` key once. `POST /control/user` bans or unbans a user and revokes their sessions when banning. Public routes require a registered `zp_` key or a valid ES256 user token. The existing `zk_` graph secret is refused on public auth routes.

Auth D1 stores email credentials and verifier costs, tenant signing keys, sessions and refresh-token HMACs, one-time challenges, exact request counters, the daily shared-sender allowance, and minimal auth settings. Signing keys are sealed with `KEY_SEALING_KEY`; refresh/challenge/key digests use `GATE_CONTEXT_SECRET`. The rate/email reservation writes are project-scoped and atomic. CORS is derived from the Site URL and redirect allow-list.

Email uses Resend's HTTP API. Production sets `RESEND_API_KEY` as a Worker secret. The shared sender is `Zega <noreply@auth.zega.dev>` and has a 100-message daily project allowance. Tests replace Resend with a fake handler.

## Package

```ts
import { createAuth } from '@zegadb/auth'

const auth = createAuth({ url, publishableKey })
await auth.signUp({ email, password })
await auth.signInWithPassword({ email, password })
const user = await auth.getUser()
const graph = await auth.graph({ schema })
```

The `key` method and the client's `graph()` pass the current access token to `@zegadb/lib/client` as a function. `ZegaAuthError` keeps the shared error prototype and exposes the auth endpoint's stable error code.

## Local checks

- `npm run check`
- `npm test` (Miniflare/workerd with a fake email sender)
- `npx wrangler deploy --dry-run --env dev --outdir .tmp/dist`
- `npx wrangler dev --config test/wrangler.argon2.jsonc` runs the local Argon2 measurement endpoint; it accepts only POST JSON with a test password and returns the CPU and memory parameters, never the verifier.

See [the password hash spike](docs/password-hash-spike.md) for the Wrangler dev measurements and algorithm decision.

## Next

- `/next`, `/astro`, `/react`, `/admin`, GitHub/Google OAuth, and the two starter integrations.
- Cloud gate service binding and `/auth/v1/*` forwarding, access-token verification for graph data requests, and publishable-key routing.
- Persisting developer-visible `Auth` nodes through the gate/engine path and the control API/dashboard integrations.
