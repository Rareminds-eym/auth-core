# @rareminds-eym/auth-core

Enterprise-grade auth middleware for Cloudflare Functions. Stateless JWT verification at the edge with centralized session control and secure refresh token flow.

## Features

- **Edge-compatible** — runs on Cloudflare Functions, no Node.js APIs required
- **Stateless JWT verification** via JWKS
- **Automatic refresh token flow** — transparent token renewal from HTTP-only cookies
- **Session validation** — optional SSO round-trip to check session revocation
- **Role & product guards** — composable middleware for authorization
- **Runtime configuration** — no hardcoded domains, works across environments
- **Timeout protection** — all SSO calls use configurable `AbortController` timeouts
- **Type-safe** — full TypeScript with generic Cloudflare context support

## Installation

```bash
npm install @rareminds-eym/auth-core
```

## Quick Start

### 1. Initialize (once at startup)

```ts
import { initAuth } from "@rareminds-eym/auth-core";

initAuth({
  ssoDomain: "https://sso.rareminds.com",
});
```

### 2. Protect a route

```ts
import { withAuth } from "@rareminds-eym/auth-core";

export const onRequestGet = withAuth(async (context) => {
  const user = context.data.user;
  return Response.json({ user_id: user.sub, org: user.org_id });
});
```

That's it. `withAuth` handles JWT verification, refresh token fallback, session validation, and error responses automatically.

## Configuration

```ts
initAuth({
  ssoDomain: "https://sso.rareminds.com",   // Required — your SSO base URL
  ssoTimeoutMs: 3000,                        // Optional — fetch timeout (default: 5000ms)
  validateSessionBeforeRefresh: false,        // Optional — skip /validate-session call (default: true)
  issuer: "https://sso.rareminds.com",       // Optional — JWT issuer validation
  audience: "rareminds-api",                 // Optional — JWT audience validation
});
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ssoDomain` | `string` | — | Base URL of your SSO service |
| `ssoTimeoutMs` | `number` | `5000` | Timeout in ms for all SSO fetch calls (must be > 0) |
| `validateSessionBeforeRefresh` | `boolean` | `true` | Whether to call `/auth/validate-session` before `/auth/refresh`. Set to `false` if your refresh endpoint already rejects revoked sessions. |
| `issuer` | `string` | — | Expected JWT `iss` claim. Recommended for multi-service setups. |
| `audience` | `string` | — | Expected JWT `aud` claim. Recommended for multi-service setups. |

Safe to call `initAuth()` again — it clears all internal caches (JWKS, etc).

## Auth Flow

```
Request arrives
    │
    ├─ Has valid JWT? → Check membership active → ✅ Run handler
    │
    ├─ JWT expired/missing?
    │   ├─ Has refresh_token cookie?
    │   │   ├─ validateSession (optional) → ❌ 401 "Session expired"
    │   │   ├─ refreshAccessToken         → ❌ 502 "Refresh failed"
    │   │   └─ verifyJWT(new token)       → ✅ Run handler + new Authorization header
    │   └─ No refresh token → ❌ 401 "Unauthorized"
    │
    └─ SSO unreachable → ❌ 502
```

When a token is refreshed, the new JWT is attached to the response via the `X-Access-Token` header so the client can update its stored token.

## Middleware

### `withAuth`

Authenticates the request. Tries the access token first, falls back to refresh token flow.

```ts
import { withAuth } from "@rareminds-eym/auth-core";

export const onRequestGet = withAuth(async (context) => {
  const user = context.data.user;
  return Response.json(user);
});
```

### `requireRole`

Requires the user to have at least one of the specified roles. Must be nested inside `withAuth`.

```ts
import { withAuth, requireRole } from "@rareminds-eym/auth-core";

// Single role
export const onRequestPost = withAuth(
  requireRole("admin", async (context) => {
    return Response.json({ ok: true });
  })
);

// Multiple roles (user needs ANY one)
export const onRequestGet = withAuth(
  requireRole(["admin", "manager"], async (context) => {
    return Response.json({ ok: true });
  })
);
```

### `requireProduct`

Requires the user to have access to at least one of the specified products.

```ts
import { withAuth, requireProduct } from "@rareminds-eym/auth-core";

export const onRequestGet = withAuth(
  requireProduct("hiring-platform", async (context) => {
    return Response.json({ feature: "unlocked" });
  })
);

// Multiple products
export const onRequestGet = withAuth(
  requireProduct(["hiring-platform", "lms"], async (context) => {
    return Response.json({ feature: "unlocked" });
  })
);
```

### Composing Guards

```ts
export const onRequestPost = withAuth(
  requireRole("admin",
    requireProduct("hiring-platform", async (context) => {
      // Only admins with hiring-platform access
      return Response.json({ ok: true });
    })
  )
);
```

### `withErrorHandler`

Catches unhandled errors, logs structured JSON, and returns a clean 500 response.

```ts
import { withErrorHandler, withAuth } from "@rareminds-eym/auth-core";

export const onRequestGet = withErrorHandler(
  withAuth(async (context) => {
    const data = await riskyOperation();
    return Response.json(data);
  })
);
```

Logs:
```json
{ "level": "error", "message": "...", "url": "...", "timestamp": "..." }
```

## Typed Context

`ContextWithUser` is generic — pass your Cloudflare env bindings. After `withAuth`, use `AuthenticatedContext` where `user` is guaranteed:

```ts
import { withAuth } from "@rareminds-eym/auth-core";
import type { AuthenticatedContext } from "@rareminds-eym/auth-core";

interface MyEnv {
  DB: D1Database;
  KV_STORE: KVNamespace;
}

export const onRequestGet = withAuth(async (context: AuthenticatedContext<MyEnv>) => {
  const db = context.env.DB;
  const user = context.data.user; // AuthUser — no ! needed
  return Response.json({ ok: true });
});
```

Available on context: `request`, `env`, `params`, `data`, `waitUntil()`, `passThroughOnException()`.

## Re-initialization

Safe to call `initAuth()` multiple times — useful for testing or multi-tenant setups. All internal caches (JWKS, etc.) are automatically cleared.

```ts
import { initAuth } from "@rareminds-eym/auth-core";

// Switch to staging
initAuth({ ssoDomain: "https://staging-sso.rareminds.com" });

// Later, switch to production
initAuth({ ssoDomain: "https://sso.rareminds.com" });
```

You can also register your own cleanup callbacks:

```ts
import { onConfigReset } from "@rareminds-eym/auth-core";

onConfigReset(() => {
  // Clear your own caches when initAuth is called again
});
```

## Standalone Utilities

Every internal function is exported for custom use cases:

```ts
import {
  verifyJWT,            // Verify a JWT and get AuthUser
  extractToken,         // Extract Bearer token from Authorization header
  getRefreshToken,      // Extract refresh_token from Cookie header
  validateSession,      // POST /auth/validate-session
  refreshAccessToken,   // POST /auth/refresh
  fetchWithTimeout,     // Fetch with configurable AbortController timeout
  jsonError,            // Shared JSON error response helper
  getConfig,            // Read current config
  onConfigReset,        // Register cache-clearing callbacks
  initAuth,             // Initialize / re-initialize config
} from "@rareminds-eym/auth-core";
```

### Examples

```ts
// Extract Bearer token from request
const token = extractToken(request); // "eyJhbG..." | null

// Extract refresh_token from Cookie header
const refreshToken = getRefreshToken(request); // "abc123" | null

// Verify a JWT manually
const user = await verifyJWT(token);
// { sub, org_id, roles, products, membership_status }

// Validate a session against SSO
const session = await validateSession(refreshToken);
// { valid: true, user: { ... } }

// Refresh an access token via SSO
const { access_token } = await refreshAccessToken(refreshToken);

// Make any fetch call with the configured timeout
const res = await fetchWithTimeout("https://api.example.com/data", {
  method: "GET",
});

// Read current config
const config = getConfig();
// { ssoDomain, ssoTimeoutMs, validateSessionBeforeRefresh }
```

## Types

```ts
import type {
  AuthUser,                   // { sub, org_id, roles, products, membership_status }
  MembershipStatus,           // "active" | "inactive" | "suspended" | "expired"
  ContextWithUser,            // Generic Cloudflare-style context
  AuthenticatedContext,       // Context where user is guaranteed (after withAuth)
  SessionValidationResponse,  // { valid: boolean, user?: AuthUser }
  AuthCoreConfig,             // initAuth() config shape
} from "@rareminds-eym/auth-core";
```

## SSO API Requirements

Your SSO service must expose these endpoints:

### `POST /auth/refresh`

Request:
```json
{ "refresh_token": "string" }
```

Response:
```json
{ "access_token": "jwt-string" }
```

### `POST /auth/validate-session`

Request:
```json
{ "refresh_token": "string" }
```

Response:
```json
{ "valid": true, "user": { "sub": "...", "org_id": "...", ... } }
```

### `GET /.well-known/jwks.json`

Standard JWKS endpoint for JWT verification.

## JWT Claims

The access token JWT must contain these claims:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | `string` | User ID |
| `org_id` | `string` | Organization ID |
| `roles` | `string[]` | User roles |
| `products` | `string[]` | Product access list |
| `membership_status` | `"active" \| "inactive" \| "suspended" \| "expired"` | Membership state |

## Security Notes

- Refresh tokens must be stored in **HTTP-only, Secure, SameSite=Strict** cookies
- Refresh tokens are **never validated at the edge** — always delegated to SSO
- SSO should **hash refresh tokens** in the database (store hash, not raw)
- SSO should **rotate refresh tokens** on each use (issue new, invalidate old)
- Access tokens should be **short-lived** (10–15 minutes)

## Error Responses

All error responses are JSON:

| Status | Error | When |
|--------|-------|------|
| `401` | `Unauthorized: no valid token or refresh token` | No JWT and no refresh cookie |
| `401` | `Session expired or revoked` | Session validation failed |
| `403` | `Inactive membership` | User membership is not active |
| `403` | `Forbidden: insufficient role` | User lacks required role |
| `403` | `Forbidden: product access denied` | User lacks product access |
| `500` | `Refreshed token is invalid` | SSO returned a bad JWT |
| `500` | `Internal Server Error` | Unhandled error (via withErrorHandler) |
| `502` | `Session validation failed` | SSO unreachable for session check |
| `502` | `Token refresh failed` | SSO unreachable for token refresh |

## Building

```bash
npm run build
```

## Project Structure

```
auth-core/
├── src/
│   ├── config.ts                  # initAuth, getConfig, onConfigReset
│   ├── index.ts                   # Barrel exports
│   ├── types/
│   │   └── auth.ts                # AuthUser, MembershipStatus, ContextWithUser, SessionValidationResponse
│   ├── jwt/
│   │   └── verifyJWT.ts           # JWT verification via JWKS + payload validation
│   ├── utils/
│   │   ├── extractToken.ts        # Bearer token extraction from Authorization header
│   │   ├── getRefreshToken.ts     # Refresh token extraction from Cookie header
│   │   ├── fetchWithTimeout.ts    # Fetch wrapper with AbortController timeout
│   │   └── jsonError.ts           # Shared JSON error response helper
│   ├── session/
│   │   ├── refreshAccessToken.ts  # POST /auth/refresh
│   │   └── validateSession.ts     # POST /auth/validate-session
│   └── middleware/
│       ├── withAuth.ts            # Main auth middleware (JWT + refresh flow)
│       ├── requireRole.ts         # Role-based access guard
│       ├── requireProduct.ts      # Product-based access guard
│       └── withErrorHandler.ts    # Global error handler with structured logging
├── dist/                          # Compiled output (gitignored)
├── package.json
├── tsconfig.json
├── .npmrc
├── .gitignore
└── README.md
```

## License

UNLICENSED — private package for Rareminds.
