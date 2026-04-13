# @rareminds-eym/auth-core

Server-side auth middleware for Cloudflare Functions. Stateless JWT verification at the edge via JWKS, automatic refresh token flow, role and product guards — purpose-built for the SSO worker.

## Install

```bash
npm install @rareminds-eym/auth-core
```

`.npmrc` setup for GitHub Packages:
```
@rareminds-eym:registry=https://npm.pkg.github.com
```

## Quick Start

```ts
import { initAuth, withAuth } from "@rareminds-eym/auth-core";

// Once at startup
initAuth({
  ssoDomain: "https://sso-api.your-domain.workers.dev",
});

// Protect a route
export const onRequestGet = withAuth(async (context) => {
  const user = context.data.user;
  return Response.json({ id: user.sub, org: user.org_id, verified: user.is_email_verified });
});
```

## Configuration

```ts
initAuth({
  ssoDomain: "https://sso-api.workers.dev",  // Required
  issuer: "sso-api",                          // Default: "sso-api"
  audience: "sso-client",                     // Default: "sso-client"
  ssoTimeoutMs: 5000,                         // Default: 5000
  validateSessionBeforeRefresh: false,         // Default: false
});
```

| Option | Default | Description |
|--------|---------|-------------|
| `ssoDomain` | — | SSO worker base URL (required) |
| `issuer` | `"sso-api"` | Expected JWT `iss` claim |
| `audience` | `"sso-client"` | Expected JWT `aud` claim |
| `ssoTimeoutMs` | `5000` | Timeout for SSO fetch calls |
| `validateSessionBeforeRefresh` | `false` | Call `/auth/me` before refresh (unnecessary — refresh rejects revoked sessions) |

Safe to call `initAuth()` multiple times — clears all caches (JWKS, etc).

## Auth Flow

```
Request → Has valid JWT? → membership active? → ✅ Handler
                         → membership inactive → 403
        → JWT expired?   → Has refresh cookie? → Refresh → Verify new JWT → ✅ Handler
                                                                              + Set-Cookie forwarded
                                                                              + X-Access-Token header
                         → No refresh cookie   → 401
        → JWT invalid    → 401 (no refresh attempt)
```

Key behavior: only `JWTExpired` errors trigger the refresh flow. Tampered, wrong-issuer, or wrong-audience tokens return 401 immediately.

After refresh, `Set-Cookie` headers from the SSO worker are forwarded to the browser so cookies stay fresh.

## Middleware

### `withAuth`

```ts
import { withAuth } from "@rareminds-eym/auth-core";

export const onRequestGet = withAuth(async (context) => {
  const user = context.data.user;
  // user: { sub, email, org_id, roles, products, membership_status, is_email_verified }
  return Response.json(user);
});
```

### `requireRole`

```ts
import { withAuth, requireRole } from "@rareminds-eym/auth-core";

export const onRequestPost = withAuth(
  requireRole(["admin", "owner"], async (context) => {
    return Response.json({ ok: true });
  })
);
```

### `requireProduct`

```ts
import { withAuth, requireProduct } from "@rareminds-eym/auth-core";

export const onRequestGet = withAuth(
  requireProduct("hiring-platform", async (context) => {
    return Response.json({ feature: "unlocked" });
  })
);
```

### `withErrorHandler`

```ts
import { withErrorHandler, withAuth } from "@rareminds-eym/auth-core";

export const onRequestGet = withErrorHandler(
  withAuth(async (context) => {
    return Response.json(await riskyOperation());
  })
);
```

### Composing

```ts
export const onRequestPost = withErrorHandler(
  withAuth(
    requireRole("admin",
      requireProduct("erp", async (context) => {
        // Admin with ERP access only
        return Response.json({ ok: true });
      })
    )
  )
);
```

## Standalone Functions

```ts
import {
  verifyJWT,            // Verify JWT → AuthUser
  extractToken,         // Bearer header or access_token cookie → string | null
  getRefreshToken,      // refresh_token cookie → string | null
  refreshAccessToken,   // POST /auth/refresh → { access_token, setCookieHeaders }
  validateSession,      // GET /auth/me → { valid, user? }
  logout,               // POST /auth/logout → { success, setCookieHeaders }
  fetchWithTimeout,     // Fetch with configurable AbortController timeout
  jsonError,            // JSON error response helper
} from "@rareminds-eym/auth-core";
```

### Token extraction

`extractToken` checks the `Authorization: Bearer` header first, then falls back to the `access_token` cookie — matching the SSO worker's extraction logic exactly.

`getRefreshToken` returns the raw cookie value without URI decoding — matching the SSO worker's cookie parsing.

### Refresh with cookie forwarding

```ts
const { access_token, setCookieHeaders } = await refreshAccessToken(refreshToken);

// Forward cookies to the browser
for (const cookie of setCookieHeaders) {
  response.headers.append("Set-Cookie", cookie);
}
```

### Server-side logout

```ts
const { success, setCookieHeaders } = await logout(refreshToken);
// Forward Set-Cookie headers to clear browser cookies
```

## Types

```ts
import type {
  AuthUser,                   // { sub, email, org_id, roles, products, membership_status, is_email_verified }
  MembershipStatus,           // "active" | "inactive" | "suspended" | "expired"
  ContextWithUser,            // Generic Cloudflare context (user optional)
  AuthenticatedContext,       // Context where user is guaranteed
  SessionValidationResponse,  // { valid, user? }
  AuthCoreConfig,             // initAuth() input
  ResolvedAuthCoreConfig,     // Config with defaults applied
} from "@rareminds-eym/auth-core";
```

## JWT Claims

The SSO worker signs JWTs with these claims:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | `string` | User ID |
| `email` | `string` | User email |
| `org_id` | `string` | Active organization ID |
| `roles` | `string[]` | Roles in active org |
| `products` | `string[]` | Product access codes |
| `membership_status` | `MembershipStatus` | Membership state |
| `is_email_verified` | `boolean` | Email verification status |
| `iss` | `"sso-api"` | Issuer |
| `aud` | `"sso-client"` | Audience |

All claims are validated with strict type checking in `verifyJWT`.

## Error Responses

| Status | Error | When |
|--------|-------|------|
| `401` | `Invalid token` | JWT tampered, wrong issuer/audience |
| `401` | `Unauthorized: no valid token or refresh token` | No JWT and no refresh cookie |
| `403` | `Inactive membership` | `membership_status` is not `"active"` |
| `403` | `Forbidden: insufficient role` | Missing required role |
| `403` | `Forbidden: product access denied` | Missing product access |
| `500` | `Refreshed token is invalid` | SSO returned a bad JWT |
| `502` | `Token refresh failed` | SSO unreachable |

## Build

```bash
npm run build
```

## Re-initialization

Safe to call `initAuth()` multiple times — clears all caches. Useful for testing or multi-tenant setups:

```ts
initAuth({ ssoDomain: "https://staging-sso.workers.dev" });
// Later...
initAuth({ ssoDomain: "https://prod-sso.workers.dev" });
```

Register cleanup callbacks:

```ts
import { onConfigReset } from "@rareminds-eym/auth-core";

const unsub = onConfigReset(() => {
  // Clear your own caches when initAuth is called again
});
unsub(); // unsubscribe when done
```

## Typed Context

`ContextWithUser` is generic — pass your Cloudflare env bindings:

```ts
import type { AuthenticatedContext } from "@rareminds-eym/auth-core";

interface MyEnv {
  DB: D1Database;
  KV: KVNamespace;
}

export const onRequestGet = withAuth(async (context: AuthenticatedContext<MyEnv>) => {
  const db = context.env.DB;
  const user = context.data.user; // AuthUser — guaranteed present
  return Response.json({ ok: true });
});
```

## Project Structure

```
auth-core/
├── src/
│   ├── index.ts                   # Barrel exports
│   ├── config.ts                  # initAuth, getConfig, onConfigReset
│   ├── types/auth.ts              # AuthUser, MembershipStatus, Context types
│   ├── jwt/verifyJWT.ts           # JWKS-based JWT verification + claim validation
│   ├── middleware/
│   │   ├── withAuth.ts            # Auth middleware (JWT + refresh + cookie forwarding)
│   │   ├── requireRole.ts         # Role guard
│   │   ├── requireProduct.ts      # Product guard
│   │   └── withErrorHandler.ts    # Global error handler
│   ├── session/
│   │   ├── refreshAccessToken.ts  # POST /auth/refresh (captures Set-Cookie)
│   │   ├── validateSession.ts     # GET /auth/me
│   │   └── logout.ts             # POST /auth/logout (captures Set-Cookie)
│   └── utils/
│       ├── extractToken.ts        # Bearer header + access_token cookie fallback
│       ├── getRefreshToken.ts     # refresh_token cookie (raw, no URI decode)
│       ├── fetchWithTimeout.ts    # AbortController timeout wrapper
│       └── jsonError.ts           # JSON error response helper
├── dist/
├── package.json
└── tsconfig.json
```

## License

UNLICENSED — private package for Rareminds.
