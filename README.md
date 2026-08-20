# @rareminds-eym/auth-core

Trusted-runtime authentication middleware for Rareminds applications. Version 3 is a clean break: consumers use one isolated `createAuth` facade; token extraction, JWT/JWKS implementation, cookies, refresh, logout, and response construction are package-private.

## Architecture

`auth-core` is the server-side authentication package for Cloudflare Workers and other supported server runtimes. It exposes a single public entrypoint while keeping implementation details internal.

```text
src/
├── index.ts
├── createAuth.ts
├── internal/
│   ├── authentication/
│   ├── browser/
│   └── telemetry/
└── types/
    └── public.ts

tests/
├── unit/
├── property/
└── integration/

negative/
└── legacy-imports.ts
```

### Conventions

* `src/index.ts` is the only public package entrypoint.
* `createAuth.ts` is the composition root.
* Authentication implementation belongs under `src/internal/`.
* Public types belong under `src/types/public.ts`.
* Tests are kept outside production source under `tests/`.
* Internal modules are organized by capability, such as `authentication`, `browser`, and `telemetry`.
* Avoid generic folders such as `utils`, `helpers`, `common`, or `misc`.
* Internal modules must not be exposed as public package subpaths.
* Production code must not depend on test or negative-test files.
* NodeNext ESM imports use explicit `.js` extensions.
* Observability, correlation, errors, and configuration should remain separate modules rather than being inlined into the factory.
* Each call to `createAuth()` should create an isolated instance without shared mutable global state.

The intended dependency direction is:

```text
index.ts
   ↓
createAuth.ts
   ↓
authentication / browser / telemetry
   ↓
config / context / errors
```

The public API should remain small and stable, while server-side authentication logic stays internal and independently testable.

## Runtime support

- Node.js 18 or newer
- Cloudflare Workers-compatible Web APIs
- ESM and TypeScript declarations

## Installation

```bash
npm install @rareminds-eym/auth-core@3.0.0
```

## Public API

The package root has one runtime export, `createAuth`, plus its public configuration, handler, verified-context, observation, and safe-error types. Package subpaths are not exported.

```ts
import { createAuth } from "@rareminds-eym/auth-core";
import type { AuthCoreConfig, VerifiedAuthContext } from "@rareminds-eym/auth-core";

const config: AuthCoreConfig = {
  sso: env.SSO_SERVICE,
  issuer: "https://sso.example.com",
  audience: "skillpassport-api",
  approvedOrigins: ["https://app.example.com"],
  basePath: "/api/auth",
  csrf: { name: "X-RM-CSRF", value: "1" },
  cookieMaxAgeSeconds: 2_592_000,
  jwksMaxAgeSeconds: 300,
  ssoRequestTimeoutMs: 8_000,
};

const auth = createAuth(config);

export const onRequestGet = auth.authenticate(
  async (_request: Request, context: VerifiedAuthContext) =>
    Response.json({ subject: context.user.sub }),
);
```
## Configuration validation

`createAuth` rejects configuration before creating an instance when:

- issuer or audience is empty, unnormalized, contains controls, or is oversized;
- an approved/CORS origin is wildcard, opaque, non-HTTPS, contains credentials, path, query, or fragment, is duplicated, or is not serialized exactly as an origin;
- `basePath` is cross-origin, network-path, unnormalized, query-bearing, fragment-bearing, or has a trailing slash;
- CSRF is not exactly `X-RM-CSRF: 1`;
- cookie/JWKS/SSO timeout bounds are not positive finite safe integers;
- credentialed CORS contains an origin outside `approvedOrigins`; or
- the private SSO binding or optional callbacks have invalid types.

Every factory call captures issuer, audience, fixed verification algorithm, and the bound SSO method in a new closure. Later mutation of the caller's config object cannot retarget an existing verifier.

## Authentication and context

`auth.authenticate(handler)` accepts one `Authorization` field containing one RFC Bearer token. It does not read an access-token cookie and does not refresh inside a protected handler. Missing, malformed, comma-combined, or multiple credentials fail closed.

A successful handler receives a detached, deeply frozen `VerifiedAuthContext`:

```ts
interface VerifiedAuthContext {
  readonly user: VerifiedAuthUser;
  readonly verification: "verified";
  readonly correlationId: string;
}
```

Authorization guards compose after authentication:

```ts
const adminRoute = auth.authenticate(
  auth.requireActiveMembership(
    auth.requireRole(["admin"], async (_request, context) =>
      Response.json({ subject: context.user.sub }),
    ),
  ),
);
```

Guards accept only the immutable context verified for their current request. Calling a guard directly, reusing a context on another request, or supplying a structural lookalike fails with `INVALID_TOKEN` before policy or handler execution. Protected routes never authenticate or refresh from cookies.

## Safe errors

Public failures use a closed JSON envelope with static messages:

```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "status": 401,
    "retryable": false,
    "message": "The access token is invalid.",
    "correlationId": "request:abc-123"
  }
}
```
| Code | HTTP | Retryable |
|---|---:|:---:|
| `REQUEST_VALIDATION_REJECTED` | 403 | No |
| `MISSING_CREDENTIALS` | 401 | No |
| `INVALID_TOKEN` | 401 | No |
| `EXPIRED_TOKEN` | 401 | No |
| `INACTIVE_MEMBERSHIP` | 403 | No |
| `FORBIDDEN_ROLE` | 403 | No |
| `FORBIDDEN_PRODUCT` | 403 | No |
| `FORBIDDEN_FEATURE` | 403 | No |
| `INVALID_COOKIE` | 401 | No |
| `REFRESH_REJECTED` | 401 | No |
| `REVOCATION_UNCONFIRMED` | 503 | Yes |
| `INVALID_RESPONSE` | 502 | No |
| `UPSTREAM_UNAVAILABLE` | 503 | Yes |
| `INTERNAL_FAILURE` | 500 | No |

Internal exception messages, stacks, credentials, claims, key material, RPC details, upstream bodies, PII, full URLs, IP addresses, and user agents are never copied to public errors. A configured correlation provider must return 1–128 characters matching `[A-Za-z0-9][A-Za-z0-9._:-]*`; invalid or throwing providers fail closed.

## Security model

- SSO Worker remains the key and credential authority through a private service binding.
- Auth Core instances hold verifier state privately and never share mutable global configuration.
- Browser UX state is not authorization evidence.
- Protected handlers receive only verified immutable context.
- There is no package-root token getter, extractor, standalone verifier, direct refresh/logout/session validation, cache reset, legacy access-cookie fallback, or credential response header.

### Refresh cookie policy

Auth Core's private Cookie Codec accepts only the application-origin host-only cookie `__Host-rm-refresh`. It validates one exact cookie occurrence without decoding the opaque value and returns typed missing/invalid outcomes so browser-route mediation can stop before private SSO RPC. Malformed fields, invalid cookie octets, duplicate or prefix-conflicting names, and values over the fixed cookie size bound fail closed.

Creation and clearing use one immutable policy: `Secure; HttpOnly; Path=/; SameSite=Strict`, with no `Domain`. Creation caps `Max-Age` to the shorter configured bound and authoritative SSO session lifetime. Clearing preserves the same identity and attributes and adds `Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`. Parent-domain sharing, `SameSite=None`, and third-party-cookie delivery are not configurable. Browser consumers never read, parse, copy, or apply `Set-Cookie`; the user agent applies it.

## Development

```bash
npm run test:run
npm run build
```

Human review is required for authentication changes before release.
