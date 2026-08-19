import {
    SignJWT,
    exportJWK,
    generateKeyPair
} from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import * as packageRoot from "../index.js";
import { createAuth } from "../index.js";
import { ERROR_DEFINITIONS, describeError } from "../internal/errors.js";
import type {
    AuthCoreConfig,
    SsoJwksKey,
    SsoServiceBinding,
    VerifiedAuthContext
} from "../types/public.js";

interface SigningFixture {
    readonly privateKey: CryptoKey;
    readonly jwk: SsoJwksKey;
    readonly issuer: string;
    readonly audience: string;
}

const correlationId = "correlation-test-1";

function jwksSucceeded(jwk: SsoJwksKey, id = correlationId) {
    return {
        kind: "succeeded" as const,
        correlationId: id,
        keys: [jwk],
        freshnessSeconds: 60,
    };
}

async function signingFixture(name: string): Promise<SigningFixture> {
    const pair = await generateKeyPair("RS256");
    const exported = await exportJWK(pair.publicKey);
    if (exported.kty !== "RSA" || typeof exported.n !== "string" || typeof exported.e !== "string") {
        throw new TypeError("Expected an RSA public test key.");
    }
    return {
        privateKey: pair.privateKey,
        jwk: {
            kty: "RSA",
            n: exported.n,
            e: exported.e,
            kid: `${name}-kid`,
            alg: "RS256",
            use: "sig",
            status: "active",
        },
        issuer: `https://${name}.issuer.example`,
        audience: `${name}-audience`,
    };
}

function issuedLogin() {
    return vi.fn(async ({ correlationId }) => ({
        kind: "issued" as const,
        correlationId,
        session: {
            accessToken: "access-1",
            refreshToken: "refresh-1",
            remainingLifetimeSeconds: 3600,
            identity: { sub: "user-1" },
        },
    }));
}

function bindingFor(jwk: SsoJwksKey): SsoServiceBinding {
    return {
        getJwks: vi.fn(async ({ correlationId }) => jwksSucceeded(jwk, correlationId)),
        login: issuedLogin(),
    };
}
function configFor(fixture: SigningFixture, sso = bindingFor(fixture.jwk)): AuthCoreConfig {
    return {
        sso,
        issuer: fixture.issuer,
        audience: fixture.audience,
        approvedOrigins: ["https://app.example"],
        basePath: "/api/auth",
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 60,
        ssoRequestTimeoutMs: 8000,
        correlationId: () => "correlation-test-1",
    };
}

async function tokenFor(
    fixture: SigningFixture,
    overrides: Record<string, unknown> = {},
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
        email: "person@example.com",
        org_id: "org-1",
        roles: ["member"],
        products: ["passport"],
        membership_status: "active",
        is_email_verified: true,
        user_metadata: { preferences: { locale: "en" } },
        ...overrides,
    })
        .setProtectedHeader({ alg: "RS256", kid: fixture.jwk.kid, typ: "JWT" })
        .setSubject("user-1")
        .setIssuer(fixture.issuer)
        .setAudience(fixture.audience)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(fixture.privateKey);
}

async function errorBody(response: Response) {
    return response.json() as Promise<{ error: Record<string, unknown> }>;
}

let primary: SigningFixture;

beforeAll(async () => {
    primary = await signingFixture("primary");
});
describe("createAuth configuration", () => {
    it.each([
        "*",
        "https://*.example",
        "null",
        "http://app.example",
        "file:///tmp/auth",
        "https://app.example/path",
        "https://app.example/",
        "https://app.example?query=1",
        "https://user@app.example",
    ])("rejects wildcard, opaque, insecure, or path-bearing origin %s", (origin) => {
        expect(() => createAuth({ ...configFor(primary), approvedOrigins: [origin] }))
            .toThrow(/Invalid Auth Core configuration/);
    });

    it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5, 2_147_483_648])(
        "rejects invalid numeric bound %s",
        (bound) => {
            expect(() => createAuth({ ...configFor(primary), ssoRequestTimeoutMs: bound }))
                .toThrow(/positive finite safe integer/);
            expect(() => createAuth({ ...configFor(primary), cookieMaxAgeSeconds: bound }))
                .toThrow(/positive finite safe integer/);
            expect(() => createAuth({ ...configFor(primary), jwksMaxAgeSeconds: bound }))
                .toThrow(/positive finite safe integer/);
        },
    );

    it("rejects cross-origin or non-normalized base paths and non-exact CSRF", () => {
        for (const basePath of ["https://other.example/api/auth", "//other.example/auth", "/api/../auth", "/api/auth/"]) {
            expect(() => createAuth({ ...configFor(primary), basePath })).toThrow(/basePath/);
        }
        expect(() => createAuth({
            ...configFor(primary),
            csrf: { name: "X-RM-CSRF", value: "wrong" } as unknown as AuthCoreConfig["csrf"],
        })).toThrow(/csrf/);
    });

    it("rejects CORS origins outside the exact approved allowlist", () => {
        expect(() => createAuth({
            ...configFor(primary),
            credentialedCors: { origins: ["https://other.example"] },
        })).toThrow(/approved origins/);
    });

    it("keeps every RPC method on a workerd-style service-binding stub", async () => {
        // Workerd exposes binding RPC methods only through the proxy get trap;
        // they are never own enumerable properties, so an object spread drops them.
        const rpcMethods = ["getJwks", "login", "signup", "refreshCurrentSession", "logoutCurrentSession"];
        const login = vi.fn(async ({ correlationId }) => ({
            kind: "issued" as const,
            correlationId,
            session: {
                accessToken: "access-1",
                refreshToken: "refresh-1",
                remainingLifetimeSeconds: 3600,
                identity: { sub: "user-1" },
            },
        }));
        const stub = new Proxy({}, {
            get(_target, prop) {
                if (prop === "getJwks") return async ({ correlationId }) => jwksSucceeded(primary.jwk, correlationId);
                if (prop === "login") return login;
                return undefined;
            },
            ownKeys() {
                return rpcMethods;
            },
            getOwnPropertyDescriptor() {
                return undefined;
            },
        }) as SsoServiceBinding;

        const auth = createAuth(configFor(primary, stub));
        const response = await auth.handleBrowserRequest(new Request("https://app.example/api/auth/login", {
            method: "POST",
            headers: {
                "Origin": "https://app.example",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "X-RM-CSRF": "1",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ email: "person@example.com", password: "hunter2" }),
        }));

        expect(response.status).toBe(200);
        expect(login).toHaveBeenCalledWith(expect.objectContaining({
            email: "person@example.com",
            password: "hunter2",
        }));
    });

    it("publishes only the approved package-root runtime factory", () => {
        expect(Object.keys(packageRoot)).toEqual(["createAuth"]);
    });
});
describe("authentication boundary", () => {
    it("accepts normalized Bearer scheme casing and publishes a deeply immutable context", async () => {
        const auth = createAuth(configFor(primary));
        const token = await tokenFor(primary);
        let received: VerifiedAuthContext | undefined;
        const response = await auth.authenticate((_request, context) => {
            received = context;
            return Response.json({ subject: context.user.sub });
        })(new Request("https://app.example/protected", {
            headers: { Authorization: `bEaReR ${token}` },
        }));

        expect(response.status).toBe(200);
        expect(received?.verification).toBe("verified");
        expect(received?.correlationId).toBe("correlation-test-1");
        expect(Object.isFrozen(received)).toBe(true);
        expect(Object.isFrozen(received?.user)).toBe(true);
        expect(Object.isFrozen(received?.user.roles)).toBe(true);
        expect(Object.isFrozen(received?.user.user_metadata)).toBe(true);
        expect(Object.isFrozen((received?.user.user_metadata?.preferences as object))).toBe(true);
    });

    it.each([
        [undefined, "MISSING_CREDENTIALS"],
        ["Basic abc", "INVALID_TOKEN"],
        ["Bearer", "INVALID_TOKEN"],
        ["Bearer  abc", "INVALID_TOKEN"],
        ["Bearer\tabc", "INVALID_TOKEN"],
        ["Bearer abc def", "INVALID_TOKEN"],
        ["Bearer abc, Bearer def", "INVALID_TOKEN"],
    ])("rejects non-exact singleton Authorization value %s", async (authorization, code) => {
        const auth = createAuth(configFor(primary));
        const headers = authorization === undefined ? undefined : { Authorization: authorization };
        const response = await auth.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/protected", { headers }),
        );
        expect(response.status).toBe(401);
        expect((await errorBody(response)).error.code).toBe(code);
    });

    it("rejects Headers-normalized duplicate Authorization values", async () => {
        const headers = new Headers();
        headers.append("Authorization", "Bearer abc");
        headers.append("Authorization", "Bearer def");
        const response = await createAuth(configFor(primary))
            .authenticate(() => new Response("unexpected"))(
                new Request("https://app.example/protected", { headers }),
            );
        expect((await errorBody(response)).error.code).toBe("INVALID_TOKEN");
    });
});
describe("instance isolation and redaction", () => {
    it("cannot reuse verifier state after caller config and binding mutation", async () => {
        const secondary = await signingFixture("secondary");
        const primaryBinding = bindingFor(primary.jwk);
        const mutable = {
            ...configFor(primary, primaryBinding),
            approvedOrigins: ["https://app.example"],
        };
        const first = createAuth(mutable);

        mutable.issuer = secondary.issuer;
        mutable.audience = secondary.audience;
        mutable.approvedOrigins[0] = "https://mutated.example";
        mutable.sso = bindingFor(secondary.jwk);
        const second = createAuth(configFor(secondary, mutable.sso));

        const firstResponse = await first.authenticate((_request, context) => Response.json(context.user))(
            new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
            }),
        );
        const secondResponse = await second.authenticate((_request, context) => Response.json(context.user))(
            new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${await tokenFor(secondary)}` },
            }),
        );
        const firstWithChangedTrust = await first.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${await tokenFor(secondary)}` },
            }),
        );
        const secondWithPriorTrust = await second.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
            }),
        );

        expect(firstResponse.status).toBe(200);
        expect(secondResponse.status).toBe(200);
        expect(firstWithChangedTrust.status).toBe(401);
        expect((await errorBody(firstWithChangedTrust)).error.code).toBe("INVALID_TOKEN");
        expect(secondWithPriorTrust.status).toBe(401);
        expect((await errorBody(secondWithPriorTrust)).error.code).toBe("INVALID_TOKEN");
        expect(primaryBinding.getJwks).toHaveBeenCalledTimes(2);
        expect(mutable.sso.getJwks).toHaveBeenCalledTimes(2);
    });

    it("propagates only a validated correlation identifier to the private binding", async () => {
        const sso = bindingFor(primary.jwk);
        const auth = createAuth({ ...configFor(primary, sso), correlationId: () => "request:abc-123" });
        const response = await auth.authenticate(() => new Response("ok"))(
            new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
            }),
        );
        expect(response.status).toBe(200);
        expect(sso.getJwks).toHaveBeenCalledWith({ correlationId: "request:abc-123" });
    });

    it("maps closed transient JWKS outcomes and rejects mismatched outcome correlation", async () => {
        const transientBinding: SsoServiceBinding = {
            getJwks: vi.fn(async ({ correlationId }) => ({ kind: "timeout" as const, correlationId })),
            login: issuedLogin(),
        };
        const transient = await createAuth(configFor(primary, transientBinding))
            .authenticate(() => new Response("unexpected"))(
                new Request("https://app.example/protected", {
                    headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
                }),
            );
        expect(transient.status).toBe(503);
        expect((await errorBody(transient)).error.code).toBe("UPSTREAM_UNAVAILABLE");

        const mismatchedBinding: SsoServiceBinding = {
            getJwks: vi.fn(async () => jwksSucceeded(primary.jwk, "different-correlation")),
            login: issuedLogin(),
        };
        const mismatched = await createAuth(configFor(primary, mismatchedBinding))
            .authenticate(() => new Response("unexpected"))(
                new Request("https://app.example/protected", {
                    headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
                }),
            );
        expect(mismatched.status).toBe(502);
        expect((await errorBody(mismatched)).error.code).toBe("INVALID_RESPONSE");
    });

    it.each([
        () => "contains space",
        () => "https://secret.example/path",
        () => "line\r\nbreak",
        () => "x".repeat(129),
        () => { throw new Error("Bearer secret-token person@example.com"); },
    ])("fails closed for an invalid correlation provider without echoing details", async (provider) => {
        const auth = createAuth({ ...configFor(primary), correlationId: provider });
        const response = await auth.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/private?secret=yes", {
                headers: { Authorization: "Bearer secret-token" },
            }),
        );
        const serialized = await response.text();
        expect(response.status).toBe(500);
        expect(serialized).toContain("INTERNAL_FAILURE");
        expect(serialized).not.toMatch(/secret-token|person@example|secret=yes|contains space/);
    });

    it("redacts upstream exceptions and handler exceptions into static errors", async () => {
        const leakingBinding: SsoServiceBinding = {
            getJwks: async () => {
                throw new Error("Bearer private.jwt Cookie=session person@example.com https://internal/path");
            },
            login: issuedLogin(),
        };
        const upstream = await createAuth(configFor(primary, leakingBinding))
            .authenticate(() => new Response("unexpected"))(
                new Request("https://app.example/private", {
                    headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
                }),
            );
        const upstreamText = await upstream.text();
        expect(upstream.status).toBe(503);
        expect(upstreamText).toContain("UPSTREAM_UNAVAILABLE");
        expect(upstreamText).not.toMatch(/private\.jwt|Cookie|person@example|internal\/path/);

        const handler = await createAuth(configFor(primary))
            .authenticate(() => { throw new Error("stack token Cookie IP 192.0.2.1"); })(
                new Request("https://app.example/private", {
                    headers: { Authorization: `Bearer ${await tokenFor(primary)}` },
                }),
            );
        const handlerText = await handler.text();
        expect(handler.status).toBe(500);
        expect(handlerText).toContain("INTERNAL_FAILURE");
        expect(handlerText).not.toMatch(/stack token|Cookie|192\.0\.2\.1/);
    });
});
describe("total static Auth Core error mapping", () => {
    it("maps every closed error code to one frozen status, retryability, and safe message", () => {
        const expected: Record<string, readonly [number, boolean]> = {
            REQUEST_VALIDATION_REJECTED: [403, false],
            MISSING_CREDENTIALS: [401, false],
            INVALID_TOKEN: [401, false],
            EXPIRED_TOKEN: [401, false],
            INACTIVE_MEMBERSHIP: [403, false],
            FORBIDDEN_ROLE: [403, false],
            FORBIDDEN_PRODUCT: [403, false],
            FORBIDDEN_FEATURE: [403, false],
            INVALID_COOKIE: [401, false],
            REFRESH_REJECTED: [401, false],
            REVOCATION_UNCONFIRMED: [503, true],
            INVALID_REQUEST_BODY: [400, false],
            NOT_FOUND: [404, false],
            CONFLICT: [409, false],
            REAUTHENTICATION_REQUIRED: [401, false],
            INVALID_RESPONSE: [502, false],
            UPSTREAM_UNAVAILABLE: [503, true],
            INTERNAL_FAILURE: [500, false],
        };

        expect(Object.keys(ERROR_DEFINITIONS).sort()).toEqual(Object.keys(expected).sort());
        for (const [code, [status, retryable]] of Object.entries(expected)) {
            const descriptor = describeError(code as keyof typeof ERROR_DEFINITIONS, "correlation-safe");
            expect(descriptor).toMatchObject({ code, status, retryable, correlationId: "correlation-safe" });
            expect(descriptor.message).toMatch(/^[A-Z][^\r\n]{1,127}\.$/);
            expect(Object.isFrozen(descriptor)).toBe(true);
            expect(descriptor).not.toHaveProperty("cause");
            expect(descriptor).not.toHaveProperty("stack");
        }
    });
});

describe("SDK-private browser wire contract (auth-client envelope)", () => {
    const ROUTE_HEADERS = Object.freeze({
        "Origin": "https://app.example",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "X-RM-CSRF": "1",
        "Content-Type": "application/json",
    });

    const IDENTITY = Object.freeze({
        subject: "user-1",
        email: "person@example.com",
        organizationId: "org-1",
        roles: Object.freeze(["member"]),
        products: Object.freeze(["passport"]),
        membershipStatus: "active",
        emailVerified: true,
    });

    function issuedSession(overrides: Record<string, unknown> = {}): Record<string, unknown> {
        return {
            accessToken: "access-1",
            refreshToken: "refresh-1",
            remainingLifetimeSeconds: 3600,
            identity: { ...IDENTITY, ...overrides },
        };
    }

    function sessionBinding(outcome: Record<string, unknown>): SsoServiceBinding {
        return {
            getJwks: vi.fn(async ({ correlationId }) => jwksSucceeded(primary.jwk, correlationId)),
            login: vi.fn(async ({ correlationId }) => ({ kind: "issued" as const, correlationId, session: outcome })),
        };
    }

    function routeRequest(path: string, init: RequestInit = {}): Request {
        return new Request(`https://app.example/api/auth${path}`, {
            method: "POST",
            headers: ROUTE_HEADERS,
            ...init,
        });
    }

    function sessionBindingFor(sso: SsoServiceBinding): SsoServiceBinding {
        return {
            getJwks: vi.fn(async ({ correlationId }) => jwksSucceeded(primary.jwk, correlationId)),
            login: vi.fn(async ({ correlationId }) => ({ kind: "issued" as const, correlationId, session: issuedSession() })),
            ...sso,
        };
    }

    it("emits the exact session envelope, required headers, and refresh cookie on login", async () => {
        const auth = createAuth(configFor(primary, sessionBindingFor({})));
        const response = await auth.handleBrowserRequest(routeRequest("/login", {
            body: JSON.stringify({ email: "person@example.com", password: "hunter2" }),
        }));

        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        expect(response.headers.get("expires")).toBe("Thu, 01 Jan 1970 00:00:00 GMT");
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect(response.headers.get("set-cookie")).toContain("__Host-rm-refresh=refresh-1;");
        const body = await response.json();
        expect(body).toEqual({
            ok: true,
            credential: { accessToken: "access-1" },
            identity: IDENTITY,
            outcome: "created",
            data: { identity: IDENTITY },
            correlationId,
        });
    });

    it("maps signup RPC outcome to identity, organization, and emailSent data", async () => {
        const sso = {
            signup: vi.fn(async ({ correlationId }) => ({
                kind: "issued" as const,
                correlationId,
                emailSent: true,
                session: issuedSession(),
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(routeRequest("/signup", {
            body: JSON.stringify({ email: "person@example.com", password: "hunter2", organizationName: "Rareminds", role: "owner" }),
        }));

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.ok).toBe(true);
        expect(body.outcome).toBe("created");
        expect(body.data).toEqual({
            identity: IDENTITY,
            organization: { id: "org-1", name: null, slug: null, roles: ["member"], active: true },
            emailSent: true,
        });
    });

    it("rejects session failures with the exact client rejection vocabulary", async () => {
        const sso = {
            login: vi.fn(async ({ correlationId }) => ({
                kind: "rejected" as const, correlationId, code: "invalid_credentials",
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(routeRequest("/login", {
            body: JSON.stringify({ email: "person@example.com", password: "wrong" }),
        }));

        expect(response.status).toBe(401);
        expect(await response.json()).toEqual({ status: "rejected", code: "invalid_credentials" });
        expect(response.headers.get("set-cookie")).toBeNull();
    });

    it("rejects workflow failures with the exact client rejection vocabulary", async () => {
        const sso = {
            forgotPassword: vi.fn(async ({ correlationId }) => ({
                kind: "rejected" as const, correlationId, code: "not_found",
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(routeRequest("/password/forgot", {
            body: JSON.stringify({ email: "missing@example.com" }),
        }));

        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({ status: "rejected", code: "not_found" });
    });

    it("serves /me as a GET workflow with a Bearer access token", async () => {
        const sso = {
            getIdentity: vi.fn(async ({ correlationId }) => ({
                kind: "succeeded" as const, correlationId, data: IDENTITY,
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(new Request("https://app.example/api/auth/me", {
            method: "GET",
            headers: {
                "Origin": "https://app.example",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "X-RM-CSRF": "1",
                "Authorization": "Bearer access-1",
            },
        }));

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ status: "succeeded", data: IDENTITY });
        expect(sso.getIdentity).toHaveBeenCalledWith({ correlationId, accessToken: "access-1" });
    });

    it("maps /organizations RPC organizationId fields to the client id shape", async () => {
        const sso = {
            listOrganizations: vi.fn(async ({ correlationId }) => ({
                kind: "succeeded" as const,
                correlationId,
                data: { organizations: [{ organizationId: "org-1", name: "Rareminds", slug: "rareminds", roles: ["owner"], active: true }] },
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(new Request("https://app.example/api/auth/organizations", {
            method: "GET",
            headers: {
                "Origin": "https://app.example",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "X-RM-CSRF": "1",
                "Authorization": "Bearer access-1",
            },
        }));

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({
            status: "succeeded",
            data: { organizations: [{ id: "org-1", name: "Rareminds", slug: "rareminds", roles: ["owner"], active: true }] },
        });
    });

    it("returns the closed logout result shape on session revocation", async () => {
        const sso = {
            logoutCurrentSession: vi.fn(async ({ correlationId }) => ({
                kind: "current_revoked" as const, correlationId,
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(routeRequest("/logout/current", {
            headers: {
                ...ROUTE_HEADERS,
                "Cookie": "__Host-rm-refresh=refresh-1",
            },
            body: "{}",
        }));

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ outcome: "current_session_revoked", cookieClearing: "confirmed" });
        expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    });

    it("rejects definitive /session rotation failures with a cleared cookie", async () => {
        const sso = {
            refreshCurrentSession: vi.fn(async ({ correlationId }) => ({
                kind: "rejected" as const, correlationId, code: "expired",
            })),
        };
        const auth = createAuth(configFor(primary, sessionBindingFor(sso)));
        const response = await auth.handleBrowserRequest(routeRequest("/session", {
            headers: {
                ...ROUTE_HEADERS,
                "Cookie": "__Host-rm-refresh=refresh-1",
            },
            body: "{}",
        }));

        expect(response.status).toBe(401);
        expect(await response.json()).toEqual({ status: "rejected", code: "not_authenticated" });
        expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    });
});
