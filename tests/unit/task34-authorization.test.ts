import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createAuth } from "../../src/index.js";
import type {
    AuthCoreConfig,
    SsoJwksKey,
    SsoServiceBinding,
    VerifiedAuthContext,
} from "../../src/types/public.js";

const issuer = "https://authorization.issuer.example";
const audience = "authorization-resource";
const correlationId = "task-34-guard";
let privateKey: CryptoKey;
let publicJwk: SsoJwksKey;

beforeAll(async () => {
    const pair = await generateKeyPair("RS256");
    const exported = await exportJWK(pair.publicKey);
    if (exported.kty !== "RSA" || !exported.n || !exported.e) {
        throw new TypeError("Expected an RSA public test key.");
    }
    privateKey = pair.privateKey;
    publicJwk = {
        kty: "RSA",
        kid: "task-34-key",
        alg: "RS256",
        use: "sig",
        status: "active",
        n: exported.n,
        e: exported.e,
    };
});

function fixture() {
    let keyRequests = 0;
    const sso: SsoServiceBinding = {
        async getJwks({ correlationId: requestCorrelationId }) {
            keyRequests += 1;
            return {
                kind: "succeeded",
                correlationId: requestCorrelationId,
                keys: [publicJwk],
                freshnessSeconds: 60,
            };
        },
    };
    const config: AuthCoreConfig = {
        sso,
        issuer,
        audience,
        approvedOrigins: ["https://app.example"],
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 60,
        ssoRequestTimeoutMs: 8000,
        correlationId: () => correlationId,
    };
    return { auth: createAuth(config), keyRequests: () => keyRequests };
}

async function tokenFor(overrides: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
        email: "person@example.com",
        org_id: "org-1",
        roles: ["member"],
        products: ["passport"],
        membership_status: "active",
        is_email_verified: true,
        iat: now,
        exp: now + 300,
        ...overrides,
    })
        .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid, typ: "JWT" })
        .setSubject("user-1")
        .setIssuer(issuer)
        .setAudience(audience)
        .sign(privateKey);
}

function protectedRequest(authorization?: string): Request {
    const headers = new Headers({ Cookie: "__Host-rm-refresh=must-not-be-read" });
    if (authorization !== undefined) headers.set("Authorization", authorization);
    return new Request("https://app.example/protected", { headers });
}

async function errorCode(response: Response): Promise<string> {
    const body = await response.json() as { error: { code: string } };
    return body.error.code;
}

describe("Task 3.4 authorization after verification", () => {
    it("runs every composed policy and the handler over the same immutable verified context", async () => {
        const { auth } = fixture();
        let checkedContext: VerifiedAuthContext | undefined;
        let handledContext: VerifiedAuthContext | undefined;
        const guarded = auth.requireActiveMembership(
            auth.requireRole(["member"], auth.requireProduct(["passport"],
                auth.requireFeature((_request, context) => {
                    checkedContext = context;
                    return true;
                }, (_request, context) => {
                    handledContext = context;
                    return new Response("allowed");
                }))),
        );
        const response = await auth.authenticate(guarded)(
            protectedRequest(`Bearer ${await tokenFor()}`),
        );

        expect(response.status).toBe(200);
        expect(await response.text()).toBe("allowed");
        expect(checkedContext).toBe(handledContext);
        expect(checkedContext?.verification).toBe("verified");
        expect(Object.isFrozen(checkedContext)).toBe(true);
        expect(Object.isFrozen(checkedContext?.user)).toBe(true);
    });

    it("returns each typed authorization denial as 403 without rewriting verification", async () => {
        const { auth } = fixture();
        let featureChecks = 0;
        let handlerCalls = 0;
        let deniedContext: VerifiedAuthContext | undefined;
        const guarded = auth.requireActiveMembership(
            auth.requireRole(["member"], auth.requireProduct(["passport"],
                auth.requireFeature((_request, context) => {
                    featureChecks += 1;
                    deniedContext = context;
                    return false;
                }, () => {
                    handlerCalls += 1;
                    return new Response("unexpected");
                }))),
        );
        const cases = [
            [{ membership_status: "inactive" }, "INACTIVE_MEMBERSHIP"],
            [{ roles: ["viewer"] }, "FORBIDDEN_ROLE"],
            [{ products: ["analytics"] }, "FORBIDDEN_PRODUCT"],
            [{}, "FORBIDDEN_FEATURE"],
        ] as const;

        for (const [claims, expectedCode] of cases) {
            const response = await auth.authenticate(guarded)(
                protectedRequest(`Bearer ${await tokenFor(claims)}`),
            );
            const body = await response.json() as { error: Record<string, unknown> };
            expect(response.status).toBe(403);
            expect(body.error.code).toBe(expectedCode);
            expect(body.error).not.toHaveProperty("processing");
        }
        expect(featureChecks).toBe(1);
        expect(handlerCalls).toBe(0);
        expect(deniedContext?.verification).toBe("verified");
        expect(Object.isFrozen(deniedContext)).toBe(true);
        expect(Object.isFrozen(deniedContext?.user)).toBe(true);
    });

    it("never evaluates authorization or cookies before successful Bearer verification", async () => {
        const { auth, keyRequests } = fixture();
        let policyCalls = 0;
        let handlerCalls = 0;
        const guarded = auth.requireFeature(() => {
            policyCalls += 1;
            return true;
        }, () => {
            handlerCalls += 1;
            return new Response("unexpected");
        });
        const now = Math.floor(Date.now() / 1000);
        const expired = await tokenFor({ iat: now - 600, exp: now - 1 });

        const missing = await auth.authenticate(guarded)(protectedRequest());
        const invalid = await auth.authenticate(guarded)(protectedRequest("Bearer not-a-jwt"));
        const expiredResponse = await auth.authenticate(guarded)(
            protectedRequest(`Bearer ${expired}`),
        );

        expect([missing.status, invalid.status, expiredResponse.status]).toEqual([401, 401, 401]);
        expect(await errorCode(missing.clone())).toBe("MISSING_CREDENTIALS");
        expect(await errorCode(invalid.clone())).toBe("INVALID_TOKEN");
        await expect(missing.json()).resolves.not.toMatchObject({
            error: { processing: "pre_handler" },
        });
        await expect(invalid.json()).resolves.not.toMatchObject({
            error: { processing: "pre_handler" },
        });
        await expect(expiredResponse.json()).resolves.toMatchObject({
            error: { code: "EXPIRED_TOKEN", processing: "pre_handler" },
        });
        expect(policyCalls).toBe(0);
        expect(handlerCalls).toBe(0);
        expect(keyRequests()).toBe(1);
    });

    it("fails closed when feature policy evaluation throws without invoking the handler", async () => {
        const { auth } = fixture();
        let handlerCalls = 0;
        const guarded = auth.requireFeature(async () => {
            throw new Error("Bearer secret.jwt Cookie=session person@example.com");
        }, () => {
            handlerCalls += 1;
            return new Response("unexpected");
        });

        const response = await auth.authenticate(guarded)(
            protectedRequest(`Bearer ${await tokenFor()}`),
        );
        const serialized = await response.text();

        expect(response.status).toBe(500);
        expect(serialized).toContain("INTERNAL_FAILURE");
        expect(serialized).not.toMatch(/secret\.jwt|Cookie|person@example/);
        expect(handlerCalls).toBe(0);
    });

    it("rejects forged verified-context lookalikes without parsing or verifying request credentials", async () => {
        const { auth, keyRequests } = fixture();
        let policyCalls = 0;
        const guarded = auth.requireFeature(() => {
            policyCalls += 1;
            return true;
        }, () => new Response("unexpected"));
        const forgedContext: VerifiedAuthContext = Object.freeze({
            verification: "verified",
            correlationId,
            user: Object.freeze({
                sub: "user-1",
                email: "person@example.com",
                org_id: "org-1",
                roles: Object.freeze(["member"]),
                products: Object.freeze(["passport"]),
                membership_status: "active",
                is_email_verified: true,
            }),
        });
        const request = protectedRequest(`Bearer ${await tokenFor()}`);

        const response = await guarded(request, forgedContext);

        expect(response.status).toBe(401);
        expect(await errorCode(response)).toBe("INVALID_TOKEN");
        expect(policyCalls).toBe(0);
        expect(keyRequests()).toBe(0);
    });

    it("requires feature callbacks to return literal true", async () => {
        const { auth } = fixture();
        const nonBooleanCheck = (() => "truthy") as unknown as Parameters<typeof auth.requireFeature>[0];
        const handler = () => new Response("unexpected");
        const response = await auth.authenticate(auth.requireFeature(nonBooleanCheck, handler))(
            protectedRequest(`Bearer ${await tokenFor()}`),
        );

        expect(response.status).toBe(403);
        expect(await errorCode(response)).toBe("FORBIDDEN_FEATURE");
    });

    it("rejects ambiguous policy declarations before handling a request", () => {
        const { auth, keyRequests } = fixture();
        const handler = () => new Response("unexpected");

        expect(() => auth.requireRole([], handler)).toThrow(/normalized non-empty strings/);
        expect(() => auth.requireRole(["member", "member"], handler)).toThrow(/duplicates/);
        expect(() => auth.requireRole([" member"], handler)).toThrow(/normalized non-empty strings/);
        expect(() => auth.requireProduct([1] as unknown as readonly string[], handler))
            .toThrow(/normalized non-empty strings/);
        expect(() => auth.requireFeature(null as unknown as Parameters<typeof auth.requireFeature>[0], handler))
            .toThrow(/Feature check must be a function/);
        expect(keyRequests()).toBe(0);
    });
});
