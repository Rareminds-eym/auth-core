import {
    SignJWT,
    base64url,
    exportJWK,
    generateKeyPair,
    type JWSHeaderParameters,
    type JWTPayload,
} from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "../index.js";
import type {
    AuthCoreConfig,
    SsoJwksKey,
    SsoServiceBinding,
    VerifiedAuthContext,
} from "../types/public.js";

interface SigningFixture {
    readonly privateKey: CryptoKey;
    readonly jwk: SsoJwksKey;
}

const issuer = "https://strict.issuer.example";
const audience = "strict-resource";
const correlationId = "strict-verifier-test";
let trusted: SigningFixture;
let attacker: SigningFixture;

async function createSigningFixture(kid: string): Promise<SigningFixture> {
    const pair = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(pair.publicKey);
    if (publicJwk.kty !== "RSA" || !publicJwk.n || !publicJwk.e) {
        throw new TypeError("Expected an RSA public test key.");
    }
    return {
        privateKey: pair.privateKey,
        jwk: {
            kty: "RSA",
            kid,
            alg: "RS256",
            use: "sig",
            status: "active",
            n: publicJwk.n,
            e: publicJwk.e,
        },
    };
}
function bindingFor(jwk: SsoJwksKey = trusted.jwk): SsoServiceBinding {
    return {
        getJwks: vi.fn(async ({ correlationId: requestId }) => ({
            kind: "succeeded" as const,
            correlationId: requestId,
            keys: [jwk],
            freshnessSeconds: 60,
        })),
    };
}

function configFor(sso: SsoServiceBinding): AuthCoreConfig {
    return {
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
}

async function signToken(
    claims: Record<string, unknown> = {},
    header: JWSHeaderParameters = {},
    key: CryptoKey = trusted.privateKey,
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: JWTPayload = {
        sub: "subject-1",
        email: "person@example.com",
        org_id: "org-1",
        roles: ["member"],
        products: ["passport"],
        membership_status: "active",
        is_email_verified: true,
        iss: issuer,
        aud: audience,
        iat: now,
        exp: now + 300,
        ...claims,
    };
    return new SignJWT(payload)
        .setProtectedHeader({ alg: "RS256", kid: trusted.jwk.kid, typ: "JWT", ...header })
        .sign(key);
}
function unsignedToken(header: Record<string, unknown>, payload: Record<string, unknown> = {}): string {
    return `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(payload))}.`;
}

async function authenticate(
    token: string,
    sso: SsoServiceBinding = bindingFor(),
    handler: (context: VerifiedAuthContext) => Response = () => new Response(null, { status: 204 }),
): Promise<Response> {
    return createAuth(configFor(sso)).authenticate((_request, context) => handler(context))(
        new Request("https://app.example/protected", {
            headers: { Authorization: `Bearer ${token}` },
        }),
    );
}

async function expectRejection(
    token: string,
    expectedCode = "INVALID_TOKEN",
    sso: SsoServiceBinding = bindingFor(),
): Promise<void> {
    const response = await authenticate(token, sso);
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: { code: expectedCode } });
}

beforeAll(async () => {
    [trusted, attacker] = await Promise.all([
        createSigningFixture("trusted-kid"),
        createSigningFixture("attacker-kid"),
    ]);
});

describe("Task 3.2 strict verification-only JWT predicate", () => {
    it("accepts the complete predicate without applying endpoint authorization", async () => {
        const now = Math.floor(Date.now() / 1000);
        const token = await signToken({
            membership_status: "inactive",
            roles: [],
            products: [],
            nbf: now + 20,
            user_metadata: { profile: { locale: "en" }, flags: ["beta"] },
        });
        let context: VerifiedAuthContext | undefined;

        const response = await authenticate(token, bindingFor(), (verified) => {
            context = verified;
            return new Response(null, { status: 204 });
        });

        expect(response.status).toBe(204);
        expect(context?.verification).toBe("verified");
        expect(context?.user.membership_status).toBe("inactive");
        expect(Object.isFrozen(context)).toBe(true);
        expect(Object.isFrozen(context?.user)).toBe(true);
        expect(Object.isFrozen(context?.user.roles)).toBe(true);
        expect(Object.isFrozen(context?.user.products)).toBe(true);
        expect(Object.isFrozen(context?.user.user_metadata)).toBe(true);
        expect(Object.isFrozen(context?.user.user_metadata?.profile)).toBe(true);
        expect(Object.isFrozen(context?.user.user_metadata?.flags)).toBe(true);
    });
    it("rejects none, wrong algorithms, malformed kid/type, and unsupported critical headers before key lookup", async () => {
        const cases = [
            await signToken({}, { kid: undefined }),
            await signToken({}, { kid: "" }),
            await signToken({}, { kid: " unnormalized-kid " }),
            await signToken({}, { typ: "jwt" }),
            unsignedToken({ alg: "none", kid: trusted.jwk.kid, typ: "JWT" }),
            unsignedToken({ alg: "HS256", kid: trusted.jwk.kid, typ: "JWT" }),
            unsignedToken({ alg: "RS256", kid: trusted.jwk.kid, typ: "JWT", crit: ["custom"], custom: true }),
        ];
        const sso = bindingFor();

        for (const token of cases) {
            await expectRejection(token, "INVALID_TOKEN", sso);
        }
        expect(sso.getJwks).not.toHaveBeenCalled();
    });

    it("rejects absent signatures, untrusted signatures, nonexact trust claims, and non-signing keys", async () => {
        const validPayload = {
            sub: "subject-1",
            email: "person@example.com",
            org_id: "org-1",
            roles: ["member"],
            products: ["passport"],
            membership_status: "active",
            is_email_verified: true,
            iss: issuer,
            aud: audience,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 300,
        };
        await expectRejection(unsignedToken(
            { alg: "RS256", kid: trusted.jwk.kid, typ: "JWT" },
            validPayload,
        ));
        await expectRejection(await signToken({}, { kid: trusted.jwk.kid }, attacker.privateKey));
        await expectRejection(await signToken({ iss: `${issuer}/other` }));
        await expectRejection(await signToken({ aud: [audience, "other-resource"] }));

        const encryptionKey = { ...trusted.jwk, use: "enc" } as unknown as SsoJwksKey;
        await expectRejection(await signToken(), "INVALID_TOKEN", bindingFor(encryptionKey));
    });
    it("requires valid exp and iat, applies nbf tolerance only, and rejects malformed ordering", async () => {
        const now = Math.floor(Date.now() / 1000);
        const invalidClaims: readonly Record<string, unknown>[] = [
            { exp: undefined },
            { iat: undefined },
            { exp: "soon" },
            { iat: "now" },
            { iat: now + 120 },
            { nbf: now + 120 },
            { nbf: now + 20, exp: now + 20 },
        ];
        for (const claims of invalidClaims) {
            await expectRejection(await signToken(claims));
        }
        await expectRejection(await signToken({ exp: now - 1 }), "EXPIRED_TOKEN");
        await expectRejection(
            await signToken({ iat: now - 120, exp: now - 60 }),
            "EXPIRED_TOKEN",
        );
    });

    it("rejects missing or malformed required application claims", async () => {
        const invalidClaims: readonly Record<string, unknown>[] = [
            { sub: undefined },
            { email: undefined },
            { org_id: undefined },
            { roles: ["member", 1] },
            { products: "passport" },
            { membership_status: "unknown" },
            { is_email_verified: "true" },
            { user_metadata: [] },
        ];

        for (const claims of invalidClaims) {
            await expectRejection(await signToken(claims));
        }
    });
});
