import fc from "fast-check";
import { base64url, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "../index.js";
import type {
    AuthCoreConfig,
    MembershipStatus,
    SsoJwksKey,
    SsoServiceBinding,
    VerifiedAuthContext,
} from "../types/public.js";

type AlgorithmCase = "RS256" | "PS256" | "HS256" | "none";
type KeyCase = "trusted" | "attacker";
type KidCase = "trusted" | "attacker" | "missing" | "empty" | "padded";
type TypeCase = "JWT" | "missing" | "lowercase" | "other";
type CriticalCase = "absent" | "unsupported";
type IssuerCase = "exact" | "wrong" | "missing";
type AudienceCase = "exact" | "wrong" | "array" | "missing";
type TemporalCase =
    | "valid" | "valid_nbf_tolerance" | "expired" | "future_iat"
    | "future_nbf" | "invalid_order" | "wrong_exp_type" | "missing_iat";
type ApplicationCase =
    | "valid" | "missing_sub" | "empty_sub" | "email_number" | "org_null"
    | "roles_scalar" | "roles_mixed" | "products_scalar" | "membership_unknown"
    | "verified_string";

interface RsaFixture {
    readonly privateKey: CryptoKey;
    readonly jwk: SsoJwksKey;
}
interface Scenario {
    readonly algorithm: AlgorithmCase;
    readonly key: KeyCase;
    readonly kid: KidCase;
    readonly type: TypeCase;
    readonly critical: CriticalCase;
    readonly issuer: IssuerCase;
    readonly audience: AudienceCase;
    readonly temporal: TemporalCase;
    readonly application: ApplicationCase;
    readonly sub: string;
    readonly email: string;
    readonly orgId: string;
    readonly roles: readonly string[];
    readonly products: readonly string[];
    readonly membershipStatus: MembershipStatus;
    readonly isEmailVerified: boolean;
}

const issuer = "https://property.issuer.example";
const audience = "property-resource";
const correlationId = "property-13";
const propertySeed = 0x13a11ce;
let trustedRs256: RsaFixture;
let attackerRs256: RsaFixture;
let trustedPs256: CryptoKey;
let attackerPs256: CryptoKey;
let trustedHmac: CryptoKey;
let attackerHmac: CryptoKey;

async function createRsaFixture(kid: string): Promise<RsaFixture> {
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

async function createHmacKey(seed: number): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        new Uint8Array(32).fill(seed),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
}
function protectedHeaderFor(scenario: Scenario): Record<string, unknown> {
    const header: Record<string, unknown> = { alg: scenario.algorithm };
    if (scenario.kid === "trusted") header.kid = trustedRs256.jwk.kid;
    if (scenario.kid === "attacker") header.kid = attackerRs256.jwk.kid;
    if (scenario.kid === "empty") header.kid = "";
    if (scenario.kid === "padded") header.kid = ` ${trustedRs256.jwk.kid} `;
    if (scenario.type === "JWT") header.typ = "JWT";
    if (scenario.type === "lowercase") header.typ = "jwt";
    if (scenario.type === "other") header.typ = "at+jwt";
    if (scenario.critical === "unsupported") {
        header.crit = ["property13"];
        header.property13 = true;
    }
    return header;
}

function payloadFor(scenario: Scenario, now: number): Record<string, unknown> {
    const payload: Record<string, unknown> = {
        sub: scenario.sub,
        email: scenario.email,
        org_id: scenario.orgId,
        roles: [...scenario.roles],
        products: [...scenario.products],
        membership_status: scenario.membershipStatus,
        is_email_verified: scenario.isEmailVerified,
        iss: issuer,
        aud: audience,
        iat: now - 10,
        exp: now + 300,
    };

    if (scenario.issuer === "wrong") payload.iss = `${issuer}/other`;
    if (scenario.issuer === "missing") delete payload.iss;
    if (scenario.audience === "wrong") payload.aud = `${audience}-other`;
    if (scenario.audience === "array") payload.aud = [audience, "other-resource"];
    if (scenario.audience === "missing") delete payload.aud;

    if (scenario.temporal === "valid_nbf_tolerance") payload.nbf = now + 20;
    if (scenario.temporal === "expired") payload.exp = now - 1;
    if (scenario.temporal === "future_iat") payload.iat = now + 60;
    if (scenario.temporal === "future_nbf") payload.nbf = now + 60;
    if (scenario.temporal === "invalid_order") {
        payload.nbf = now + 20;
        payload.exp = now + 20;
    }
    if (scenario.temporal === "wrong_exp_type") payload.exp = "soon";
    if (scenario.temporal === "missing_iat") delete payload.iat;

    if (scenario.application === "missing_sub") delete payload.sub;
    if (scenario.application === "empty_sub") payload.sub = "";
    if (scenario.application === "email_number") payload.email = 7;
    if (scenario.application === "org_null") payload.org_id = null;
    if (scenario.application === "roles_scalar") payload.roles = "member";
    if (scenario.application === "roles_mixed") payload.roles = ["member", 1];
    if (scenario.application === "products_scalar") payload.products = "passport";
    if (scenario.application === "membership_unknown") payload.membership_status = "unknown";
    if (scenario.application === "verified_string") payload.is_email_verified = "true";
    return payload;
}
async function tokenFor(scenario: Scenario): Promise<string> {
    const encodedHeader = base64url.encode(JSON.stringify(protectedHeaderFor(scenario)));
    const encodedPayload = base64url.encode(JSON.stringify(
        payloadFor(scenario, Math.floor(Date.now() / 1000)),
    ));
    const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
    let signature = new Uint8Array(0);

    if (scenario.algorithm === "RS256") {
        const key = scenario.key === "trusted" ? trustedRs256.privateKey : attackerRs256.privateKey;
        signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, signingInput));
    } else if (scenario.algorithm === "PS256") {
        const key = scenario.key === "trusted" ? trustedPs256 : attackerPs256;
        signature = new Uint8Array(await crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            key,
            signingInput,
        ));
    } else if (scenario.algorithm === "HS256") {
        const key = scenario.key === "trusted" ? trustedHmac : attackerHmac;
        signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, signingInput));
    }
    return `${encodedHeader}.${encodedPayload}.${base64url.encode(signature)}`;
}

function completePredicate(scenario: Scenario): boolean {
    return scenario.algorithm === "RS256" &&
        scenario.key === "trusted" &&
        scenario.kid === "trusted" &&
        scenario.type === "JWT" &&
        scenario.critical === "absent" &&
        scenario.issuer === "exact" &&
        scenario.audience === "exact" &&
        (scenario.temporal === "valid" || scenario.temporal === "valid_nbf_tolerance") &&
        scenario.application === "valid";
}

function binding(): SsoServiceBinding {
    return {
        getJwks: vi.fn(async ({ correlationId: requestId }) => ({
            kind: "succeeded" as const,
            correlationId: requestId,
            keys: [trustedRs256.jwk],
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
const scenarioArbitrary: fc.Arbitrary<Scenario> = fc.record({
    algorithm: fc.constantFrom<AlgorithmCase>("RS256", "PS256", "HS256", "none"),
    key: fc.constantFrom<KeyCase>("trusted", "attacker"),
    kid: fc.constantFrom<KidCase>("trusted", "attacker", "missing", "empty", "padded"),
    type: fc.constantFrom<TypeCase>("JWT", "missing", "lowercase", "other"),
    critical: fc.constantFrom<CriticalCase>("absent", "unsupported"),
    issuer: fc.constantFrom<IssuerCase>("exact", "wrong", "missing"),
    audience: fc.constantFrom<AudienceCase>("exact", "wrong", "array", "missing"),
    temporal: fc.constantFrom<TemporalCase>(
        "valid", "valid_nbf_tolerance", "expired", "future_iat", "future_nbf",
        "invalid_order", "wrong_exp_type", "missing_iat",
    ),
    application: fc.constantFrom<ApplicationCase>(
        "valid", "missing_sub", "empty_sub", "email_number", "org_null", "roles_scalar",
        "roles_mixed", "products_scalar", "membership_unknown", "verified_string",
    ),
    sub: fc.string({ minLength: 1, maxLength: 24 }),
    email: fc.string({ minLength: 1, maxLength: 32 }),
    orgId: fc.string({ minLength: 1, maxLength: 24 }),
    roles: fc.array(fc.string({ maxLength: 16 }), { maxLength: 3 }),
    products: fc.array(fc.string({ maxLength: 16 }), { maxLength: 3 }),
    membershipStatus: fc.constantFrom<MembershipStatus>("active", "inactive", "suspended", "expired"),
    isEmailVerified: fc.boolean(),
});

beforeAll(async () => {
    const [trusted, attacker, trustedPss, attackerPss, hmac, attackerMac] = await Promise.all([
        createRsaFixture("trusted-property-kid"),
        createRsaFixture("attacker-property-kid"),
        generateKeyPair("PS256"),
        generateKeyPair("PS256"),
        createHmacKey(0x13),
        createHmacKey(0x31),
    ]);
    trustedRs256 = trusted;
    attackerRs256 = attacker;
    trustedPs256 = trustedPss.privateKey;
    attackerPs256 = attackerPss.privateKey;
    trustedHmac = hmac;
    attackerHmac = attackerMac;
});

describe("Feature: auth-sdk-token-hardening, Property 13: JWT acceptance equals the complete verification predicate", () => {
    it("accepts if and only if every configured verification predicate holds", async () => {
        // **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.9, 29.4, 29.5**
        await fc.assert(
            fc.asyncProperty(scenarioArbitrary, async (scenario) => {
                const token = await tokenFor(scenario);
                let context: VerifiedAuthContext | undefined;
                const auth = createAuth(configFor(binding()));
                const response = await auth.authenticate((_request, verified) => {
                    context = verified;
                    return new Response(null, { status: 204 });
                })(new Request("https://app.example/protected", {
                    headers: { Authorization: `Bearer ${token}` },
                }));
                const accepted = response.status === 204 && context?.verification === "verified";
                expect(accepted).toBe(completePredicate(scenario));
            }),
            {
                numRuns: 120,
                seed: propertySeed,
                verbose: true,
            },
        );
    });
});
