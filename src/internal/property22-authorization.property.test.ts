import fc from "fast-check";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { retainedPropertyParameters } from "../../../tools/auth-test-infrastructure/pbt.mjs";
import { createAuth } from "../index.js";
import type {
    AuthCoreConfig,
    MembershipStatus,
    SsoJwksKey,
    SsoServiceBinding,
    VerifiedAuthContext,
} from "../types/public.js";

const issuer = "https://property-22.issuer.example";
const audience = "property-22-resource";
// Correlation IDs reject security-sensitive vocabulary before verification starts.
const correlationId = "property-22-policy";
const roleNames = ["admin", "auditor", "member", "viewer"] as const;
const productNames = ["analytics", "lte", "passport", "reports"] as const;
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
        kty: "RSA", kid: "property-22-key", alg: "RS256", use: "sig", status: "active",
        n: exported.n, e: exported.e,
    };
});

const scenarioArbitrary = fc.record({
    subject: fc.uuid(),
    email: fc.emailAddress(),
    organizationId: fc.uuid(),
    membership: fc.constantFrom<MembershipStatus>("active", "inactive", "suspended", "expired"),
    roles: fc.uniqueArray(fc.constantFrom(...roleNames), { maxLength: roleNames.length }),
    products: fc.uniqueArray(fc.constantFrom(...productNames), { maxLength: productNames.length }),
    allowedRoles: fc.uniqueArray(fc.constantFrom(...roleNames), { minLength: 1, maxLength: roleNames.length }),
    allowedProducts: fc.uniqueArray(fc.constantFrom(...productNames), { minLength: 1, maxLength: productNames.length }),
    emailVerified: fc.boolean(),
    featurePermitted: fc.boolean(),
    asynchronousFeature: fc.boolean(),
});

function fixture() {
    const sso: SsoServiceBinding = {
        async getJwks({ correlationId: requestCorrelationId }) {
            return {
                kind: "succeeded", correlationId: requestCorrelationId,
                keys: [publicJwk], freshnessSeconds: 3600,
            };
        },
    };
    const config: AuthCoreConfig = {
        sso, issuer, audience, approvedOrigins: ["https://app.example"],
        csrf: { name: "X-RM-CSRF", value: "1" }, cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 3600, ssoRequestTimeoutMs: 8000,
        correlationId: () => correlationId,
    };
    return createAuth(config);
}

type Scenario = typeof scenarioArbitrary extends fc.Arbitrary<infer Value> ? Value : never;

async function tokenFor(scenario: Scenario): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
        email: scenario.email,
        org_id: scenario.organizationId,
        roles: scenario.roles,
        products: scenario.products,
        membership_status: scenario.membership,
        is_email_verified: scenario.emailVerified,
        iat: now - 1,
        exp: now + 300,
    })
        .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid, typ: "JWT" })
        .setSubject(scenario.subject)
        .setIssuer(issuer)
        .setAudience(audience)
        .sign(privateKey);
}

describe("auth-hardening.property", () => {
    it("Feature: auth-sdk-token-hardening, Property 22: Verification and endpoint authorization are separate decisions", async () => {
        // **Validates: Requirements 1.6, 12.2, 29.4, 29.6, 29.7**
        const auth = fixture();

        await fc.assert(fc.asyncProperty(scenarioArbitrary, async (scenario) => {
            let capturedContext: VerifiedAuthContext | undefined;
            let rewriteSucceeded: boolean | undefined;
            let featureCalls = 0;
            let handlerCalls = 0;
            const rolePermitted = scenario.roles.some((role) => scenario.allowedRoles.includes(role));
            const productPermitted = scenario.products.some((product) => scenario.allowedProducts.includes(product));
            const policiesPermit = scenario.membership === "active" && rolePermitted &&
                productPermitted && scenario.featurePermitted;
            const featureCheck = () => {
                featureCalls += 1;
                return scenario.asynchronousFeature
                    ? Promise.resolve(scenario.featurePermitted)
                    : scenario.featurePermitted;
            };
            const guarded = auth.requireFeature((_request, context) => {
                capturedContext = context;
                rewriteSucceeded = Reflect.set(context, "verification", "rewritten");
                return true;
            }, auth.requireActiveMembership(
                auth.requireRole(scenario.allowedRoles,
                    auth.requireProduct(scenario.allowedProducts,
                        auth.requireFeature(featureCheck, () => {
                            handlerCalls += 1;
                            return new Response("handled");
                        }))),
            ));
            const token = await tokenFor(scenario);
            const response = await auth.authenticate(guarded)(new Request("https://app.example/protected", {
                headers: { Authorization: `Bearer ${token}` },
            }));

            expect(capturedContext?.verification).toBe("verified");
            expect(rewriteSucceeded).toBe(false);
            expect(Object.isFrozen(capturedContext)).toBe(true);
            expect(Object.isFrozen(capturedContext?.user)).toBe(true);
            expect(handlerCalls).toBe(policiesPermit ? 1 : 0);
            expect(featureCalls).toBe(
                scenario.membership === "active" && rolePermitted && productPermitted ? 1 : 0,
            );
            expect(response.status).toBe(policiesPermit ? 200 : 403);
            if (policiesPermit) {
                await expect(response.text()).resolves.toBe("handled");
                return;
            }
            const expectedCode = scenario.membership !== "active" ? "INACTIVE_MEMBERSHIP"
                : !rolePermitted ? "FORBIDDEN_ROLE"
                    : !productPermitted ? "FORBIDDEN_PRODUCT" : "FORBIDDEN_FEATURE";
            const body = await response.json() as { error: Record<string, unknown> };
            expect(body.error.code).toBe(expectedCode);
            expect(body.error).not.toHaveProperty("processing");
            expect(capturedContext?.verification).toBe("verified");
        }), retainedPropertyParameters({
            suiteId: "auth-hardening.property",
            property: "22-verification-and-endpoint-authorization-are-separate-decisions",
        }));
    }, 30_000);
});
