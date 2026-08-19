import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { createCookieCodec } from "./cookieCodec.js";
import { SafeObserver } from "./observability.js";
import { BrowserAuthRoute } from "./browser-route-guard.js";
import { retainedPropertyParameters } from "../../../tools/auth-test-infrastructure/pbt.mjs";
import { createWorkflowRouteHandler } from "./browser-workflow-routes.js";

const legacyCredentialArbitrary = fc.record({
    authorization: fc.option(fc.string(), { nil: undefined }),
    cookie: fc.option(fc.string(), { nil: undefined }),
    xAccessToken: fc.option(fc.string(), { nil: undefined }),
});

const IDENTITY = { subject: "u1", email: "a@b.c", organizationId: "org-1", roles: ["member"], products: [], membershipStatus: "active", emailVerified: true };

const ROUTES = [
    { route: { kind: "browser", method: "POST", prefix: "/auth", suffix: "/session/organization" } as BrowserAuthRoute, body: { organizationId: "org_1" } },
    { route: { kind: "browser", method: "POST", prefix: "/auth", suffix: "/password/reset" } as BrowserAuthRoute, body: { resetToken: "tok", password: "pw" } },
    { route: { kind: "browser", method: "POST", prefix: "/auth", suffix: "/logout/all" } as BrowserAuthRoute, body: {} },
];

describe("auth-hardening.property", () => {
    it("Feature: auth-sdk-token-hardening, Property 23: Legacy credentials are cleanup-only and implement bounded cleanup handling", async () => {
        // **Validates: Requirements 18.1, 18.2, 18.3, 28.1, 28.2**
        await fc.assert(fc.asyncProperty(legacyCredentialArbitrary, fc.constantFrom(...ROUTES), async (creds, scenario) => {
            const sso = {
                login: vi.fn(async () => ({ kind: "issued", session: { accessToken: "a", refreshToken: "rt", remainingLifetimeSeconds: 3600, identity: IDENTITY } })),
                logoutAllSessions: vi.fn(async () => ({ kind: "all_revoked" })),
                resetPassword: vi.fn(async () => ({ kind: "issued", data: { reset: true }, session: { accessToken: "a", refreshToken: "rt", remainingLifetimeSeconds: 3600, identity: IDENTITY } })),
                changeOrganization: vi.fn(async () => ({ kind: "rotated", session: { accessToken: "a", refreshToken: "rt", remainingLifetimeSeconds: 3600, identity: IDENTITY } })),
            };
            const config = {
                sso,
                issuer: "https://issuer",
                audience: "aud",
                approvedOrigins: ["https://app"],
                csrf: { name: "X-RM-CSRF", value: "1" },
                cookieMaxAgeSeconds: 3600,
                ssoRequestTimeoutMs: 8000,
                correlationId: () => "test",
            } as any;

            const cookieCodec = createCookieCodec(3600);
            const telemetry = new SafeObserver(config);
            const handler = createWorkflowRouteHandler(config, telemetry, cookieCodec);

            const headers = new Headers();
            if (creds.authorization) headers.set("Authorization", creds.authorization);
            if (creds.cookie) headers.set("Cookie", creds.cookie);
            if (creds.xAccessToken) headers.set("X-Access-Token", creds.xAccessToken);

            // Authorization Bearer is the sanctioned SDK transport; only X-Access-Token is tombstoned.
            const legacyPresent = Boolean(creds.xAccessToken);

            const req = new Request(`https://api.example.com${scenario.route.prefix}${scenario.route.suffix}`, {
                method: "POST",
                headers,
                body: JSON.stringify(scenario.body)
            });

            const response = await handler(scenario.route, req);

            if (legacyPresent) {
                // Fast boundary rejection (401) before any RPC, regardless of header content or route.
                expect(response.status).toBe(401);
                const body = await response.json().catch(() => null);
                expect(body).toBeDefined();
                expect(body.error).toBeDefined();
                expect(body.error.code).toBe("REAUTHENTICATION_REQUIRED");
                // Bounded cleanup: the current credential cookie is cleared.
                expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
                // Side-effect-free: no RPC method was invoked.
                for (const method of Object.values(sso)) {
                    expect(method).not.toHaveBeenCalled();
                }
            } else {
                // Without legacy credentials the workflow proceeds normally; no tombstone is emitted.
                const body = await response.json().catch(() => null);
                expect(body?.error?.code).not.toBe("REAUTHENTICATION_REQUIRED");
            }
        }), retainedPropertyParameters({
            suiteId: "auth-hardening.property",
            property: "23-legacy-credentials-are-cleanup-only"
        }));
    });
});