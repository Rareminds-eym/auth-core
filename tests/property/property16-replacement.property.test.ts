import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { retainedPropertyParameters } from "../../../tools/auth-test-infrastructure/pbt.mjs";
import { createWorkflowRouteHandler } from "../../src/internal/browser/browser-workflow-routes.js";
import { createCookieCodec } from "../../src/internal/browser/cookie-codec.js";
import { resolveConfig } from "../../src/internal/config.js";
import { SafeObserver } from "../../src/internal/telemetry/observability.js";
import type { AuthCoreConfig } from "../../src/types/public.js";

const FEATURE_PROPERTY_LABEL = "Feature: auth-sdk-token-hardening, Property 16: Authentication and privilege changes replace prior credentials before publication";

function makeConfig(): AuthCoreConfig {
    return {
        sso: { 
            getJwks: vi.fn(),
            login: vi.fn(),
            signup: vi.fn(),
            signupMember: vi.fn(),
            refreshCurrentSession: vi.fn(),
            changeOrganization: vi.fn(),
            logoutCurrentSession: vi.fn(),
            logoutAllSessions: vi.fn(),
            createInvite: vi.fn(),
            acceptInvite: vi.fn(),
            cancelInvite: vi.fn(),
            resendInvite: vi.fn(),
            requestVerification: vi.fn(),
            verifyEmail: vi.fn(),
            forgotPassword: vi.fn(),
            resetPassword: vi.fn(),
        } as any,
        issuer: "https://issuer.example",
        audience: "resource-api",
        approvedOrigins: ["https://app.example"],
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        ssoRequestTimeoutMs: 8000,
    };
}

const scenarioArbitrary = fc.record({
    routeSuffix: fc.constantFrom(
        "/login", "/signup", "/signup-member", "/session", "/session/organization",
        "/password/reset", "/verification/complete", "/invite/accept"
    ),
    outcomeRaw: fc.oneof(
        fc.constant({ kind: "issued", session: { accessToken: "a", refreshToken: "new-rt", remainingLifetimeSeconds: 3000, identity: { subject: "u1", email: "a@b.c", organizationId: "org-1", roles: ["member"], products: [], membershipStatus: "active", emailVerified: true } } }),
        fc.constant({ kind: "rotated", session: { accessToken: "a", refreshToken: "new-rt", remainingLifetimeSeconds: 3000, identity: { subject: "u1", email: "a@b.c", organizationId: "org-1", roles: ["member"], products: [], membershipStatus: "active", emailVerified: true } } }),
        fc.constant({ kind: "overlap", session: { accessToken: "a", refreshToken: "new-rt", remainingLifetimeSeconds: 3000, identity: { subject: "u1", email: "a@b.c", organizationId: "org-1", roles: ["member"], products: [], membershipStatus: "active", emailVerified: true } } }),
        fc.constant({ kind: "rejected", code: "invalid_credentials" })
    ),
    hasCurrentCookie: fc.boolean()
});

describe(FEATURE_PROPERTY_LABEL, () => {
    it(FEATURE_PROPERTY_LABEL, async () => {
        // **Validates: Requirements 14.1, 14.2, 14.3, 14.4**
        await fc.assert(fc.asyncProperty(scenarioArbitrary, async (scenario) => {
            const rawConfig = makeConfig();

            // adjust outcome to match valid returns
            let outcome = scenario.outcomeRaw;
            if (["/login", "/signup", "/signup-member", "/password/reset", "/invite/accept"].includes(scenario.routeSuffix)) {
                if (outcome.kind === "rotated" || outcome.kind === "overlap") {
                    outcome = { kind: "issued", session: outcome.session };
                }
            } else if (scenario.routeSuffix === "/session") {
                if (outcome.kind === "issued") {
                    outcome = { kind: "rotated", session: outcome.session };
                }
            } else if (["/session/organization", "/verification/complete"].includes(scenario.routeSuffix)) {
                if (outcome.kind === "issued" || outcome.kind === "overlap") {
                    outcome = { kind: "rotated", session: outcome.session };
                }
            }
            if (scenario.routeSuffix === "/password/reset" && outcome.kind === "issued") {
                outcome = { ...outcome, data: { reset: true } };
            } else if (scenario.routeSuffix === "/verification/complete" && outcome.kind === "rotated") {
                outcome = { ...outcome, data: { verified: true } };
            }

            // mock the specific SSO method to return outcome
            const methods = {
                "/login": "login",
                "/signup": "signup",
                "/signup-member": "signupMember",
                "/session": "refreshCurrentSession",
                "/session/organization": "changeOrganization",
                "/password/reset": "resetPassword",
                "/verification/complete": "verifyEmail",
                "/invite/accept": "acceptInvite"
            } as any;
            
            const methodName = methods[scenario.routeSuffix];
            (rawConfig.sso as any)[methodName] = vi.fn().mockResolvedValue(outcome);

            const configObj = resolveConfig(rawConfig);
            const cookieCodec = createCookieCodec(3600);
            const telemetry = new SafeObserver();

            const handler = createWorkflowRouteHandler(configObj, telemetry, cookieCodec);

            const headers = new Headers();
            if (scenario.hasCurrentCookie) {
                headers.set("Cookie", `__Host-rm-refresh=old-rt`);
            }

            const routeBodies: Record<string, unknown> = {
                "/login": { email: "a@b.c", password: "pw" },
                "/signup": { email: "a@b.c", password: "pw" },
                "/signup-member": { email: "a@b.c", password: "pw", organizationId: "org_1" },
                "/session": {},
                "/session/organization": { organizationId: "org_1" },
                "/password/reset": { resetToken: "tok", password: "pw" },
                "/verification/complete": { verificationToken: "tok" },
                "/invite/accept": { invitationToken: "tok", password: "pw" },
            };

            const request = new Request(`https://app.example/api/auth${scenario.routeSuffix}`, {
                method: "POST",
                headers,
                body: JSON.stringify(routeBodies[scenario.routeSuffix] ?? {})
            });

            const response = await handler({ suffix: scenario.routeSuffix as any, method: "POST", path: `/api/auth${scenario.routeSuffix}` }, request);
            
            const setCookie = response.headers.get("Set-Cookie");
            
            const isSessionRoute = scenario.routeSuffix === "/session" || scenario.routeSuffix === "/session/organization";
            if (isSessionRoute && !scenario.hasCurrentCookie) {
                expect(setCookie).not.toBeNull();
                expect(setCookie).toContain("__Host-rm-refresh=;");
                expect(setCookie).toContain("Max-Age=0");
            } else if (outcome.kind === "issued" || outcome.kind === "rotated" || outcome.kind === "overlap") {
                expect(setCookie).not.toBeNull();
                expect(setCookie).toContain("__Host-rm-refresh=new-rt");
                expect(setCookie).toContain("Max-Age=3000");
                const body = await response.json();
                if (scenario.routeSuffix === "/password/reset" || scenario.routeSuffix === "/verification/complete") {
                    expect(body.status).toBe("succeeded");
                } else {
                    expect(body.credential.accessToken).toBe("a");
                }
            } else if (outcome.kind === "rejected") {
                if (isSessionRoute) {
                    expect(setCookie).not.toBeNull();
                    expect(setCookie).toContain("__Host-rm-refresh=;");
                    expect(setCookie).toContain("Max-Age=0");
                }
            }
        }), retainedPropertyParameters({
            suiteId: "auth-hardening.property",
            property: "16-authentication-and-privilege-changes-replace-prior-credentials"
        }, { parameters: { numRuns: 100 } }));
    });
});
