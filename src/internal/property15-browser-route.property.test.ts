import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { retainedPropertyParameters } from "../../../tools/auth-test-infrastructure/pbt.mjs";
import { dispatchBrowserAuthRequest } from "./browser-route-guard.js";
import { resolveConfig } from "./config.js";
import type { AuthCoreConfig } from "../types/public.js";

const FEATURE_PROPERTY_LABEL = "Feature: auth-sdk-token-hardening, Property 15: Browser auth route validation is exact and deny-first";

const ROUTES = [
    "/login", "/signup", "/signup-member", "/session", "/session/organization",
    "/invite", "/invite/accept", "/invite/cancel", "/invite/resend",
    "/verification/request", "/verification/complete", "/password/forgot",
    "/password/reset", "/logout/current", "/logout/all"
] as const;

function makeConfig(cors: boolean): AuthCoreConfig {
    return {
        sso: { getJwks: vi.fn(async () => ({ kind: "unavailable", correlationId: "test" })) },
        issuer: "https://issuer.example",
        audience: "resource-api",
        approvedOrigins: ["https://app.example"],
        basePath: "/api/auth",
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 60,
        ssoRequestTimeoutMs: 8000,
        ...(cors ? { credentialedCors: { origins: ["https://app.example"] } } : {}),
    };
}

const headerValueArbitrary = fc.oneof(
    fc.constant("valid"),
    fc.constant("missing"),
    fc.constant("malformed"),
    fc.constant("multiple"),
);

const requestArbitrary = fc.record({
    route: fc.oneof(fc.constantFrom(...ROUTES), fc.constant("/unknown-route"), fc.constant("/session?query=1")),
    method: fc.constantFrom("POST", "OPTIONS", "GET", "PUT", "DELETE"),
    origin: headerValueArbitrary,
    csrf: headerValueArbitrary,
    fetchSite: headerValueArbitrary,
    fetchMode: headerValueArbitrary,
    fetchDest: headerValueArbitrary,
    contentType: headerValueArbitrary,
    corsEnabled: fc.boolean(),
});

describe(FEATURE_PROPERTY_LABEL, () => {
    it(FEATURE_PROPERTY_LABEL, async () => {
        // **Validates: Requirements 13.1, 13.2, 13.3, 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7**
        await fc.assert(fc.asyncProperty(requestArbitrary, async (req) => {
            const configObj = resolveConfig(makeConfig(req.corsEnabled));
            const isPreflight = req.method === "OPTIONS";
            const handler = vi.fn(async () => new Response("ok"));

            let isPerfectOrigin = req.origin === "valid";
            let isPerfectCsrf = req.csrf === "valid";
            let isPerfectFetchSite = req.fetchSite === "valid";
            let isPerfectFetchMode = req.fetchMode === "valid";
            let isPerfectFetchDest = req.fetchDest === "valid";
            let isPerfectContentType = req.contentType === "valid";
            let isPerfectRoute = ROUTES.includes(req.route as any);
            let isPerfectMethod = req.method === "POST" || (isPreflight && req.method === "OPTIONS");

            const headers = new Headers();
            
            if (req.origin === "valid") headers.set("Origin", "https://app.example");
            else if (req.origin === "malformed") headers.set("Origin", "http://app.example/path");
            else if (req.origin === "multiple") headers.append("Origin", "https://app.example"); // multiple will be rejected if comma combined

            if (req.csrf === "valid") headers.set(isPreflight ? "Access-Control-Request-Headers" : "X-RM-CSRF", isPreflight ? "content-type, x-rm-csrf" : "1");
            else if (req.csrf === "malformed") headers.set(isPreflight ? "Access-Control-Request-Headers" : "X-RM-CSRF", isPreflight ? "content-type" : "wrong");

            if (req.fetchSite === "valid") headers.set("Sec-Fetch-Site", "same-origin");
            else if (req.fetchSite === "malformed") headers.set("Sec-Fetch-Site", "cross-site");

            if (req.fetchMode === "valid") headers.set("Sec-Fetch-Mode", "cors");
            else if (req.fetchMode === "malformed") headers.set("Sec-Fetch-Mode", "navigate");

            if (req.fetchDest === "valid") headers.set("Sec-Fetch-Dest", "empty");
            else if (req.fetchDest === "malformed") headers.set("Sec-Fetch-Dest", "document");

            if (req.contentType === "valid") headers.set("Content-Type", "application/json");
            else if (req.contentType === "malformed") headers.set("Content-Type", "text/plain");

            if (isPreflight) {
                headers.set("Access-Control-Request-Method", "POST");
            }

            const rawHeaders: any = {};
            for (const [key, val] of headers) {
                rawHeaders[key] = [val];
            }
            if (req.origin === "multiple") rawHeaders["origin"] = ["https://app.example", "https://app.example"];
            if (req.csrf === "multiple") rawHeaders[isPreflight ? "access-control-request-headers" : "x-rm-csrf"] = isPreflight ? ["content-type, x-rm-csrf", "content-type, x-rm-csrf"] : ["1", "1"];
            if (req.fetchSite === "multiple") rawHeaders["sec-fetch-site"] = ["same-origin", "same-origin"];
            if (req.fetchMode === "multiple") rawHeaders["sec-fetch-mode"] = ["cors", "cors"];
            if (req.fetchDest === "multiple") rawHeaders["sec-fetch-dest"] = ["empty", "empty"];
            if (req.contentType === "multiple") rawHeaders["content-type"] = ["application/json", "application/json"];

            const reqObj = {
                url: `https://app.example/api/auth${req.route}`,
                method: req.method,
                headers: {
                    get: (name: string) => headers.get(name),
                    raw: () => rawHeaders
                } as any
            } as Request;

            const dispatched = await dispatchBrowserAuthRequest(reqObj, configObj, handler);
            
            const shouldAccept = isPerfectRoute && isPerfectMethod && isPerfectOrigin && isPerfectCsrf && isPerfectFetchSite && isPerfectFetchMode && isPerfectFetchDest && (isPreflight || isPerfectContentType);

            if (shouldAccept) {
                if (isPreflight) {
                    expect(dispatched.response.status).toBe(204);
                    expect(handler).not.toHaveBeenCalled();
                } else {
                    expect(handler).toHaveBeenCalled();
                    expect(dispatched.rejectionReason).toBeUndefined();
                }
            } else {
                expect(handler).not.toHaveBeenCalled();
                expect(dispatched.response.status).toBe(403);
                expect(dispatched.rejectionReason).toBeDefined();
            }

        }), retainedPropertyParameters({
            suiteId: "auth-hardening.property",
            property: "15-browser-auth-route-validation-is-exact-and-deny-first"
        }, { parameters: { numRuns: 100 } }));
    });
});
