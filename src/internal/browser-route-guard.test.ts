import { describe, expect, it, vi } from "vitest";
import type { AuthCoreConfig } from "../types/public.js";
import {
    dispatchBrowserAuthRequest,
    headerValue,
    isApplicationJson,
    matchRoute,
    validApprovedOrigin,
    validateBrowserAuthRequest,
} from "./browser-route-guard.js";
import { resolveConfig } from "./config.js";

const ROUTES = [
    "/login",
    "/signup",
    "/signup-member",
    "/session",
    "/session/organization",
    "/invite",
    "/invite/accept",
    "/invite/cancel",
    "/invite/resend",
    "/verification/request",
    "/verification/complete",
    "/password/forgot",
    "/password/reset",
    "/logout/current",
    "/logout/all",
] as const;

function config(cors = false) {
    const source: AuthCoreConfig = {
        sso: { getJwks: vi.fn(async ({ correlationId }) => ({ kind: "unavailable" as const, correlationId })) },
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
    return resolveConfig(source);
}

function validHeaders(overrides: Record<string, string | undefined> = {}): Headers {
    const headers = new Headers({
        Origin: "https://app.example",
        "X-RM-CSRF": "1",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Content-Type": "application/json",
    });
    for (const [name, value] of Object.entries(overrides)) {
        if (value === undefined) headers.delete(name);
        else headers.set(name, value);
    }
    return headers;
}

function request(route = "/session", headers = validHeaders(), method = "POST"): Request {
    return new Request(`https://app.example/api/auth${route}`, { method, headers, body: method === "POST" ? "{}" : undefined });
}

function corsFields(response: Response): Record<string, string> {
    return Object.fromEntries([...response.headers]
        .filter(([name]) => name.startsWith("access-control-")));
}

describe("fixed Browser Auth Route table", () => {
    it.each(ROUTES)("accepts only POST application/json metadata for %s", async (route) => {
        const handler = vi.fn(() => new Response("accepted", { status: 202 }));
        const dispatched = await dispatchBrowserAuthRequest(request(route), config(), handler);

        expect(dispatched.response.status).toBe(202);
        expect(handler).toHaveBeenCalledOnce();
        expect(handler.mock.calls[0]?.[0]).toMatchObject({ suffix: route, method: "POST" });
    });

    it.each([
        ["/unknown", "POST", "route"],
        ["/session?next=true", "POST", "route"],
        ["/session", "GET", "method"],
        ["/session", "PUT", "method"],
    ])("rejects path %s method %s at %s", async (route, method, reason) => {
        const handler = vi.fn(() => new Response("unexpected"));
        const target = route.includes("?")
            ? new Request(`https://app.example/api/auth${route}`, { method, headers: validHeaders() })
            : request(route, validHeaders(), method);
        const dispatched = await dispatchBrowserAuthRequest(target, config(), handler);

        expect(dispatched.response.status).toBe(403);
        expect(dispatched.rejectionReason).toBe(reason);
        expect(handler).not.toHaveBeenCalled();
        await expect(dispatched.response.json()).resolves.toMatchObject({
            error: { code: "REQUEST_VALIDATION_REJECTED", status: 403, retryable: false },
        });
    });

    it.each(["/me", "/organizations"])("accepts only GET application/json metadata for %s", async (route) => {
        const handler = vi.fn(() => new Response("accepted", { status: 202 }));
        const dispatched = await dispatchBrowserAuthRequest(request(route, validHeaders(), "GET"), config(), handler);

        expect(dispatched.response.status).toBe(202);
        expect(handler).toHaveBeenCalledOnce();
        expect(handler.mock.calls[0]?.[0]).toMatchObject({ suffix: route, method: "GET" });
    });

    it.each(["/me", "/organizations"])("rejects non-GET requests for %s", async (route) => {
        const handler = vi.fn(() => new Response("unexpected"));
        const dispatched = await dispatchBrowserAuthRequest(request(route, validHeaders(), "POST"), config(), handler);

        expect(dispatched.response.status).toBe(403);
        expect(dispatched.rejectionReason).toBe("method");
        expect(handler).not.toHaveBeenCalled();
    });
});

describe("ordered singleton browser metadata validation", () => {
    it.each([
        ["Origin", undefined, "origin"],
        ["Origin", "https://other.example", "origin"],
        ["Origin", "https://app.example/path", "origin"],
        ["Origin", "https://app.example, https://app.example", "origin"],
        ["X-RM-CSRF", undefined, "csrf"],
        ["X-RM-CSRF", "0", "csrf"],
        ["X-RM-CSRF", "1, 1", "csrf"],
        ["Sec-Fetch-Site", undefined, "fetch_site"],
        ["Sec-Fetch-Site", "invalid-site", "fetch_site"],
        ["Sec-Fetch-Site", "same-origin, same-origin", "fetch_site"],
        ["Sec-Fetch-Mode", undefined, "fetch_mode"],
        ["Sec-Fetch-Mode", "navigate", "fetch_mode"],
        ["Sec-Fetch-Dest", undefined, "fetch_destination"],
        ["Sec-Fetch-Dest", "document", "fetch_destination"],
        ["Content-Type", undefined, "media_type"],
        ["Content-Type", "text/plain", "media_type"],
        ["Content-Type", "application/json, application/json", "media_type"],
        ["Content-Type", "application/json; charset", "media_type"],
        ["Content-Type", "application/json; charset=utf-8; charset=utf-8", "media_type"],
    ])("rejects %s=%s as %s before dispatch", async (name, value, reason) => {
        const handler = vi.fn(() => new Response("unexpected"));
        const dispatched = await dispatchBrowserAuthRequest(
            request("/session", validHeaders({ [name]: value })),
            config(),
            handler,
        );
        expect(dispatched.rejectionReason).toBe(reason);
        expect(dispatched.response.status).toBe(403);
        expect(handler).not.toHaveBeenCalled();
    });

    it.each([
        "application/json",
        "APPLICATION/JSON",
        "application/json; charset=utf-8",
        " application/json ; charset=\"utf-8\" ",
        "application/json; profile=\"a;b\"",
    ])("accepts normalized JSON media type %s", (contentType) => {
        expect(validateBrowserAuthRequest(request("/session", validHeaders({ "Content-Type": contentType })), config()))
            .toMatchObject({ ok: true, kind: "actual" });
    });

    it("rejects raw duplicate singleton values even when a normalized value appears valid", () => {
        const ordinary = validHeaders();
        const rawAwareHeaders = {
            get: ordinary.get.bind(ordinary),
            raw: () => ({ Origin: ["https://app.example", "https://app.example"] }),
        } as unknown as Headers;
        const rawAwareRequest = {
            url: "https://app.example/api/auth/session",
            method: "POST",
            headers: rawAwareHeaders,
        } as Request;

        expect(validateBrowserAuthRequest(rawAwareRequest, config())).toEqual({ ok: false, reason: "origin" });
    });

    it("does not inspect headers when route or method rejects first", () => {
        const unknownRoute = {
            url: "https://app.example/api/auth/not-a-route",
            method: "POST",
            get headers(): Headers { throw new Error("headers must not be read"); },
        } as Request;
        const wrongMethod = {
            url: "https://app.example/api/auth/session",
            method: "DELETE",
            get headers(): Headers { throw new Error("headers must not be read"); },
        } as Request;

        expect(validateBrowserAuthRequest(unknownRoute, config())).toEqual({ ok: false, reason: "route" });
        expect(validateBrowserAuthRequest(wrongMethod, config())).toEqual({ ok: false, reason: "method" });
    });
});

describe("minimal credentialed CORS", () => {
    it("emits exactly the four allowed singleton fields on actual responses", async () => {
        const dispatched = await dispatchBrowserAuthRequest(request(), config(true), () => new Response("ok", {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Expose-Headers": "Authorization",
                "Access-Control-Max-Age": "600",
            },
        }));

        expect(corsFields(dispatched.response)).toEqual({
            "access-control-allow-credentials": "true",
            "access-control-allow-headers": "Content-Type, X-RM-CSRF, Authorization",
            "access-control-allow-methods": "POST",
            "access-control-allow-origin": "https://app.example",
        });
    });

    it("omits every CORS field in same-origin mode even if a handler attempts to add one", async () => {
        const dispatched = await dispatchBrowserAuthRequest(request(), config(), () => new Response("ok", {
            headers: { "Access-Control-Allow-Origin": "*" },
        }));
        expect(corsFields(dispatched.response)).toEqual({});
    });

    it("answers only exact preflight method, headers, origin, and Fetch Metadata", async () => {
        const headers = validHeaders({
            "X-RM-CSRF": undefined,
            "Content-Type": undefined,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, x-rm-csrf",
        });
        const handler = vi.fn(() => new Response("unexpected"));
        const accepted = await dispatchBrowserAuthRequest(request("/login", headers, "OPTIONS"), config(true), handler);

        expect(accepted.response.status).toBe(204);
        expect(handler).not.toHaveBeenCalled();
        expect(corsFields(accepted.response)).toEqual({
            "access-control-allow-credentials": "true",
            "access-control-allow-headers": "Content-Type, X-RM-CSRF, Authorization",
            "access-control-allow-methods": "POST",
            "access-control-allow-origin": "https://app.example",
        });

        for (const requestedHeaders of ["x-rm-csrf", "content-type, x-rm-csrf, x-custom", "content-type, x-rm-csrf, x-rm-csrf"]) {
            const deniedHeaders = new Headers(headers);
            deniedHeaders.set("Access-Control-Request-Headers", requestedHeaders);
            const denied = await dispatchBrowserAuthRequest(request("/login", deniedHeaders, "OPTIONS"), config(true), handler);
            expect(denied.response.status).toBe(403);
            expect(denied.rejectionReason).toBe("csrf");
        }
    });

    it("returns readable minimal CORS on a later denial but never reflects an unapproved origin", async () => {
        const csrfDenied = await dispatchBrowserAuthRequest(
            request("/session", validHeaders({ "X-RM-CSRF": "wrong" })),
            config(true),
            () => new Response("unexpected"),
        );
        expect(csrfDenied.response.status).toBe(403);
        expect(corsFields(csrfDenied.response)["access-control-allow-origin"]).toBe("https://app.example");

        const originDenied = await dispatchBrowserAuthRequest(
            request("/session", validHeaders({ Origin: "https://evil.example" })),
            config(true),
            () => new Response("unexpected"),
        );
        expect(originDenied.response.status).toBe(403);
        expect(corsFields(originDenied.response)).toEqual({});
    });
});

describe("typed private binding boundary", () => {
    it("reaches a typed binding only from the post-guard handler and sends no browser headers", async () => {
        const binding = vi.fn(async (input: { correlationId: string }) => ({
            kind: "unavailable" as const,
            correlationId: input.correlationId,
        }));
        const handler = vi.fn(async () => {
            await binding({ correlationId: "private-call-1" });
            return new Response("handled");
        });

        const denied = await dispatchBrowserAuthRequest(
            request("/session", validHeaders({ Origin: undefined })),
            config(),
            handler,
        );
        expect(denied.response.status).toBe(403);
        expect(binding).not.toHaveBeenCalled();

        const accepted = await dispatchBrowserAuthRequest(request(), config(), handler);
        expect(accepted.response.status).toBe(200);
        expect(binding).toHaveBeenCalledWith({ correlationId: "private-call-1" });
        expect(binding.mock.calls[0]?.[0]).not.toHaveProperty("headers");
        expect(binding.mock.calls[0]?.[0]).not.toHaveProperty("cookies");
    });
});

describe("header parsing and route-matching internals", () => {
    it("reads raw values through the getAll fallback when raw is absent", () => {
        const headers = { get: () => "a", getAll: () => ["a"] } as unknown as Headers;
        expect(headerValue(headers, "X-Test")).toBe("a");
        const empty = { get: () => "", getAll: () => [] } as unknown as Headers;
        expect(headerValue(empty, "X-Test")).toBeUndefined();
        const duplicate = { get: () => "a", getAll: () => ["a", "a"] } as unknown as Headers;
        expect(headerValue(duplicate, "X-Test")).toBeUndefined();
    });

    it("normalizes raw values through the raw map when present", () => {
        const headers = {
            get: () => "a",
            raw: () => ({ "x-other": ["b"], "x-test": ["a"] }),
        } as unknown as Headers;
        expect(headerValue(headers, "X-Test")).toBe("a");
        const noMatch = { get: () => "a", raw: () => ({ "x-other": ["b"] }) } as unknown as Headers;
        expect(headerValue(noMatch, "X-Test")).toBe("a");
    });

    it("falls back to get() when raw() throws (e.g., workerd getAll for non-Set-Cookie)", () => {
        const throwingRaw = { get: () => "a", raw: () => { throw new Error("boom"); } } as unknown as Headers;
        expect(headerValue(throwingRaw, "X-Test")).toBe("a");
    });

    it("returns undefined when get() throws", () => {
        const throwingGet = { get: () => { throw new Error("boom"); } } as unknown as Headers;
        expect(headerValue(throwingGet, "X-Test")).toBeUndefined();
    });

    it("rejects non-https and unparseable approved origins", () => {
        const approved = new Set([
            "http://app.example/",
            "http://[",
            "https://app.example/?q=1",
            "https://app.example/#frag",
            "https://user:pass@app.example/",
            "https://app.example/path",
        ]);
        expect(validApprovedOrigin("http://app.example/", approved)).toBe(false);
        expect(validApprovedOrigin("http://[", approved)).toBe(false);
        expect(validApprovedOrigin("https://app.example/?q=1", approved)).toBe(false);
        expect(validApprovedOrigin("https://app.example/#frag", approved)).toBe(false);
        expect(validApprovedOrigin("https://user:pass@app.example/", approved)).toBe(false);
        expect(validApprovedOrigin("https://app.example/path", approved)).toBe(false);
    });

    it("returns undefined for an unparseable request URL", () => {
        expect(matchRoute({ url: "http://[" } as unknown as Request, config())).toBeUndefined();
    });

    it("classifies media types through the shared parser", () => {
        expect(isApplicationJson("application/json")).toBe(true);
        expect(isApplicationJson("application")).toBe(false);
        expect(isApplicationJson("application/json; charset=\"a\u0001b\"")).toBe(false);
        expect(isApplicationJson("application/json; charset=\"a\\\"b\"")).toBe(true);
        expect(isApplicationJson("application/json; charset=\"a\\")).toBe(false);
        expect(isApplicationJson("application/json; charset=utf-8 extra")).toBe(false);
    });

    it.each([
        ["application/json; charset=\"a\\\"b\"", true],
        ["application/json; charset=\"a\u0001b\"", false],
        ["application/json; charset=\"abc", false],
        ["application/json; charset=\"a\\", false],
        ["application", false],
        ["application/json; charset=utf-8 extra", false],
    ])("parses quoted parameter values: %s", async (contentType, accepted) => {
        const handler = vi.fn(() => new Response("handled", { status: 202 }));
        const dispatched = await dispatchBrowserAuthRequest(
            request("/session", validHeaders({ "Content-Type": contentType })),
            config(),
            handler,
        );
        if (accepted) {
            expect(dispatched.response.status).toBe(202);
            expect(handler).toHaveBeenCalledOnce();
        } else {
            expect(dispatched.rejectionReason).toBe("media_type");
            expect(handler).not.toHaveBeenCalled();
        }
    });
});

describe("preflight and credentialed-origin branches", () => {
    it("rejects preflight with a non-POST requested method", async () => {
        const dispatched = await dispatchBrowserAuthRequest(
            new Request("https://app.example/api/auth/session", {
                method: "OPTIONS",
                headers: validHeaders({ "Access-Control-Request-Method": "GET" }),
            }),
            config(),
            vi.fn(),
        );
        expect(dispatched.rejectionReason).toBe("method");
    });

    it("rejects preflight without exact requested headers as csrf", async () => {
        const dispatched = await dispatchBrowserAuthRequest(
            new Request("https://app.example/api/auth/session", {
                method: "OPTIONS",
                headers: validHeaders({ "Access-Control-Request-Method": "POST" }),
            }),
            config(true),
            vi.fn(),
        );
        expect(dispatched.rejectionReason).toBe("csrf");
    });

    it("rejects preflight from an approved but non-credentialed origin", async () => {
        const source: AuthCoreConfig = {
            sso: { getJwks: vi.fn() },
            issuer: "https://issuer.example",
            audience: "resource-api",
            approvedOrigins: ["https://app.example", "https://other.example"],
            basePath: "/api/auth",
            csrf: { name: "X-RM-CSRF", value: "1" },
            cookieMaxAgeSeconds: 3600,
            jwksMaxAgeSeconds: 60,
            ssoRequestTimeoutMs: 8000,
            credentialedCors: { origins: ["https://app.example"] },
        };
        const dispatched = await dispatchBrowserAuthRequest(
            new Request("https://app.example/api/auth/session", {
                method: "OPTIONS",
                headers: validHeaders({
                    Origin: "https://other.example",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type, x-rm-csrf",
                }),
            }),
            resolveConfig(source),
            vi.fn(),
        );
        expect(dispatched.rejectionReason).toBe("origin");
    });
});
