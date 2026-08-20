import { describe, expect, it, vi } from "vitest";
import { createCookieCodec } from "../../../src/internal/browser/cookie-codec.js";
import { SafeObserver } from "../../../src/internal/telemetry/observability.js";
import { BrowserAuthRoute } from "../../../src/internal/browser/browser-route-guard.js";
import { createWorkflowRouteHandler } from "../../../src/internal/browser/browser-workflow-routes.js";

const ROUTE: BrowserAuthRoute = { kind: "browser", method: "POST", prefix: "/auth", suffix: "/login" };

function handlerWith(sso: Record<string, unknown>) {
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
    return { handler: createWorkflowRouteHandler(config, telemetry, cookieCodec), cookieCodec, config };
}

function post(suffix: string, body: unknown, headers: Record<string, string> = {}) {
    const route: BrowserAuthRoute = { kind: "browser", method: "POST", prefix: "/auth", suffix } as any;
    const req = new Request(`https://api.example.com/auth${suffix}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body),
    });
    return { route, req };
}

describe("browser-workflow-routes", () => {
    it("should reject unknown body properties with 400 INVALID_REQUEST_BODY", async () => {
        const { handler } = handlerWith({ login: vi.fn() });
        const { route, req } = post("/login", { email: "a@b.c", password: "pw", admin: true });
        const response = await handler(route, req);
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ error: { code: "INVALID_REQUEST_BODY" } });
    });

    it("should reject missing required body properties with 400", async () => {
        const { handler } = handlerWith({ login: vi.fn() });
        const { route, req } = post("/login", { email: "a@b.c" });
        const response = await handler(route, req);
        expect(response.status).toBe(400);
        expect((await response.json()).error.code).toBe("INVALID_REQUEST_BODY");
    });

    it("should reject malformed JSON with 400 before any RPC", async () => {
        const login = vi.fn();
        const { handler } = handlerWith({ login });
        const { route, req } = post("/login", "{not json");
        const response = await handler(route, req);
        expect(response.status).toBe(400);
        expect(login).not.toHaveBeenCalled();
    });

    it("should map session rejection codes to exact status shapes (401/403/404/409)", async () => {
        const cases: Array<[string, number]> = [
            ["invalid_credentials", 401],
            ["identity_conflict", 409],
            ["invalid_invitation", 404],
            ["membership_rejected", 403],
        ];
        for (const [code, status] of cases) {
            const { handler } = handlerWith({ login: vi.fn(async () => ({ kind: "rejected", code })) });
            const { route, req } = post("/login", { email: "a@b.c", password: "pw" });
            const response = await handler(route, req);
            expect(response.status, code).toBe(status);
        }
    });

    it("should map workflow rejection codes to exact status shapes (404/409)", async () => {
        const cases: Array<[string, number]> = [
            ["not_found", 404],
            ["conflict", 409],
            ["already_used", 409],
        ];
        for (const [code, status] of cases) {
            const { handler } = handlerWith({ acceptInvite: vi.fn(async () => ({ kind: "rejected", code })) });
            const { route, req } = post("/invite/accept", { invitationToken: "t", password: "pw" });
            const response = await handler(route, req);
            expect(response.status, code).toBe(status);
        }
    });

    it("should build the exact session envelope with charset, nosniff, and no-store", async () => {
        const { handler } = handlerWith({
            login: vi.fn(async () => ({
                kind: "issued",
                session: {
                    accessToken: "a",
                    refreshToken: "rt",
                    remainingLifetimeSeconds: 3600,
                    identity: { subject: "u1", email: "a@b.c", organizationId: "org-1", roles: ["member"], products: [], membershipStatus: "active", emailVerified: true },
                },
            })),
        });
        const { route, req } = post("/login", { email: "a@b.c", password: "pw" });
        const response = await handler(route, req);
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("application/json; charset=utf-8");
        expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
        expect(response.headers.get("Cache-Control")).toBe("no-store");
        expect(response.headers.get("Pragma")).toBe("no-cache");
        expect(response.headers.get("Expires")).toBe("Thu, 01 Jan 1970 00:00:00 GMT");
        expect(response.headers.get("Set-Cookie")).toContain("__Host-rm-refresh=rt");
        const body = await response.json();
        expect(body.ok).toBe(true);
        expect(body.credential).toEqual({ accessToken: "a" });
        expect(body.outcome).toBe("created");
        expect(body.data.identity.organizationId).toBe("org-1");
        expect(body.correlationId).toBe("test");
    });

    it("should mediate /logout/current revoked to 200 with cookie clear and client logout body", async () => {
        const { handler } = handlerWith({ logoutCurrentSession: vi.fn(async () => ({ kind: "current_revoked" })) });
        const { route, req } = post("/logout/current", {}, { Cookie: "__Host-rm-refresh=rt" });
        const response = await handler(route, req);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ outcome: "current_session_revoked", cookieClearing: "confirmed" });
        expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    it("should mediate /logout/all already-ended to 200 without upgrading", async () => {
        const { handler } = handlerWith({ logoutAllSessions: vi.fn(async () => ({ kind: "all_already_ended" })) });
        const { route, req } = post("/logout/all", {}, { Cookie: "__Host-rm-refresh=rt" });
        const response = await handler(route, req);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ outcome: "all_sessions_already_ended", cookieClearing: "confirmed" });
        expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    it("should emit REVOCATION_UNCONFIRMED without cookie clear when revocation is unconfirmed", async () => {
        for (const outcome of [{ kind: "cancelled" }, { kind: "timeout" }, { kind: "rate_limited" }, { kind: "unavailable" }]) {
            const { handler } = handlerWith({ logoutCurrentSession: vi.fn(async () => outcome) });
            const { route, req } = post("/logout/current", {}, { Cookie: "__Host-rm-refresh=rt" });
            const response = await handler(route, req);
            expect(response.status, outcome.kind).toBe(503);
            expect((await response.json()).error.code, outcome.kind).toBe("REVOCATION_UNCONFIRMED");
            expect(response.headers.get("Set-Cookie"), outcome.kind).toBeNull();
        }
    });

    it("should not tombstone a sanctioned Authorization Bearer credential", async () => {
        const login = vi.fn(async () => ({ kind: "rejected", code: "invalid_credentials" }));
        const { handler } = handlerWith({ login });
        const { route, req } = post("/login", "{malformed", { Authorization: "Bearer access-1" });
        const response = await handler(route, req);
        expect(response.status).toBe(400);
        expect((await response.json()).error.code).toBe("INVALID_REQUEST_BODY");
        expect(login).not.toHaveBeenCalled();
    });

    it("should extract the Bearer access token for authenticated /me requests", async () => {
        const getIdentity = vi.fn(async () => ({ kind: "succeeded", data: { subject: "u1" } }));
        const { handler } = handlerWith({ getIdentity });
        const route: BrowserAuthRoute = { suffix: "/me", path: "/auth/me", method: "GET" };
        const req = new Request("https://api.example.com/auth/me", {
            method: "GET",
            headers: { Authorization: "Bearer access-1" },
        });
        const response = await handler(route, req);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ status: "succeeded", data: { subject: "u1" } });
        expect(getIdentity).toHaveBeenCalledWith(expect.objectContaining({ accessToken: "access-1" }));
    });

    it("should reject missing Bearer credentials on authenticated routes with the rejection envelope", async () => {
        const { handler } = handlerWith({ getIdentity: vi.fn() });
        const route: BrowserAuthRoute = { suffix: "/me", path: "/auth/me", method: "GET" };
        const req = new Request("https://api.example.com/auth/me", { method: "GET" });
        const response = await handler(route, req);
        expect(response.status).toBe(401);
        expect(await response.json()).toEqual({ status: "rejected", code: "not_authenticated" });
    });

    it("should tombstone X-Access-Token headers with 401 without verification", async () => {
        const { handler } = handlerWith({ login: vi.fn() });
        const { route, req } = post("/login", { email: "a@b.c", password: "pw" }, { "X-Access-Token": "legacy" });
        const response = await handler(route, req);
        expect(response.status).toBe(401);
        expect((await response.json()).error.code).toBe("REAUTHENTICATION_REQUIRED");
    });
});