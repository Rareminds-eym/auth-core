/**
 * Unit tests for the generic `requireFeature` guard.
 *
 * `requireFeature` is intentionally app-agnostic: the access decision is
 * delegated to a `check` callback supplied by the consumer. These tests verify
 * the guard's own contract:
 *   - allow path: check resolves true  -> wrapped handler is invoked & returned
 *   - deny path:  check resolves false -> 403 "feature not available", handler skipped
 *   - featureKey normalization: string and string[] both yield a normalized keys[]
 *   - the request context is forwarded to the check callback unchanged
 *
 * Mirrors the sso-worker test conventions: vitest globals, `vi` spies,
 * lightweight hand-built mock context (no network / no real env bindings).
 */

import { describe, expect, it, vi } from "vitest";
import { requireFeature } from "../middleware/requireFeature.js";
import type { AuthUser, ContextWithUser } from "../types/auth.js";

// ── Mock context helper ─────────────────────────────────────────
function createMockUser(overrides: Partial<AuthUser> = {}): AuthUser {
    return {
        sub: "user-123",
        email: "user@example.com",
        org_id: "org-1",
        roles: ["learner"],
        products: ["skillpassport"],
        membership_status: "active",
        is_email_verified: true,
        ...overrides,
    };
}

function createMockContext(
    overrides: Partial<ContextWithUser> = {}
): ContextWithUser {
    return {
        request: new Request("https://example.com/api/feature"),
        env: {},
        params: {},
        data: { user: createMockUser() },
        waitUntil: () => { },
        passThroughOnException: () => { },
        ...overrides,
    };
}

describe("requireFeature", () => {
    it("ALLOW: invokes the wrapped handler and returns its Response when check resolves true", async () => {
        const context = createMockContext();
        const handlerResponse = new Response("ok", { status: 200 });
        const handler = vi.fn(() => handlerResponse);
        const check = vi.fn(async () => true);

        const guarded = requireFeature("advanced-reports", check, handler);
        const result = await guarded(context);

        expect(check).toHaveBeenCalledTimes(1);
        expect(handler).toHaveBeenCalledTimes(1);
        expect(handler).toHaveBeenCalledWith(context);
        expect(result).toBe(handlerResponse);
        expect(result.status).toBe(200);
    });

    it("DENY: returns 403 'feature not available' and does NOT invoke the handler when check resolves false", async () => {
        const context = createMockContext();
        const handler = vi.fn(() => new Response("ok", { status: 200 }));
        const check = vi.fn(async () => false);

        const guarded = requireFeature("advanced-reports", check, handler);
        const result = await guarded(context);

        expect(check).toHaveBeenCalledTimes(1);
        expect(handler).not.toHaveBeenCalled();
        expect(result.status).toBe(403);

        const body = (await result.json()) as { error: string };
        expect(body.error).toBe("Forbidden: feature not available");
        expect(result.headers.get("Content-Type")).toBe("application/json");
    });

    it("NORMALIZATION: a single string feature key is forwarded to check as a one-element array", async () => {
        const context = createMockContext();
        const handler = vi.fn(() => new Response(null, { status: 200 }));
        const check = vi.fn(async () => true);

        const guarded = requireFeature("x", check, handler);
        await guarded(context);

        expect(check).toHaveBeenCalledWith(context, ["x"]);
    });

    it("NORMALIZATION: an array of feature keys is forwarded to check unchanged", async () => {
        const context = createMockContext();
        const handler = vi.fn(() => new Response(null, { status: 200 }));
        const check = vi.fn(async () => true);

        const guarded = requireFeature(["a", "b"], check, handler);
        await guarded(context);

        expect(check).toHaveBeenCalledWith(context, ["a", "b"]);
    });

    it("forwards the request context to the check callback so app logic can inspect the user", async () => {
        const user = createMockUser({ sub: "user-999", products: ["pro"] });
        const context = createMockContext({ data: { user } });
        const handler = vi.fn(() => new Response(null, { status: 200 }));

        let receivedContext: ContextWithUser | undefined;
        const check = vi.fn(async (ctx: ContextWithUser) => {
            receivedContext = ctx;
            return true;
        });

        const guarded = requireFeature("feature-y", check, handler);
        await guarded(context);

        expect(receivedContext).toBe(context);
        expect(receivedContext?.data.user?.sub).toBe("user-999");
    });
});
