import { describe, expect, it, vi } from "vitest";
import { createAuth } from "../../src/index.js";
import type { AuthCoreConfig, SsoServiceBinding, VerifiedAuthUser } from "../../src/types/public.js";
import { resolveConfig } from "../../src/internal/config.js";
import { createVerifiedContext } from "../../src/internal/context.js";

function validConfig(sso: SsoServiceBinding = {
    getJwks: vi.fn(async ({ correlationId }) => ({
        kind: "succeeded" as const,
        correlationId,
        keys: [],
        freshnessSeconds: 60,
    })),
}): AuthCoreConfig {
    return {
        sso,
        issuer: "https://issuer.example",
        audience: "resource-api",
        approvedOrigins: ["https://app.example"],
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 60,
        ssoRequestTimeoutMs: 8000,
        correlationId: () => "request-1",
    };
}

describe("Task 3.1 configuration hardening", () => {
    it("redacts exceptions thrown by configuration accessors", () => {
        const config = validConfig() as AuthCoreConfig & { issuer: string };
        Object.defineProperty(config, "issuer", {
            get: () => { throw new Error("Bearer secret.jwt person@example.com"); },
        });

        let failure: unknown;
        try {
            createAuth(config);
        } catch (error) {
            failure = error;
        }

        expect(failure).toBeInstanceOf(TypeError);
        expect(String(failure)).toContain("configuration could not be read");
        expect(String(failure)).not.toMatch(/secret\.jwt|person@example/);
    });

    it("reads caller configuration once and passes the RPC binding through", async () => {
        const original = vi.fn(async ({ correlationId }: { correlationId: string }) => ({
            kind: "succeeded" as const,
            correlationId,
            keys: [],
            freshnessSeconds: 60,
        }));
        const binding: SsoServiceBinding = { getJwks: original };
        const config = validConfig(binding);
        let bindingReads = 0;
        Object.defineProperty(config, "sso", {
            get: () => { bindingReads += 1; return binding; },
        });
        const resolved = resolveConfig(config);
        await resolved.sso.getJwks({ correlationId: "request-1" });

        expect(bindingReads).toBe(1);
        expect(original).toHaveBeenCalledOnce();
        // The binding is delegated, not copied: spreading a workerd RPC stub
        // would drop every method, since they are not own enumerable properties.
        expect(resolved.sso).toBe(binding);
    });

    it("fails closed when a configured correlation provider returns no identifier", async () => {
        const sso: SsoServiceBinding = {
            getJwks: vi.fn(async ({ correlationId }) => ({
                kind: "succeeded" as const,
                correlationId,
                keys: [],
                freshnessSeconds: 60,
            })),
        };
        const auth = createAuth({
            ...validConfig(sso),
            correlationId: () => undefined as unknown as string,
        });
        const response = await auth.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/protected", {
                headers: { Authorization: "Bearer opaque" },
            }),
        );

        expect(response.status).toBe(500);
        expect(await response.json()).toEqual({
            error: {
                code: "INTERNAL_FAILURE",
                status: 500,
                retryable: false,
                message: "An internal authentication error occurred.",
            },
        });
        expect(sso.getJwks).not.toHaveBeenCalled();
    });

    it("rejects an unverified guard context without disclosing its unvalidated correlation value", async () => {
        const auth = createAuth(validConfig());
        const forgedContext = createVerifiedContext({
            sub: "subject-1",
            email: "person@example.com",
            org_id: "org-1",
            roles: ["member"],
            products: ["passport"],
            membership_status: "active",
            is_email_verified: true,
        }, "Bearer secret.jwt person@example.com");

        const response = await auth.requireRole(["admin"], () => new Response("unexpected"))(
            new Request("https://app.example/protected"),
            forgedContext,
        );
        const serialized = await response.text();

        expect(response.status).toBe(401);
        expect(serialized).toContain("INVALID_TOKEN");
        expect(serialized).not.toContain("correlationId");
        expect(serialized).not.toMatch(/secret\.jwt|person@example/);
    });
});

describe("Task 3.1 verified context hardening", () => {
    it("detaches all nested values from the verified claim source", () => {
        const roles = ["member"];
        const products = ["passport"];
        const preferences = { locale: "en" };
        const user: VerifiedAuthUser = {
            sub: "subject-1",
            email: "person@example.com",
            org_id: "org-1",
            roles,
            products,
            membership_status: "active",
            is_email_verified: true,
            user_metadata: { preferences },
        };

        const context = createVerifiedContext(user, "request-1");
        roles[0] = "admin";
        products.push("other");
        preferences.locale = "changed";

        expect(context.user.roles).toEqual(["member"]);
        expect(context.user.products).toEqual(["passport"]);
        expect(context.user.user_metadata).toEqual({ preferences: { locale: "en" } });
        expect(Object.isFrozen(context)).toBe(true);
        expect(Object.isFrozen(context.user)).toBe(true);
        expect(Object.isFrozen(context.user.roles)).toBe(true);
        expect(Object.isFrozen(context.user.products)).toBe(true);
        expect(Object.isFrozen(context.user.user_metadata?.preferences as object)).toBe(true);
    });

    it("deeply freezes metadata and preserves hostile JSON keys as inert data", () => {
        const metadata = JSON.parse(
            '{"__proto__":{"polluted":"no"},"constructor":{"prototype":{"polluted":"no"}}}',
        ) as Record<string, unknown>;
        const user: VerifiedAuthUser = {
            sub: "subject-1",
            email: "person@example.com",
            org_id: "org-1",
            roles: ["member"],
            products: ["passport"],
            membership_status: "active",
            is_email_verified: true,
            user_metadata: metadata,
        };

        const context = createVerifiedContext(user, "request-1");
        const copiedMetadata = context.user.user_metadata!;

        expect(Object.prototype.hasOwnProperty.call(copiedMetadata, "__proto__")).toBe(true);
        expect(Object.getPrototypeOf(copiedMetadata)).toBe(Object.prototype);
        expect(Object.isFrozen(copiedMetadata)).toBe(true);
        expect(Object.isFrozen(copiedMetadata.__proto__ as object)).toBe(true);
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
        expect(() => {
            (copiedMetadata.__proto__ as Record<string, unknown>).polluted = "yes";
        }).toThrow(TypeError);
        expect((copiedMetadata.__proto__ as Record<string, unknown>).polluted).toBe("no");
    });
});