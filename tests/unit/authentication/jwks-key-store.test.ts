import { exportJWK, generateKeyPair, importJWK } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type {
    AuthCoreConfig,
    SsoJwksKey,
    SsoJwksRpcOutcome,
    SsoServiceBinding,
} from "../../../src/types/public.js";
import { resolveConfig } from "../../../src/internal/config.js";
import { CoreFailure } from "../../../src/internal/errors.js";
import { JwksKeyStore, jwksFailureReason } from "../../../src/internal/authentication/jwks-key-store.js";

vi.mock("jose", async (importOriginal) => {
    const original = await importOriginal<typeof import("jose")>();
    return { ...original, importJWK: vi.fn(original.importJWK) };
});

const correlationId = "jwks-lifecycle-test";
let activeKey: SsoJwksKey;
let replacementKey: SsoJwksKey;

async function publicKey(kid: string, status: "active" | "retiring" = "active"): Promise<SsoJwksKey> {
    const { publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") {
        throw new TypeError("Expected RSA test key material.");
    }
    return { kty: "RSA", kid, alg: "RS256", use: "sig", status, n: jwk.n, e: jwk.e };
}

function succeeded(
    keys: readonly SsoJwksKey[],
    freshnessSeconds: number | undefined = 60,
): SsoJwksRpcOutcome {
    return {
        kind: "succeeded",
        correlationId,
        keys,
        ...(freshnessSeconds === undefined ? {} : { freshnessSeconds }),
    };
}

function config(
    getJwks: SsoServiceBinding["getJwks"],
    options: { maxAge?: number; timeout?: number } = {},
): AuthCoreConfig {
    return {
        sso: { getJwks }, issuer: "https://issuer.example", audience: "resource-api",
        approvedOrigins: ["https://app.example"], csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600, ssoRequestTimeoutMs: options.timeout ?? 8000,
        ...(options.maxAge === undefined ? {} : { jwksMaxAgeSeconds: options.maxAge }),
    };
}
beforeAll(async () => {
    [activeKey, replacementKey] = await Promise.all([
        publicKey("active-kid"),
        publicKey("replacement-kid", "retiring"),
    ]);
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe("finite authoritative JWKS lifecycle", () => {
    it.each([
        { metadataAge: 10, configuredAge: 5, expiresAfterMs: 5000 },
        { metadataAge: 2, configuredAge: 10, expiresAfterMs: 2000 },
    ])("uses the shorter finite freshness source: $metadataAge/$configuredAge", async ({
        metadataAge,
        configuredAge,
        expiresAfterMs,
    }) => {
        vi.useFakeTimers();
        vi.setSystemTime(0);
        const getJwks = vi.fn(async () => succeeded([activeKey], metadataAge));
        const store = new JwksKeyStore(resolveConfig(config(getJwks, { maxAge: configuredAge })));

        const first = await store.keySetFor(activeKey.kid, correlationId);
        vi.setSystemTime(expiresAfterMs - 1);
        const cached = await store.keySetFor(activeKey.kid, correlationId);
        expect(cached).toBe(first);
        expect(getJwks).toHaveBeenCalledOnce();

        vi.setSystemTime(expiresAfterMs);
        await store.keySetFor(activeKey.kid, correlationId);
        expect(getJwks).toHaveBeenCalledTimes(2);
    });

    it("uses either sole valid freshness source and rejects when neither is valid", async () => {
        vi.useFakeTimers();
        vi.setSystemTime(0);
        const invalidMetadata = vi.fn(async () => succeeded([activeKey], Number.NaN));
        const configured = new JwksKeyStore(resolveConfig(config(invalidMetadata, { maxAge: 3 })));
        await configured.keySetFor(activeKey.kid, correlationId);
        vi.setSystemTime(3000);
        await configured.keySetFor(activeKey.kid, correlationId);
        expect(invalidMetadata).toHaveBeenCalledTimes(2);

        const metadataOnly = new JwksKeyStore(resolveConfig(config(
            async () => succeeded([activeKey], 3),
        )));
        await expect(metadataOnly.keySetFor(activeKey.kid, correlationId)).resolves.toBeTypeOf("function");

        const absent = new JwksKeyStore(resolveConfig(config(
            async () => ({ kind: "succeeded", correlationId, keys: [activeKey] }),
        )));
        await expect(absent.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    });
    it("validates every key and atomically preserves the prior snapshot on rejection", async () => {
        const duplicate = succeeded([activeKey, { ...activeKey, status: "retiring" }]);
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockResolvedValueOnce(duplicate);
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));

        const original = await store.keySetFor(activeKey.kid, correlationId);
        await expect(store.keySetFor(replacementKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
        await expect(store.keySetFor(activeKey.kid, correlationId)).resolves.toBe(original);
        expect(getJwks).toHaveBeenCalledTimes(2);

        const malformed = { ...activeKey, use: "enc" } as unknown as SsoJwksKey;
        const invalidStore = new JwksKeyStore(resolveConfig(config(
            async () => succeeded([malformed]),
        )));
        await expect(invalidStore.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_TOKEN" });
    });

    it("evicts removed keys as soon as a later authoritative snapshot is accepted", async () => {
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockResolvedValue(succeeded([replacementKey]));
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));

        await store.keySetFor(activeKey.kid, correlationId);
        await store.keySetFor(replacementKey.kid, correlationId);
        await expect(store.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_TOKEN" });
        expect(getJwks).toHaveBeenCalledTimes(3);
    });

    it("coalesces concurrent unknown-kid callers into one refresh", async () => {
        let release!: (outcome: SsoJwksRpcOutcome) => void;
        const pending = new Promise<SsoJwksRpcOutcome>((resolve) => { release = resolve; });
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockReturnValueOnce(pending);
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));
        await store.keySetFor(activeKey.kid, correlationId);

        const callers = Array.from({ length: 20 }, () =>
            store.keySetFor(replacementKey.kid, correlationId));
        await vi.waitFor(() => expect(getJwks).toHaveBeenCalledTimes(2));
        release(succeeded([activeKey, replacementKey]));
        const results = await Promise.all(callers);

        expect(new Set(results).size).toBe(1);
        expect(getJwks).toHaveBeenCalledTimes(2);
    });
    it("maps authoritative absence to invalid token", async () => {
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockResolvedValueOnce(succeeded([]));
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));
        await store.keySetFor(activeKey.kid, correlationId);

        await expect(store.keySetFor(replacementKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_TOKEN" });
    });

    it("bounds refresh and never extends expired freshness after upstream failure", async () => {
        vi.useFakeTimers();
        vi.setSystemTime(0);
        const never = new Promise<SsoJwksRpcOutcome>(() => undefined);
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey], 1))
            .mockReturnValue(never);
        const store = new JwksKeyStore(resolveConfig(config(getJwks, { timeout: 50 })));
        await store.keySetFor(activeKey.kid, correlationId);
        vi.setSystemTime(1000);

        const firstFailure = store.keySetFor(activeKey.kid, correlationId);
        const firstAssertion = expect(firstFailure)
            .rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
        await vi.advanceTimersByTimeAsync(50);
        await firstAssertion;

        const secondFailure = store.keySetFor(activeKey.kid, correlationId);
        const secondAssertion = expect(secondFailure)
            .rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
        await vi.advanceTimersByTimeAsync(50);
        await secondAssertion;
        expect(getJwks).toHaveBeenCalledTimes(3);
    });

    it("rejects non-closed and sparse snapshots without replacing prior authority", async () => {
        const sparseKeys = new Array<SsoJwksKey>(2);
        sparseKeys[0] = replacementKey;
        const inheritedKey = Object.create(activeKey) as SsoJwksKey;
        const getJwks = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockResolvedValueOnce(succeeded(sparseKeys))
            .mockResolvedValueOnce(succeeded([inheritedKey]));
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));

        const original = await store.keySetFor(activeKey.kid, correlationId);
        await expect(store.keySetFor(replacementKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
        await expect(store.keySetFor(activeKey.kid, correlationId)).resolves.toBe(original);
        await expect(store.keySetFor(replacementKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
        await expect(store.keySetFor(activeKey.kid, correlationId)).resolves.toBe(original);
    });

    it("keeps accepted snapshots and refresh flights scoped to one Auth instance", async () => {
        const firstBinding = vi.fn()
            .mockResolvedValueOnce(succeeded([activeKey]))
            .mockResolvedValueOnce(succeeded([replacementKey]));
        const secondBinding = vi.fn(async () => succeeded([activeKey]));
        const firstStore = new JwksKeyStore(resolveConfig(config(firstBinding)));
        const secondStore = new JwksKeyStore(resolveConfig(config(secondBinding)));

        await firstStore.keySetFor(activeKey.kid, correlationId);
        const secondSnapshot = await secondStore.keySetFor(activeKey.kid, correlationId);
        await expect(firstStore.keySetFor(replacementKey.kid, correlationId)).resolves.toBeTypeOf("function");
        await expect(secondStore.keySetFor(activeKey.kid, correlationId)).resolves.toBe(secondSnapshot);

        expect(firstBinding).toHaveBeenCalledTimes(2);
        expect(secondBinding).toHaveBeenCalledOnce();
    });

    it("maps every explicit transient JWKS outcome and thrown binding failure to upstream unavailable", async () => {
        const outcomes: readonly SsoJwksRpcOutcome[] = [
            { kind: "cancelled", correlationId },
            { kind: "timeout", correlationId },
            { kind: "unavailable", correlationId },
            { kind: "rate_limited", correlationId, retryAfterSeconds: 1 },
        ];
        for (const outcome of outcomes) {
            const store = new JwksKeyStore(resolveConfig(config(async () => outcome)));
            await expect(store.keySetFor(activeKey.kid, correlationId))
                .rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
        }

        const thrown = new JwksKeyStore(resolveConfig(config(async () => {
            throw new Error("private upstream detail");
        })));
        await expect(thrown.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
    });

    it("rejects malformed key material and crypto-unusable key material as invalid responses", async () => {
        const malformed: readonly SsoJwksKey[] = [
            { ...activeKey, kty: "EC" },
            { ...activeKey, alg: "RS512" },
            { ...activeKey, status: "retired" },
            { ...activeKey, kid: " whitespace " },
            { ...activeKey, n: "not-base64url!!" },
            { ...activeKey, e: "!!" },
        ].map((key) => key as unknown as SsoJwksKey);
        for (const key of malformed) {
            const store = new JwksKeyStore(resolveConfig(config(async () => succeeded([key]))));
            await expect(store.keySetFor(activeKey.kid, correlationId))
                .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
        }

        const cryptoUnusable = { ...activeKey, n: "AQAB" } as unknown as SsoJwksKey;
        vi.mocked(importJWK).mockRejectedValueOnce(new Error("crypto refused"));
        const unusable = new JwksKeyStore(resolveConfig(config(async () => succeeded([cryptoUnusable]))));
        await expect(unusable.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    });

    it("rejects freshness that collapses below clock precision", async () => {
        const store = new JwksKeyStore(resolveConfig(config(async () => succeeded([activeKey], 1e-308))));
        await expect(store.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    });

    it("never serves a snapshot whose freshness expires during its own refresh", async () => {
        const nowSpy = vi.spyOn(Date, "now")
            .mockReturnValueOnce(1000)
            .mockReturnValueOnce(1000)
            .mockReturnValueOnce(2000)
            .mockReturnValueOnce(5000);
        const getJwks = vi.fn(async () => succeeded([activeKey], 1));
        const store = new JwksKeyStore(resolveConfig(config(getJwks)));
        await expect(store.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "UPSTREAM_UNAVAILABLE" });
        expect(nowSpy).toHaveBeenCalled();
    });

    it("classifies unhandled failures as internal for telemetry", () => {
        expect(jwksFailureReason(new CoreFailure("INTERNAL_FAILURE"))).toBe("INTERNAL_FAILURE");
        expect(jwksFailureReason(new CoreFailure("EXPIRED_TOKEN"))).toBe("INTERNAL_FAILURE");
        expect(jwksFailureReason(new Error("private detail"))).toBe("INTERNAL_FAILURE");
    });

    it("rejects accessor-shaped snapshots, extra fields, and unknown outcome kinds as invalid responses", async () => {
        const withGetter = { ...succeeded([activeKey]), get freshnessSeconds() { return 60; } };
        const accessor = new JwksKeyStore(resolveConfig(config(async () => withGetter)));
        await expect(accessor.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });

        const withExtraField = { ...succeeded([activeKey]), extra: "field" };
        const extra = new JwksKeyStore(resolveConfig(config(async () => withExtraField)));
        await expect(extra.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });

        const unknownKind = new JwksKeyStore(resolveConfig(config(async () => ({
            kind: "weird" as const,
            correlationId,
            keys: [activeKey],
        }))));
        await expect(unknownKind.keySetFor(activeKey.kid, correlationId))
            .rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    });

    it("fails closed when the timeout timer cannot be armed", async () => {
        vi.spyOn(globalThis, "setTimeout").mockImplementationOnce(() => {
            throw new Error("timer refused");
        });
        const store = new JwksKeyStore(resolveConfig(config(async () => succeeded([activeKey]))));
        await expect(store.keySetFor(activeKey.kid, correlationId)).rejects.toThrow("timer refused");
    });
});
