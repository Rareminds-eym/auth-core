import { describe, expect, it, vi } from "vitest";
import { createAuth } from "../index.js";
import type { AuthCoreConfig, AuthObservation } from "../types/public.js";
import { SafeObserver } from "./observability.js";

function config(observer?: (event: AuthObservation) => void): AuthCoreConfig {
    return {
        sso: {
            async getJwks({ correlationId }) {
                return { kind: "unavailable", correlationId };
            },
        },
        issuer: "https://issuer.example",
        audience: "resource",
        approvedOrigins: ["https://app.example"],
        csrf: { name: "X-RM-CSRF", value: "1" },
        cookieMaxAgeSeconds: 3600,
        jwksMaxAgeSeconds: 60,
        ssoRequestTimeoutMs: 8000,
        correlationId: () => "safe-correlation-1",
        observer,
    };
}

describe("safe Auth Core observability", () => {
    it("emits frozen allowlisted events, counters, and histograms", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));

        observer.event("jwt_verification_rejected", "safe-correlation-1", {
            outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 3,
        });
        observer.counter("auth.jwt.verification.failure.total", "safe-correlation-1", {
            outcome: "rejected", reason: "INVALID_TOKEN",
        });
        observer.histogram("auth.jwt.verification.duration", "safe-correlation-1", 3, {
            outcome: "rejected", reason: "INVALID_TOKEN",
        });

        expect(records).toHaveLength(3);
        expect(records.map((record) => record.kind)).toEqual(["event", "counter", "histogram"]);
        expect(records.every(Object.isFrozen)).toBe(true);
        expect(records.every((record) => record.packageName === "@rareminds-eym/auth-core")).toBe(true);
        expect(records.every((record) => record.correlationId === "safe-correlation-1")).toBe(true);
    });
    it("rejects prohibited dynamic canaries and isolates observer exceptions", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));

        observer.event("jwt_verification_rejected", "eyJhbGciOiJSUzI1NiJ9.payload.signature", {
            outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 1,
        });
        observer.event("jwt_verification_rejected", "safe-correlation-1", {
            outcome: "rejected", reason: "Bearer-secret", durationMs: 1,
        } as never);
        expect(records).toEqual([]);

        const faulty = new SafeObserver(() => { throw new Error("observer failure with secret details"); });
        expect(() => faulty.counter(
            "auth.csrf.rejection.total",
            "safe-correlation-1",
            { outcome: "rejected", reason: "csrf" },
        )).not.toThrow();
    });

    it("keeps correlation on verification telemetry and observer faults out of auth behavior", async () => {
        const records: AuthObservation[] = [];
        const auth = createAuth(config((record) => records.push(record)));
        const response = await auth.authenticate(() => new Response("unexpected"))(
            new Request("https://app.example/protected"),
        );

        expect(response.status).toBe(401);
        expect(records.map((record) => record.kind)).toEqual(["event", "counter", "histogram"]);
        expect(records.every((record) => record.correlationId === "safe-correlation-1")).toBe(true);
        expect(JSON.stringify(records)).not.toMatch(/protected|user-agent|cookie|bearer/i);

        const faultIsolated = createAuth(config(() => { throw new Error("observer failure"); }));
        const rejected = await faultIsolated.handleBrowserRequest(
            new Request("https://app.example/api/auth/session", { method: "POST" }),
        );
        expect(rejected.status).toBe(403);
    });

    it("uses identical production/debug schemas and rejects inapplicable fields", () => {
        vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
        const byMode = (["production", "debug"] as const).map((mode) => {
            const records: AuthObservation[] = [];
            const observer = new SafeObserver((record) => records.push(record), mode);
            observer.event("jwks_refresh_completed", "correlation-parity-1", {
                outcome: "succeeded", durationMs: 4,
            });
            observer.counter("auth.jwks.refresh.total", "correlation-parity-1", { outcome: "succeeded" });
            observer.histogram("auth.jwks.refresh.duration", "correlation-parity-1", 4, { outcome: "succeeded" });
            return records;
        });
        expect(byMode[0]).toEqual(byMode[1]);
        expect(byMode[0].every((record) => !("mode" in record))).toBe(true);

        const rejected: AuthObservation[] = [];
        const observer = new SafeObserver((record) => rejected.push(record));
        observer.event("csrf_rejected", "correlation-safe-2", {
            outcome: "rejected", reason: "csrf", durationMs: 1,
        } as never);
        observer.event("jwks_refresh_completed", "correlation-safe-2", {
            outcome: "unavailable", durationMs: 1,
        } as never);
        observer.counter("auth.jwks.refresh.total", "correlation-safe-2", {
            outcome: "succeeded", durationMs: 1,
        } as never);
        expect(rejected).toEqual([]);
        vi.restoreAllMocks();
    });

    it("isolates hostile validation objects and rejects prohibited correlation canaries", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));
        const hostile = new Proxy({ outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 1 }, {
            ownKeys() { throw new Error("password=canary"); },
        });
        expect(() => observer.event(
            "jwt_verification_rejected", "correlation-safe-3", hostile as never,
        )).not.toThrow();
        for (const correlationId of [
            "person@example.test", "https:-request", "access-token-prefix-1",
            "refresh-family-1", "database-identifier-1", "rotation-detail-1",
            "overlap-internal-1", "reuse-evidence-1", "raw-claim-1",
            "subject-identifier-1", "organization-id-1", "session-id-1",
            "stack-trace-1", "exception-detail-1", "192.0.2.1", "user-agent-1",
        ]) {
            observer.event("jwt_verification_rejected", correlationId, {
                outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 1,
            });
        }
        expect(records).toEqual([]);
    });
});

describe("observation snapshot isolation", () => {
    it("projects one allowlisted data-property snapshot from stateful inputs", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));
        let descriptorReads = 0;
        const stateful = new Proxy({
            outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 2,
        }, {
            ownKeys() {
                descriptorReads += 1;
                return descriptorReads === 1
                    ? ["outcome", "reason", "durationMs"]
                    : ["outcome", "reason", "durationMs", "authorization"];
            },
            getOwnPropertyDescriptor(target, property) {
                if (property === "authorization") {
                    return { configurable: true, enumerable: true, value: "Bearer secret-canary", writable: false };
                }
                return Object.getOwnPropertyDescriptor(target, property);
            },
        });

        observer.event("jwt_verification_rejected", "correlation-snapshot-1", stateful as never);

        expect(records).toHaveLength(1);
        expect(descriptorReads).toBe(1);
        expect(Object.keys(records[0]!).sort()).toEqual([
            "correlationId", "durationMs", "environment", "event", "kind", "outcome",
            "packageName", "packageVersion", "reason", "timestamp",
        ]);
        expect(JSON.stringify(records)).not.toContain("secret-canary");

        let getterInvoked = false;
        observer.event("jwt_verification_rejected", "correlation-snapshot-2", {
            get outcome() { getterInvoked = true; return "rejected"; },
            reason: "INVALID_TOKEN",
            durationMs: 2,
        } as never);
        expect(getterInvoked).toBe(false);
        expect(records).toHaveLength(1);
    });
});

describe("observation catalog coverage", () => {
    it("accepts every required core event and metric family", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));
        const correlationId = "core-catalog-1";

        observer.event("csrf_rejected", correlationId, { outcome: "rejected", reason: "csrf" });
        observer.event("jwt_verification_rejected", correlationId, { outcome: "rejected", reason: "INVALID_TOKEN", durationMs: 1 });
        observer.event("authorization_rejected", correlationId, { outcome: "rejected", reason: "FORBIDDEN_ROLE" });
        observer.event("jwks_refresh_completed", correlationId, { outcome: "succeeded", durationMs: 1 });
        observer.event("jwks_refresh_rejected", correlationId, { outcome: "unavailable", reason: "UPSTREAM_UNAVAILABLE", durationMs: 1 });
        observer.event("jwks_coalesced", correlationId, { outcome: "coalesced", reason: "unknown_kid", count: 2 });
        observer.event("jwks_key_removed", correlationId, { outcome: "removed", count: 1 });
        observer.event("jwks_expired", correlationId, { outcome: "expired", reason: "freshness_expired" });
        observer.event("workflow_completed", correlationId, { outcome: "succeeded", durationMs: 1 });
        observer.event("logout_completed", correlationId, { outcome: "revoked", reason: "current_session", durationMs: 1 });

        observer.counter("auth.csrf.rejection.total", correlationId, { outcome: "rejected", reason: "csrf" });
        observer.counter("auth.jwt.verification.failure.total", correlationId, { outcome: "rejected", reason: "INVALID_TOKEN" });
        observer.counter("auth.authorization.denial.total", correlationId, { outcome: "rejected", reason: "FORBIDDEN_ROLE" });
        observer.counter("auth.jwks.refresh.total", correlationId, { outcome: "succeeded" });
        observer.counter("auth.jwks.coalesced.total", correlationId, { outcome: "coalesced", reason: "unknown_kid" });
        observer.counter("auth.jwks.removal.total", correlationId, { outcome: "removed" });
        observer.counter("auth.jwks.expiry.total", correlationId, { outcome: "expired", reason: "freshness_expired" });
        observer.counter("auth.workflow.outcome.total", correlationId, { outcome: "succeeded" });
        observer.counter("auth.logout.outcome.total", correlationId, { outcome: "revoked", reason: "current_session" });

        observer.histogram("auth.jwt.verification.duration", correlationId, 1, { outcome: "succeeded" });
        observer.histogram("auth.jwks.refresh.duration", correlationId, 1, { outcome: "succeeded" });
        observer.histogram("auth.workflow.duration", correlationId, 1, { outcome: "succeeded" });

        expect(records).toHaveLength(22);
        expect(new Set(records.filter((record) => record.kind === "event").map((record) => record.event)).size).toBe(10);
        expect(new Set(records.filter((record) => record.kind !== "event").map((record) => record.metric)).size).toBe(12);
    });

    it("rejects semantically mismatched safe enums", () => {
        const records: AuthObservation[] = [];
        const observer = new SafeObserver((record) => records.push(record));

        observer.event("csrf_rejected", "core-semantic-1", {
            outcome: "rejected", reason: "INVALID_TOKEN",
        } as never);
        observer.event("authorization_rejected", "core-semantic-1", {
            outcome: "rejected", reason: "csrf",
        } as never);
        observer.counter("auth.logout.outcome.total", "core-semantic-1", {
            outcome: "revoked", reason: "unknown_kid",
        } as never);

        expect(records).toEqual([]);
    });
});