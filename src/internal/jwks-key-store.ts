import { createLocalJWKSet, importJWK } from "jose";
import type { SsoJwksKey, SsoJwksSnapshot } from "../types/public.js";
import type { ResolvedAuthCoreConfig } from "./config.js";
import { isValidCorrelationId } from "./correlation.js";
import { CoreFailure } from "./errors.js";
import { SafeObserver } from "./observability.js";

const KEY_FIELDS = new Set(["alg", "e", "kid", "kty", "n", "status", "use"]);
const SNAPSHOT_FIELDS = new Set(["correlationId", "freshnessSeconds", "keys", "kind"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;

type LocalKeySet = ReturnType<typeof createLocalJWKSet>;

interface AcceptedJwksSnapshot {
    readonly keysByKid: ReadonlyMap<string, SsoJwksKey>;
    readonly keySet: LocalKeySet;
    readonly acceptedAtMs: number;
    readonly expiresAtMs: number;
    readonly source: "sso" | "config" | "shorter_of_both";
}

function invalidResponse(): never {
    throw new CoreFailure("INVALID_RESPONSE");
}

export function jwksFailureReason(error: unknown) {
    if (error instanceof CoreFailure) {
        switch (error.code) {
            case "INVALID_TOKEN":
            case "INVALID_RESPONSE":
            case "UPSTREAM_UNAVAILABLE":
            case "INTERNAL_FAILURE":
                return error.code;
        }
    }
    return "INTERNAL_FAILURE" as const;
}

function hasOnlyFields(value: object, allowed: ReadonlySet<string>): boolean {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;

    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Reflect.ownKeys(value).every((field) => {
        if (typeof field !== "string" || !allowed.has(field)) return false;
        const descriptor = descriptors[field];
        return descriptor !== undefined && descriptor.get === undefined && descriptor.set === undefined;
    });
}

function isDenseArray(value: unknown): value is readonly unknown[] {
    // Array exotic ownKeys are the indices plus "length": count equality with
    // length + 1 therefore implies every index is present (per-index hasOwn is redundant).
    return Array.isArray(value) && Reflect.ownKeys(value).length === value.length + 1;
}

function validFreshnessSeconds(value: unknown): value is number {
    return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function effectiveFreshness(
    metadataSeconds: unknown,
    configuredSeconds: number | undefined,
): { readonly seconds: number; readonly source: AcceptedJwksSnapshot["source"] } {
    const metadataValid = validFreshnessSeconds(metadataSeconds);
    if (metadataValid && configuredSeconds !== undefined) {
        return {
            seconds: Math.min(metadataSeconds, configuredSeconds),
            source: "shorter_of_both",
        };
    }
    if (metadataValid) return { seconds: metadataSeconds, source: "sso" };
    if (configuredSeconds !== undefined) return { seconds: configuredSeconds, source: "config" };
    return invalidResponse();
}
function validatedKey(value: unknown): SsoJwksKey {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        !hasOnlyFields(value, KEY_FIELDS)) {
        return invalidResponse();
    }

    const { alg, e, kid, kty, n, status, use } = value as Record<string, unknown>;
    // A selected non-signing key is an authoritative absence for token verification,
    // not permission to accept malformed key purpose metadata.
    if (use !== "sig") throw new CoreFailure("INVALID_TOKEN");
    if (
        kty !== "RSA" || alg !== "RS256" ||
        (status !== "active" && status !== "retiring") ||
        typeof kid !== "string" || kid.length === 0 || kid !== kid.trim() ||
        typeof n !== "string" || n.length === 0 || !BASE64URL.test(n) ||
        typeof e !== "string" || e.length === 0 || !BASE64URL.test(e)
    ) {
        return invalidResponse();
    }
    return Object.freeze({ kty, kid, alg, use, status, n, e });
}

async function acceptedSnapshot(
    value: SsoJwksSnapshot,
    configuredSeconds: number | undefined,
): Promise<AcceptedJwksSnapshot> {
    try {
        if (!hasOnlyFields(value, SNAPSHOT_FIELDS) || !isDenseArray(value.keys)) {
            return invalidResponse();
        }
        const freshness = effectiveFreshness(value.freshnessSeconds, configuredSeconds);
        const acceptedAtMs = Date.now();
        const durationMs = freshness.seconds * 1000;
        const expiresAtMs = acceptedAtMs + durationMs;
        if (!Number.isFinite(durationMs) || !Number.isFinite(expiresAtMs) || expiresAtMs <= acceptedAtMs) {
            return invalidResponse();
        }

        const keys = value.keys.map(validatedKey);
        const keysByKid = new Map<string, SsoJwksKey>();
        for (const key of keys) {
            if (keysByKid.has(key.kid)) return invalidResponse();
            keysByKid.set(key.kid, key);
        }

        // Eager import proves every entry is usable public RS256 material before
        // the complete authoritative snapshot replaces the previous one.
        await Promise.all(keys.map((key) => importJWK({
            kty: key.kty,
            kid: key.kid,
            alg: key.alg,
            use: key.use,
            n: key.n,
            e: key.e,
        }, "RS256")));
        const keySet = createLocalJWKSet({ keys: keys.map(({ status: _status, ...key }) => key) });
        return Object.freeze({ keysByKid, keySet, acceptedAtMs, expiresAtMs, source: freshness.source });
    } catch (error) {
        if (error instanceof CoreFailure) throw error;
        return invalidResponse();
    }
}

function validateOutcome(
    outcome: unknown,
    correlationId: string,
): SsoJwksSnapshot {
    if (
        outcome === null || typeof outcome !== "object" || Array.isArray(outcome) ||
        !isValidCorrelationId((outcome as { correlationId?: unknown }).correlationId) ||
        (outcome as { correlationId: string }).correlationId !== correlationId
    ) {
        return invalidResponse();
    }
    const kind = (outcome as { kind?: unknown }).kind;
    if (kind === "cancelled" || kind === "timeout" || kind === "unavailable" || kind === "rate_limited") {
        throw new CoreFailure("UPSTREAM_UNAVAILABLE");
    }
    if (kind !== "succeeded") return invalidResponse();
    return outcome as SsoJwksSnapshot;
}
export class JwksKeyStore {
    private snapshot: AcceptedJwksSnapshot | undefined;
    private refreshFlight: Promise<AcceptedJwksSnapshot> | undefined;

    private readonly telemetry: SafeObserver;

    constructor(
        private readonly config: ResolvedAuthCoreConfig,
        telemetry?: SafeObserver,
    ) {
        this.telemetry = telemetry ?? new SafeObserver(config.observer);
    }

    async keySetFor(kid: string, correlationId: string): Promise<LocalKeySet> {
        const current = this.snapshot;
        const expired = current !== undefined && Date.now() >= current.expiresAtMs;
        if (expired) {
            const details = { outcome: "expired" as const, reason: "freshness_expired" as const };
            this.telemetry.event("jwks_expired", correlationId, details);
            this.telemetry.counter("auth.jwks.expiry.total", correlationId, details);
        }
        if (current === undefined || expired || !current.keysByKid.has(kid)) {
            await this.refresh(correlationId);
        }

        const refreshed = this.snapshot;
        if (refreshed === undefined || Date.now() >= refreshed.expiresAtMs) {
            throw new CoreFailure("UPSTREAM_UNAVAILABLE");
        }
        if (!refreshed.keysByKid.has(kid)) {
            throw new CoreFailure("INVALID_TOKEN");
        }
        return refreshed.keySet;
    }

    private refresh(correlationId: string): Promise<AcceptedJwksSnapshot> {
        if (this.refreshFlight !== undefined) {
            const details = { outcome: "coalesced" as const, reason: "unknown_kid" as const };
            this.telemetry.event("jwks_coalesced", correlationId, details);
            this.telemetry.counter("auth.jwks.coalesced.total", correlationId, details);
            return this.refreshFlight;
        }
        const flight = this.load(correlationId);
        this.refreshFlight = flight;
        // The finally callback is queued before any awaiting continuation, and
        // refresh() only replaces refreshFlight when it is undefined, so the
        // flight being cleared is always the current one.
        void flight.finally(() => { this.refreshFlight = undefined; }).catch(() => undefined);
        return flight;
    }

    private async load(correlationId: string): Promise<AcceptedJwksSnapshot> {
        const startedAt = Date.now();
        let timeoutId: ReturnType<typeof setTimeout> | undefined;
        try {
            const timeout = new Promise<never>((_resolve, reject) => {
                timeoutId = setTimeout(
                    () => reject(new CoreFailure("UPSTREAM_UNAVAILABLE")),
                    this.config.ssoRequestTimeoutMs,
                );
            });
            const outcome = await Promise.race([
                Promise.resolve()
                    .then(() => this.config.sso.getJwks({ correlationId }))
                    .catch(() => { throw new CoreFailure("UPSTREAM_UNAVAILABLE"); }),
                timeout,
            ]);
            const next = await acceptedSnapshot(
                validateOutcome(outcome, correlationId),
                this.config.jwksMaxAgeSeconds,
            );
            const previous = this.snapshot;
            const removedCount = previous === undefined
                ? 0
                : [...previous.keysByKid.keys()].filter((kid) => !next.keysByKid.has(kid)).length;
            // One assignment is the authority boundary: removed keys are no longer
            // reachable by any decision started after this accepted replacement.
            this.snapshot = next;
            const details = { outcome: "succeeded" as const };
            this.telemetry.event("jwks_refresh_completed", correlationId, { ...details, durationMs: Date.now() - startedAt });
            this.telemetry.counter("auth.jwks.refresh.total", correlationId, details);
            this.telemetry.histogram("auth.jwks.refresh.duration", correlationId, Date.now() - startedAt, details);
            if (removedCount > 0) {
                const removal = { outcome: "removed" as const, count: removedCount };
                this.telemetry.event("jwks_key_removed", correlationId, removal);
                this.telemetry.counter("auth.jwks.removal.total", correlationId, { outcome: "removed" }, removedCount);
            }
            return next;
        } catch (error) {
            const reason = jwksFailureReason(error);
            const outcome = reason === "UPSTREAM_UNAVAILABLE" ? "unavailable" as const : "rejected" as const;
            this.telemetry.event("jwks_refresh_rejected", correlationId, { outcome, reason, durationMs: Date.now() - startedAt });
            this.telemetry.counter("auth.jwks.refresh.total", correlationId, { outcome, reason });
            this.telemetry.histogram("auth.jwks.refresh.duration", correlationId, Date.now() - startedAt, { outcome, reason });
            throw error;
        } finally {
            if (timeoutId !== undefined) clearTimeout(timeoutId);
        }
    }
}
