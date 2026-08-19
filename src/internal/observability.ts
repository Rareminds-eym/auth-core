import type {
    AuthCoreConfig,
    AuthCounterName,
    AuthHistogramName,
    AuthObservation,
    AuthObservationEventName,
    AuthObservationOutcome,
    AuthObservationReason
} from "../types/public.js";
import { isValidCorrelationId } from "./correlation-format.js";

export type ObservationMode = "production" | "debug";
type DetailKey = "outcome" | "reason" | "durationMs" | "retryCount" | "count";
interface EventPolicy {
    readonly allowed: ReadonlySet<DetailKey>;
    readonly required: ReadonlySet<DetailKey>;
    readonly outcomes: ReadonlySet<AuthObservationOutcome>;
    readonly reasons?: ReadonlySet<AuthObservationReason>;
}

const keys = (...values: DetailKey[]): ReadonlySet<DetailKey> => new Set(values);
const outcomes = (...values: AuthObservationOutcome[]): ReadonlySet<AuthObservationOutcome> => new Set(values);
const reasons = (...values: AuthObservationReason[]): ReadonlySet<AuthObservationReason> => new Set(values);
const CSRF_REASONS = reasons("origin", "csrf", "fetch_site", "fetch_mode", "fetch_destination", "method", "media_type", "route");
const VERIFICATION_REASONS = reasons("MISSING_CREDENTIALS", "INVALID_TOKEN", "EXPIRED_TOKEN", "INVALID_RESPONSE", "UPSTREAM_UNAVAILABLE", "INTERNAL_FAILURE");
const AUTHORIZATION_REASONS = reasons("INACTIVE_MEMBERSHIP", "FORBIDDEN_ROLE", "FORBIDDEN_PRODUCT", "FORBIDDEN_FEATURE", "INTERNAL_FAILURE");
const JWKS_REASONS = reasons("INVALID_TOKEN", "INVALID_RESPONSE", "UPSTREAM_UNAVAILABLE", "INTERNAL_FAILURE");
const LOGOUT_REASONS = reasons("current_session", "all_sessions");
const EVENT_POLICIES = Object.freeze({
    csrf_rejected: { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("rejected"), reasons: CSRF_REASONS },
    jwt_verification_rejected: { allowed: keys("outcome", "reason", "durationMs"), required: keys("outcome", "reason", "durationMs"), outcomes: outcomes("rejected"), reasons: VERIFICATION_REASONS },
    authorization_rejected: { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("rejected"), reasons: AUTHORIZATION_REASONS },
    jwks_refresh_completed: { allowed: keys("outcome", "durationMs"), required: keys("outcome", "durationMs"), outcomes: outcomes("succeeded") },
    jwks_refresh_rejected: { allowed: keys("outcome", "reason", "durationMs"), required: keys("outcome", "reason", "durationMs"), outcomes: outcomes("rejected", "unavailable"), reasons: JWKS_REASONS },
    jwks_coalesced: { allowed: keys("outcome", "reason", "count"), required: keys("outcome", "reason"), outcomes: outcomes("coalesced"), reasons: reasons("unknown_kid") },
    jwks_key_removed: { allowed: keys("outcome", "count"), required: keys("outcome", "count"), outcomes: outcomes("removed") },
    jwks_expired: { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("expired"), reasons: reasons("freshness_expired") },
    workflow_completed: { allowed: keys("outcome", "reason", "durationMs"), required: keys("outcome", "durationMs"), outcomes: outcomes("succeeded", "rejected", "unavailable") },
    logout_completed: { allowed: keys("outcome", "reason", "durationMs"), required: keys("outcome", "reason", "durationMs"), outcomes: outcomes("revoked", "already_ended", "revocation_unconfirmed"), reasons: LOGOUT_REASONS },
}) satisfies Readonly<Record<AuthObservationEventName, EventPolicy>>;

const COUNTER_POLICIES = Object.freeze({
    "auth.csrf.rejection.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("rejected"), reasons: CSRF_REASONS },
    "auth.jwt.verification.failure.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("rejected"), reasons: VERIFICATION_REASONS },
    "auth.authorization.denial.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("rejected"), reasons: AUTHORIZATION_REASONS },
    "auth.jwks.refresh.total": { allowed: keys("outcome", "reason"), required: keys("outcome"), outcomes: outcomes("succeeded", "rejected", "unavailable"), reasons: JWKS_REASONS },
    "auth.jwks.coalesced.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("coalesced"), reasons: reasons("unknown_kid") },
    "auth.jwks.removal.total": { allowed: keys("outcome"), required: keys("outcome"), outcomes: outcomes("removed") },
    "auth.jwks.expiry.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("expired"), reasons: reasons("freshness_expired") },
    "auth.workflow.outcome.total": { allowed: keys("outcome", "reason"), required: keys("outcome"), outcomes: outcomes("succeeded", "rejected", "unavailable") },
    "auth.logout.outcome.total": { allowed: keys("outcome", "reason"), required: keys("outcome", "reason"), outcomes: outcomes("revoked", "already_ended", "revocation_unconfirmed"), reasons: LOGOUT_REASONS },
}) satisfies Readonly<Record<AuthCounterName, EventPolicy>>;
const HISTOGRAM_POLICIES = Object.freeze({
    "auth.jwt.verification.duration": { allowed: keys("outcome", "reason"), required: keys("outcome"), outcomes: outcomes("succeeded", "rejected"), reasons: VERIFICATION_REASONS },
    "auth.jwks.refresh.duration": { allowed: keys("outcome", "reason"), required: keys("outcome"), outcomes: outcomes("succeeded", "rejected", "unavailable"), reasons: JWKS_REASONS },
    "auth.workflow.duration": { allowed: keys("outcome", "reason"), required: keys("outcome"), outcomes: outcomes("succeeded", "rejected", "unavailable") },
}) satisfies Readonly<Record<AuthHistogramName, EventPolicy>>;
const OUTCOMES = new Set<AuthObservationOutcome>([
    "succeeded", "rejected", "unavailable", "coalesced", "removed", "expired",
    "revoked", "already_ended", "revocation_unconfirmed",
]);
const REASONS = new Set<AuthObservationReason>([
    "REQUEST_VALIDATION_REJECTED", "MISSING_CREDENTIALS", "INVALID_TOKEN", "EXPIRED_TOKEN",
    "INACTIVE_MEMBERSHIP", "FORBIDDEN_ROLE", "FORBIDDEN_PRODUCT", "FORBIDDEN_FEATURE",
    "INVALID_COOKIE", "REFRESH_REJECTED", "REVOCATION_UNCONFIRMED", "INVALID_RESPONSE",
    "UPSTREAM_UNAVAILABLE", "INTERNAL_FAILURE", "origin", "csrf", "fetch_site", "fetch_mode",
    "fetch_destination", "method", "media_type", "route", "unknown_kid", "freshness_expired",
    "current_session", "all_sessions",
]);

export interface CoreObservationDetails {
    readonly outcome: AuthObservationOutcome;
    readonly reason?: AuthObservationReason;
    readonly durationMs?: number;
    readonly retryCount?: number;
    readonly count?: number;
}
type ObservationBaseKey = "packageName" | "packageVersion" | "timestamp" | "environment" |
    "correlationId" | "kind";
type EventDetails<E extends AuthObservationEventName> = Omit<
    Extract<AuthObservation, { readonly kind: "event"; readonly event: E }>,
    ObservationBaseKey | "event"
>;
type CounterDetails<M extends AuthCounterName> = Omit<
    Extract<AuthObservation, { readonly kind: "counter"; readonly metric: M }>,
    ObservationBaseKey | "metric" | "value"
>;
type HistogramDetails<M extends AuthHistogramName> = Omit<
    Extract<AuthObservation, { readonly kind: "histogram"; readonly metric: M }>,
    ObservationBaseKey | "metric" | "value" | "unit"
>;

function safeNumber(value: unknown, integer = false): value is number {
    return typeof value === "number" && Number.isFinite(value) && value >= 0 && (!integer || Number.isSafeInteger(value));
}

/**
 * Copies only allowlisted own data properties before validation. The snapshot
 * prevents accessors, mutable objects, and stateful proxies from changing the
 * fields between validation and publication.
 */
function snapshotDetails(
    details: unknown,
    policy: EventPolicy,
): CoreObservationDetails | undefined {
    if (details === null || typeof details !== "object" || Array.isArray(details)) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(details);
    const fields = Reflect.ownKeys(descriptors);
    const snapshot: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const field of fields) {
        if (typeof field !== "string" || !policy.allowed.has(field as DetailKey)) return undefined;
        const descriptor = descriptors[field];
        if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined ||
            descriptor.enumerable !== true) return undefined;
        snapshot[field] = descriptor.value;
    }
    if ([...policy.required].some((key) => !Object.hasOwn(snapshot, key))) return undefined;
    const candidate = snapshot as unknown as CoreObservationDetails;
    if (!OUTCOMES.has(candidate.outcome) || !policy.outcomes.has(candidate.outcome)) return undefined;
    if (candidate.reason !== undefined &&
        (!REASONS.has(candidate.reason) || (policy.reasons !== undefined && !policy.reasons.has(candidate.reason)))) {
        return undefined;
    }
    if (candidate.durationMs !== undefined && !safeNumber(candidate.durationMs)) return undefined;
    if (candidate.retryCount !== undefined && !safeNumber(candidate.retryCount, true)) return undefined;
    if (candidate.count !== undefined && !safeNumber(candidate.count, true)) return undefined;
    return candidate;
}
function base(correlationId: string) {
    const timestamp = Date.now();
    if (!safeNumber(timestamp)) return undefined;
    return {
        packageName: "@rareminds-eym/auth-core" as const,
        packageVersion: "3.0.0" as const,
        timestamp,
        environment: "trusted_runtime" as const,
        correlationId,
    };
}

/** Emits one closed low-cardinality schema in production and debug, isolating all faults. */
export class SafeObserver {
    readonly #observer: AuthCoreConfig["observer"];
    readonly #mode: ObservationMode;

    constructor(observer: AuthCoreConfig["observer"], mode: ObservationMode = "production") {
        this.#observer = observer;
        this.#mode = mode;
    }

    event<E extends AuthObservationEventName>(event: E, correlationId: string, details: EventDetails<E>): void {
        this.#attempt(() => {
            const policy = EVENT_POLICIES[event];
            if (policy === undefined || !isValidCorrelationId(correlationId)) return;
            const candidate = snapshotDetails(details, policy);
            const common = base(correlationId);
            if (candidate === undefined || common === undefined) return;
            this.#emit(Object.freeze({ kind: "event", event, ...common, ...candidate } as AuthObservation));
        });
    }

    counter<M extends AuthCounterName>(metric: M, correlationId: string, details: CounterDetails<M>, value = 1): void {
        this.#attempt(() => {
            const policy = COUNTER_POLICIES[metric];
            if (policy === undefined || !safeNumber(value, true) || !isValidCorrelationId(correlationId)) return;
            const candidate = snapshotDetails(details, policy);
            const common = base(correlationId);
            if (candidate === undefined || common === undefined) return;
            this.#emit(Object.freeze({ kind: "counter", metric, value, ...common, ...candidate } as AuthObservation));
        });
    }

    histogram<M extends AuthHistogramName>(metric: M, correlationId: string, value: number, details: HistogramDetails<M>): void {
        this.#attempt(() => {
            const policy = HISTOGRAM_POLICIES[metric];
            if (policy === undefined || !safeNumber(value) || !isValidCorrelationId(correlationId)) return;
            const candidate = snapshotDetails(details, policy);
            const common = base(correlationId);
            if (candidate === undefined || common === undefined) return;
            this.#emit(Object.freeze({ kind: "histogram", metric, value, unit: "ms", ...common, ...candidate } as AuthObservation));
        });
    }

    #attempt(operation: () => void): void {
        try { operation(); } catch { /* Validation and clock faults are telemetry-only. */ }
    }

    #emit(observation: AuthObservation): void {
        if (this.#mode !== "production" && this.#mode !== "debug") return;
        try { this.#observer?.(observation); } catch { /* Telemetry is never part of auth control flow. */ }
    }
}
