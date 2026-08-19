export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

export interface VerifiedAuthUser {
    readonly sub: string;
    readonly email: string;
    readonly org_id: string;
    readonly roles: readonly string[];
    readonly products: readonly string[];
    readonly membership_status: MembershipStatus;
    readonly is_email_verified: boolean;
    readonly user_metadata?: Readonly<Record<string, unknown>>;
}

export interface VerifiedAuthContext {
    readonly user: VerifiedAuthUser;
    readonly verification: "verified";
    readonly correlationId: string;
}

/** Backward-compatible alias consumed by skillpassport handler files. */
export type AuthenticatedContext = VerifiedAuthContext;
/** Backward-compatible alias consumed by skillpassport action files. */
export type ContextWithUser = VerifiedAuthContext;

export type AuthCoreErrorCode =
    | "REQUEST_VALIDATION_REJECTED"
    | "MISSING_CREDENTIALS"
    | "INVALID_TOKEN"
    | "EXPIRED_TOKEN"
    | "INACTIVE_MEMBERSHIP"
    | "FORBIDDEN_ROLE"
    | "FORBIDDEN_PRODUCT"
    | "FORBIDDEN_FEATURE"
    | "INVALID_COOKIE"
    | "REFRESH_REJECTED"
    | "REVOCATION_UNCONFIRMED"
    | "INVALID_REQUEST_BODY"
    | "NOT_FOUND"
    | "CONFLICT"
    | "REAUTHENTICATION_REQUIRED"
    | "INVALID_RESPONSE"
    | "UPSTREAM_UNAVAILABLE"
    | "INTERNAL_FAILURE";

export interface AuthCoreErrorDescriptor {
    readonly code: AuthCoreErrorCode;
    readonly status: number;
    readonly retryable: boolean;
    readonly message: string;
    /** Safe replay metadata; present only when authentication failed before handler execution. */
    readonly processing?: "pre_handler";
    readonly correlationId?: string;
}
export interface Correlated {
    readonly correlationId: string;
}

/** Closed JWKS key shape published by the Task 2.1 private RPC contract. */
export interface SsoJwksKey {
    readonly kty: "RSA";
    readonly kid: string;
    readonly alg: "RS256";
    readonly use: "sig";
    readonly status: "active" | "retiring";
    readonly n: string;
    readonly e: string;
}

export interface SsoJwksSnapshot extends Correlated {
    readonly kind: "succeeded";
    readonly keys: readonly SsoJwksKey[];
    readonly freshnessSeconds?: number;
}

export type SsoJwksRpcOutcome =
    | SsoJwksSnapshot
    | (Correlated & { readonly kind: "cancelled" | "timeout" | "unavailable" })
    | (Correlated & { readonly kind: "rate_limited"; readonly retryAfterSeconds?: number });

/** Minimal projection of the closed Task 2.1 binding needed by this task. */
export interface SsoServiceBinding {
    getJwks(input: Correlated): Promise<SsoJwksRpcOutcome>;
    login(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    signup(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    signupMember(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    refreshCurrentSession(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    changeOrganization(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    logoutCurrentSession(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    logoutAllSessions(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    createInvite(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    acceptInvite(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    cancelInvite(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    resendInvite(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    requestVerification(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    verifyEmail(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    forgotPassword(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    resetPassword(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    getIdentity(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
    listOrganizations(input: Correlated & Record<string, unknown>): Promise<Correlated & { kind: string; [key: string]: any }>;
}

export type AuthObservationEventName =
    | "csrf_rejected" | "jwt_verification_rejected" | "authorization_rejected"
    | "jwks_refresh_completed" | "jwks_refresh_rejected" | "jwks_coalesced"
    | "jwks_key_removed" | "jwks_expired" | "workflow_completed" | "logout_completed";
export type AuthCounterName =
    | "auth.csrf.rejection.total" | "auth.jwt.verification.failure.total"
    | "auth.authorization.denial.total" | "auth.jwks.refresh.total"
    | "auth.jwks.coalesced.total" | "auth.jwks.removal.total"
    | "auth.jwks.expiry.total" | "auth.workflow.outcome.total"
    | "auth.logout.outcome.total";
export type AuthHistogramName =
    | "auth.jwt.verification.duration" | "auth.jwks.refresh.duration" | "auth.workflow.duration";
export type AuthObservationOutcome =
    | "succeeded" | "rejected" | "unavailable" | "coalesced" | "removed"
    | "expired" | "revoked" | "already_ended" | "revocation_unconfirmed";
export type AuthObservationReason =
    | AuthCoreErrorCode | "origin" | "csrf" | "fetch_site" | "fetch_mode"
    | "fetch_destination" | "method" | "media_type" | "route"
    | "unknown_kid" | "freshness_expired" | "current_session" | "all_sessions";
interface AuthObservationBase {
    readonly packageName: "@rareminds-eym/auth-core";
    readonly packageVersion: "3.0.0";
    readonly timestamp: number;
    readonly environment: "trusted_runtime";
    readonly correlationId: string;
}
type CsrfReason = "origin" | "csrf" | "fetch_site" | "fetch_mode"
    | "fetch_destination" | "method" | "media_type" | "route";
type VerificationReason = "MISSING_CREDENTIALS" | "INVALID_TOKEN" | "EXPIRED_TOKEN"
    | "INVALID_RESPONSE" | "UPSTREAM_UNAVAILABLE" | "INTERNAL_FAILURE";
type JwksFailureReason = "INVALID_TOKEN" | "INVALID_RESPONSE" | "UPSTREAM_UNAVAILABLE"
    | "INTERNAL_FAILURE";
type AuthorizationReason = "INACTIVE_MEMBERSHIP" | "FORBIDDEN_ROLE" | "FORBIDDEN_PRODUCT"
    | "FORBIDDEN_FEATURE" | "INTERNAL_FAILURE";
type LogoutObservationOutcome = "revoked" | "already_ended" | "revocation_unconfirmed";
type CoreEventObservation =
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "csrf_rejected"; readonly outcome: "rejected"; readonly reason: CsrfReason })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwt_verification_rejected"; readonly outcome: "rejected"; readonly reason: VerificationReason; readonly durationMs: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "authorization_rejected"; readonly outcome: "rejected"; readonly reason: AuthorizationReason })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwks_refresh_completed"; readonly outcome: "succeeded"; readonly durationMs: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwks_refresh_rejected"; readonly outcome: "rejected" | "unavailable"; readonly reason: JwksFailureReason; readonly durationMs: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwks_coalesced"; readonly outcome: "coalesced"; readonly reason: "unknown_kid"; readonly count?: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwks_key_removed"; readonly outcome: "removed"; readonly count: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "jwks_expired"; readonly outcome: "expired"; readonly reason: "freshness_expired" })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "workflow_completed"; readonly outcome: "succeeded" | "rejected" | "unavailable"; readonly reason?: AuthObservationReason; readonly durationMs: number })
    | (AuthObservationBase & { readonly kind: "event"; readonly event: "logout_completed"; readonly outcome: LogoutObservationOutcome; readonly reason: "current_session" | "all_sessions"; readonly durationMs: number });
type CoreCounterObservation = AuthObservationBase & {
    readonly kind: "counter"; readonly value: number;
} & (
        | { readonly metric: "auth.csrf.rejection.total"; readonly outcome: "rejected"; readonly reason: CsrfReason }
        | { readonly metric: "auth.jwt.verification.failure.total"; readonly outcome: "rejected"; readonly reason: VerificationReason }
        | { readonly metric: "auth.authorization.denial.total"; readonly outcome: "rejected"; readonly reason: AuthorizationReason }
        | { readonly metric: "auth.jwks.refresh.total"; readonly outcome: "succeeded" | "rejected" | "unavailable"; readonly reason?: JwksFailureReason }
        | { readonly metric: "auth.jwks.coalesced.total"; readonly outcome: "coalesced"; readonly reason: "unknown_kid" }
        | { readonly metric: "auth.jwks.removal.total"; readonly outcome: "removed" }
        | { readonly metric: "auth.jwks.expiry.total"; readonly outcome: "expired"; readonly reason: "freshness_expired" }
        | { readonly metric: "auth.workflow.outcome.total"; readonly outcome: "succeeded" | "rejected" | "unavailable"; readonly reason?: AuthObservationReason }
        | { readonly metric: "auth.logout.outcome.total"; readonly outcome: LogoutObservationOutcome; readonly reason: "current_session" | "all_sessions" }
    );
type CoreHistogramObservation = AuthObservationBase & {
    readonly kind: "histogram"; readonly value: number; readonly unit: "ms";
} & (
        | { readonly metric: "auth.jwt.verification.duration"; readonly outcome: "succeeded" | "rejected"; readonly reason?: VerificationReason }
        | { readonly metric: "auth.jwks.refresh.duration"; readonly outcome: "succeeded" | "rejected" | "unavailable"; readonly reason?: JwksFailureReason }
        | { readonly metric: "auth.workflow.duration"; readonly outcome: "succeeded" | "rejected" | "unavailable"; readonly reason?: AuthObservationReason }
    );
/** Closed, low-cardinality observations; no arbitrary attribute bag is accepted. */
export type AuthObservation = CoreEventObservation | CoreCounterObservation | CoreHistogramObservation;

export interface AuthCoreConfig {
    readonly sso: SsoServiceBinding;
    readonly issuer: string;
    readonly audience: string;
    readonly approvedOrigins: readonly string[];
    readonly basePath?: string;
    readonly csrf: { readonly name: "X-RM-CSRF"; readonly value: "1" };
    readonly cookieMaxAgeSeconds: number;
    readonly jwksMaxAgeSeconds?: number;
    readonly ssoRequestTimeoutMs: number;
    readonly credentialedCors?: false | { readonly origins: readonly string[] };
    readonly observer?: (event: AuthObservation) => void;
    readonly correlationId?: (request: Request) => string;
}

export type RequestHandler = (request: Request) => Promise<Response>;
export type AuthenticatedHandler = (
    request: Request,
    context: VerifiedAuthContext,
) => Promise<Response> | Response;
export type FeatureCheck = (
    request: Request,
    context: VerifiedAuthContext,
) => Promise<boolean> | boolean;

export interface Auth {
    /** Verifies one Bearer credential before creating an immutable request-bound context. */
    authenticate(handler: AuthenticatedHandler): RequestHandler;
    /** Allows only verified requests whose membership is active. */
    requireActiveMembership(handler: AuthenticatedHandler): AuthenticatedHandler;
    /** Allows only verified requests having at least one normalized allowed role. */
    requireRole(allowed: readonly string[], handler: AuthenticatedHandler): AuthenticatedHandler;
    /** Allows only verified requests having at least one normalized allowed product. */
    requireProduct(allowed: readonly string[], handler: AuthenticatedHandler): AuthenticatedHandler;
    /** Allows only verified requests explicitly approved by the application feature policy. */
    requireFeature(check: FeatureCheck, handler: AuthenticatedHandler): AuthenticatedHandler;
    handleBrowserRequest(request: Request): Promise<Response>;
}
