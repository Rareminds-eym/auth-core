import type {
    AuthCoreErrorCode,
} from "../../types/public.js";
import { CoreFailure, errorResponse } from "../errors.js";
import { CookieCodec } from "./cookie-codec.js";
import { BrowserAuthRoute } from "./browser-route-guard.js";
import { ResolvedAuthCoreConfig } from "../config.js";
import { SafeObserver } from "../telemetry/observability.js";
import { correlationIdFor } from "../telemetry/correlation.js";

/** Exact headers the SDK-private client requires on every JSON response (wireDecoder.ts). */
const JSON_RESPONSE_HEADERS = Object.freeze({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Expires": "Thu, 01 Jan 1970 00:00:00 GMT",
    "X-Content-Type-Options": "nosniff",
});

/** The legacy in-band credential header is tombstoned without verification; Authorization Bearer is the sanctioned SDK transport. */
const LEGACY_CREDENTIAL_HEADERS = Object.freeze(["X-Access-Token"]);

interface RouteBodySpec {
    readonly allowed: readonly string[];
    readonly required: readonly string[];
}

/** Per-route permitted body properties (Task 4.5): any other property is rejected with 400. */
const ROUTE_BODY_SPECS: Readonly<Record<string, RouteBodySpec>> = Object.freeze({
    "/login": Object.freeze({ allowed: Object.freeze(["email", "password"]), required: Object.freeze(["email", "password"]) }),
    "/signup": Object.freeze({ allowed: Object.freeze(["email", "password", "organizationName", "role", "redirectUrl", "userMetadata"]), required: Object.freeze(["email", "password"]) }),
    "/signup-member": Object.freeze({ allowed: Object.freeze(["email", "password", "role", "organizationId", "redirectUrl", "userMetadata"]), required: Object.freeze(["email", "password"]) }),
    "/session": Object.freeze({ allowed: Object.freeze([]), required: Object.freeze([]) }),
    "/session/organization": Object.freeze({ allowed: Object.freeze(["organizationId"]), required: Object.freeze(["organizationId"]) }),
    "/me": Object.freeze({ allowed: Object.freeze([]), required: Object.freeze([]) }),
    "/organizations": Object.freeze({ allowed: Object.freeze([]), required: Object.freeze([]) }),
    "/logout/current": Object.freeze({ allowed: Object.freeze([]), required: Object.freeze([]) }),
    "/logout/all": Object.freeze({ allowed: Object.freeze([]), required: Object.freeze([]) }),
    "/password/forgot": Object.freeze({ allowed: Object.freeze(["email"]), required: Object.freeze(["email"]) }),
    "/password/reset": Object.freeze({ allowed: Object.freeze(["resetToken", "password"]), required: Object.freeze(["resetToken", "password"]) }),
    "/verification/request": Object.freeze({ allowed: Object.freeze(["redirectUrl"]), required: Object.freeze([]) }),
    "/verification/complete": Object.freeze({ allowed: Object.freeze(["verificationToken"]), required: Object.freeze(["verificationToken"]) }),
    "/invite": Object.freeze({ allowed: Object.freeze(["email", "organizationId", "roles"]), required: Object.freeze(["email", "organizationId"]) }),
    "/invite/accept": Object.freeze({ allowed: Object.freeze(["invitationToken", "password"]), required: Object.freeze(["invitationToken"]) }),
    "/invite/cancel": Object.freeze({ allowed: Object.freeze(["inviteId"]), required: Object.freeze(["inviteId"]) }),
    "/invite/resend": Object.freeze({ allowed: Object.freeze(["inviteId"]), required: Object.freeze(["inviteId"]) }),
});

/**
 * Session-issue rejection mapping to the SDK-private client's closed rejection
 * vocabulary (client.ts REJECTION_CODES) with matching HTTP statuses.
 */
const SESSION_REJECTION: Readonly<Record<string, { readonly status: number; readonly code: string }>> = Object.freeze({
    invalid_credentials: Object.freeze({ status: 401, code: "invalid_credentials" }),
    account_blocked: Object.freeze({ status: 403, code: "blocked" }),
    identity_conflict: Object.freeze({ status: 409, code: "conflict" }),
    invalid_invitation: Object.freeze({ status: 404, code: "not_found" }),
    invitation_expired: Object.freeze({ status: 404, code: "expired" }),
    membership_rejected: Object.freeze({ status: 403, code: "not_authorized" }),
    invalid_request: Object.freeze({ status: 400, code: "invalid_input" }),
});

/** Workflow rejection mapping (invites, verification, password reset) to the same vocabulary. */
const WORKFLOW_REJECTION: Readonly<Record<string, { readonly status: number; readonly code: string }>> = Object.freeze({
    authorization_denied: Object.freeze({ status: 403, code: "not_authorized" }),
    not_found: Object.freeze({ status: 404, code: "not_found" }),
    conflict: Object.freeze({ status: 409, code: "conflict" }),
    expired: Object.freeze({ status: 404, code: "expired" }),
    already_used: Object.freeze({ status: 409, code: "conflict" }),
    invalid_one_time_value: Object.freeze({ status: 400, code: "invalid_input" }),
    account_blocked: Object.freeze({ status: 403, code: "blocked" }),
    invalid_request: Object.freeze({ status: 400, code: "invalid_input" }),
});

/** Definitive session outcomes from refresh/rotation RPCs are typed 401s. */
const DEFINITIVE_SESSION_REJECTION = Object.freeze({ status: 401, code: "not_authenticated" });

function isTransient(outcome: Readonly<Record<string, unknown>>): boolean {
    return outcome.kind === "cancelled" || outcome.kind === "rate_limited" || outcome.kind === "timeout" || outcome.kind === "unavailable";
}

function responseData(data: unknown): Response {
    return new Response(JSON.stringify(data), {
        status: 200,
        headers: JSON_RESPONSE_HEADERS,
    });
}

/** SDK-client rejection body: { status: "rejected", code } with an exact-vocabulary code. */
function rejectionResponse(rejection: { readonly status: number; readonly code: string }, correlationId: string, extraHeaders?: Record<string, string>): Response {
    return new Response(JSON.stringify({ status: "rejected", code: rejection.code }), {
        status: rejection.status,
        headers: { ...JSON_RESPONSE_HEADERS, ...extraHeaders },
    });
}

type SessionRoute =
    | "login"
    | "signup"
    | "signup-member"
    | "invite-accept"
    | "session"
    | "session-organization";

interface SessionWireState {
    readonly accessToken: string;
    readonly refreshToken: string;
    readonly remainingLifetimeSeconds: number;
    readonly identity: {
        readonly subject: string;
        readonly email: string;
        readonly organizationId: string;
        readonly roles: readonly string[];
        readonly products: readonly string[];
        readonly membershipStatus: string;
        readonly emailVerified: boolean;
        readonly userMetadata?: Readonly<Record<string, unknown>>;
    };
}

/** Client-shaped organization DTO for signup data; name/slug are unavailable on the RPC identity surface. */
function organizationOf(identity: SessionWireState["identity"]): { readonly id: string; readonly name: null; readonly slug: null; readonly roles: readonly string[]; readonly active: boolean } {
    return Object.freeze({
        id: identity.organizationId,
        name: null,
        slug: null,
        roles: identity.roles,
        active: identity.membershipStatus === "active",
    });
}

/** Per-route wire outcome and data DTO (client.ts decoders demand exact keys). */
function sessionDataFor(route: SessionRoute, outcome: Record<string, any>): { readonly outcome: "created" | "rotated" | "overlap"; readonly data?: unknown } {
    if (route === "session") return { outcome: outcome.kind === "overlap" ? "overlap" : "rotated", data: undefined };
    const identity = outcome.session.identity as SessionWireState["identity"];
    if (route === "session-organization") {
        return { outcome: "rotated", data: Object.freeze({ organizationId: identity.organizationId, roles: identity.roles }) };
    }
    if (route === "login") return { outcome: "created", data: Object.freeze({ identity }) };
    if (route === "signup") {
        return { outcome: "created", data: Object.freeze({ identity, organization: organizationOf(identity), emailSent: outcome.emailSent === true }) };
    }
    if (route === "signup-member") {
        return {
            outcome: "created",
            data: Object.freeze({
                identity,
                emailSent: outcome.emailSent === true,
                ...(identity.organizationId === "" ? {} : { organization: organizationOf(identity) }),
            }),
        };
    }
    return { outcome: "created", data: Object.freeze({ identity, organizationId: identity.organizationId }) };
}

/** SDK-private session envelope: { ok, credential, identity, outcome, data?, correlationId? }. */
function sessionResponse(
    cookieCodec: CookieCodec,
    outcome: Record<string, any>,
    correlationId: string,
    route: SessionRoute,
): Response {
    if (outcome.kind === "rejected") {
        return rejectionResponse(SESSION_REJECTION[outcome.code ?? ""] ?? DEFINITIVE_SESSION_REJECTION, correlationId);
    }
    if (isTransient(outcome)) return errorResponse("UPSTREAM_UNAVAILABLE", correlationId);
    if ((outcome.kind !== "issued" && outcome.kind !== "rotated" && outcome.kind !== "overlap") || !outcome.session) {
        return errorResponse("INTERNAL_FAILURE", correlationId);
    }
    const { outcome: wireOutcome, data } = sessionDataFor(route, outcome);
    const envelope = {
        ok: true,
        credential: { accessToken: outcome.session.accessToken },
        identity: outcome.session.identity,
        outcome: wireOutcome,
        ...(data === undefined ? {} : { data }),
        correlationId,
    };
    return new Response(JSON.stringify(envelope), {
        status: 200,
        headers: {
            ...JSON_RESPONSE_HEADERS,
            "Set-Cookie": cookieCodec.create(outcome.session.refreshToken, outcome.session.remainingLifetimeSeconds),
        },
    });
}

function clearSessionResponse(cookieCodec: CookieCodec, outcome: "current_session_revoked" | "current_session_already_ended" | "all_sessions_revoked" | "all_sessions_already_ended"): Response {
    return new Response(JSON.stringify({ outcome, cookieClearing: "confirmed" }), {
        status: 200,
        headers: {
            ...JSON_RESPONSE_HEADERS,
            "Set-Cookie": cookieCodec.clear()
        }
    });
}

/** Error envelope plus a cleanup cookie clear; used when the session credential is absent or rejected. */
function clearWithError(cookieCodec: CookieCodec, code: AuthCoreErrorCode, correlationId: string): Response {
    const response = errorResponse(code, correlationId);
    const headers = new Headers(response.headers);
    headers.set("Set-Cookie", cookieCodec.clear());
    return new Response(response.body, { status: response.status, headers });
}

/** Closed token-free workflow body: { status: "succeeded", data } (client publicSuccess contract). */
function workflowResponse(
    outcome: Record<string, any>,
    correlationId: string,
    transform: (data: any) => unknown = (data) => data,
): Response {
    if (outcome.kind === "rejected") {
        return rejectionResponse(WORKFLOW_REJECTION[outcome.code ?? ""] ?? { status: 400, code: "invalid_input" }, correlationId);
    }
    if (isTransient(outcome)) return errorResponse("UPSTREAM_UNAVAILABLE", correlationId);
    if ((outcome.kind === "succeeded" || outcome.kind === "issued" || outcome.kind === "rotated") && "data" in outcome) {
        return responseData({ status: "succeeded", data: transform(outcome.data) });
    }
    return errorResponse("INTERNAL_FAILURE", correlationId);
}

/** Applies a fresh session cookie to an already-built workflow response (rotation side effects). */
function workflowWithCookie(cookieCodec: CookieCodec, response: Response, session: { refreshToken: string; remainingLifetimeSeconds: number }): Response {
    const headers = new Headers(response.headers);
    headers.set("Set-Cookie", cookieCodec.create(session.refreshToken, session.remainingLifetimeSeconds));
    return new Response(response.body, { status: response.status, headers });
}

function bearerAccessToken(request: Request): string | undefined {
    const header = request.headers.get("Authorization");
    if (header === null || header.includes(",")) return undefined;
    const match = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i.exec(header);
    const token = match?.[1];
    return token && token.length <= 8192 ? token : undefined;
}

function parseRouteBody(route: BrowserAuthRoute, raw: unknown): Record<string, unknown> {
    const spec = ROUTE_BODY_SPECS[route.suffix];
    if (spec === undefined) throw new CoreFailure("INVALID_REQUEST_BODY");
    if (raw === undefined || raw === null || raw === "") {
        if (spec.allowed.length === 0) return {};
        throw new CoreFailure("INVALID_REQUEST_BODY");
    }
    if (typeof raw !== "object" || Array.isArray(raw)) throw new CoreFailure("INVALID_REQUEST_BODY");
    const body = raw as Record<string, unknown>;
    for (const key of Object.keys(body)) {
        if (!spec.allowed.includes(key)) throw new CoreFailure("INVALID_REQUEST_BODY");
    }
    for (const key of spec.required) {
        if (!(key in body)) throw new CoreFailure("INVALID_REQUEST_BODY");
    }
    return body;
}

export function createWorkflowRouteHandler(
    config: ResolvedAuthCoreConfig,
    telemetry: SafeObserver,
    cookieCodec: CookieCodec
) {
    return async (route: BrowserAuthRoute, request: Request): Promise<Response> => {
        const correlationId = correlationIdFor(request, config);

        // Tombstone the legacy in-band credential header before body/cookie parsing or any RPC (Task 4.9).
        for (const headerName of LEGACY_CREDENTIAL_HEADERS) {
            if (request.headers.has(headerName)) {
                return clearWithError(cookieCodec, "REAUTHENTICATION_REQUIRED", correlationId);
            }
        }

        let body: Record<string, unknown>;
        try {
            body = parseRouteBody(route, request.method === "POST" ? await request.json() : undefined);
        } catch (error) {
            if (error instanceof CoreFailure) return errorResponse(error.code, correlationId);
            return errorResponse("INVALID_REQUEST_BODY", correlationId);
        }

        const cookieParse = cookieCodec.parse(request.headers.get("Cookie"));
        const currentRefreshToken = cookieParse.kind === "present" ? cookieParse.value : undefined;

        try {
            switch (route.suffix) {
                case "/login": {
                    const outcome = await config.sso.login({ correlationId, email: body.email, password: body.password, currentRefreshToken });
                    return sessionResponse(cookieCodec, outcome, correlationId, "login");
                }
                case "/signup": {
                    const outcome = await config.sso.signup({
                        correlationId, email: body.email, password: body.password,
                        organizationName: body.organizationName, role: body.role,
                        userMetadata: body.userMetadata, currentRefreshToken,
                    });
                    return sessionResponse(cookieCodec, outcome, correlationId, "signup");
                }
                case "/signup-member": {
                    const outcome = await config.sso.signupMember({
                        correlationId, email: body.email, password: body.password,
                        role: body.role, organizationId: body.organizationId,
                        userMetadata: body.userMetadata, currentRefreshToken,
                    });
                    return sessionResponse(cookieCodec, outcome, correlationId, "signup-member");
                }
                case "/session": {
                    if (!currentRefreshToken) return clearWithError(cookieCodec, "MISSING_CREDENTIALS", correlationId);
                    const outcome = await config.sso.refreshCurrentSession({ correlationId, refreshToken: currentRefreshToken, operation: "refresh_current_session" });
                    if (outcome.kind === "rotated" || outcome.kind === "overlap") {
                        return sessionResponse(cookieCodec, outcome, correlationId, "session");
                    }
                    if (outcome.kind === "rejected") {
                        return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId, { "Set-Cookie": cookieCodec.clear() });
                    }
                    if (isTransient(outcome)) return errorResponse("UPSTREAM_UNAVAILABLE", correlationId);
                    return clearWithError(cookieCodec, "INVALID_COOKIE", correlationId);
                }
                case "/session/organization": {
                    if (!currentRefreshToken) return clearWithError(cookieCodec, "MISSING_CREDENTIALS", correlationId);
                    const outcome = await config.sso.changeOrganization({ correlationId, refreshToken: currentRefreshToken, organizationId: body.organizationId });
                    if (outcome.kind === "rotated") {
                        return sessionResponse(cookieCodec, outcome, correlationId, "session-organization");
                    }
                    if (outcome.kind === "rejected") {
                        return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId, { "Set-Cookie": cookieCodec.clear() });
                    }
                    if (isTransient(outcome)) return errorResponse("UPSTREAM_UNAVAILABLE", correlationId);
                    return clearWithError(cookieCodec, "INVALID_COOKIE", correlationId);
                }
                case "/me": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.getIdentity({ correlationId, accessToken });
                    return workflowResponse(outcome, correlationId);
                }
                case "/organizations": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.listOrganizations({ correlationId, accessToken });
                    return workflowResponse(outcome, correlationId, (data) => ({
                        organizations: data.organizations.map((org: any) => ({
                            id: org.organizationId, name: org.name, slug: org.slug, roles: org.roles, active: org.active,
                        })),
                    }));
                }
                case "/logout/current": {
                    if (!currentRefreshToken) return clearSessionResponse(cookieCodec, "current_session_already_ended");
                    const outcome = await config.sso.logoutCurrentSession({ correlationId, refreshToken: currentRefreshToken, scope: "current" });
                    if (outcome.kind === "current_revoked") return clearSessionResponse(cookieCodec, "current_session_revoked");
                    if (outcome.kind === "current_already_ended") return clearSessionResponse(cookieCodec, "current_session_already_ended");
                    // Cancelled or transient: server revocation unconfirmed; never clear the cookie, never upgrade (Task 4.8).
                    return errorResponse("REVOCATION_UNCONFIRMED", correlationId);
                }
                case "/logout/all": {
                    if (!currentRefreshToken) return clearSessionResponse(cookieCodec, "all_sessions_already_ended");
                    const outcome = await config.sso.logoutAllSessions({ correlationId, refreshToken: currentRefreshToken, scope: "all" });
                    if (outcome.kind === "all_revoked") return clearSessionResponse(cookieCodec, "all_sessions_revoked");
                    if (outcome.kind === "all_already_ended") return clearSessionResponse(cookieCodec, "all_sessions_already_ended");
                    return errorResponse("REVOCATION_UNCONFIRMED", correlationId);
                }
                case "/password/forgot": {
                    const outcome = await config.sso.forgotPassword({ correlationId, email: body.email });
                    return workflowResponse(outcome, correlationId, (data) => ({
                        accepted: data.accepted, message: "Password recovery instructions were sent to the provided email address.",
                    }));
                }
                case "/password/reset": {
                    const outcome = await config.sso.resetPassword({ correlationId, resetToken: body.resetToken, password: body.password, currentRefreshToken });
                    if (outcome.kind === "issued" && outcome.session) {
                        return workflowWithCookie(cookieCodec, workflowResponse(outcome, correlationId), outcome.session);
                    }
                    return workflowResponse(outcome, correlationId);
                }
                case "/verification/request": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.requestVerification({ correlationId, accessToken });
                    return workflowResponse(outcome, correlationId);
                }
                case "/verification/complete": {
                    const outcome = await config.sso.verifyEmail({ correlationId, verificationToken: body.verificationToken, currentRefreshToken });
                    if (outcome.kind === "rotated" && outcome.session) {
                        return workflowWithCookie(cookieCodec, workflowResponse(outcome, correlationId), outcome.session);
                    }
                    return workflowResponse(outcome, correlationId);
                }
                case "/invite": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.createInvite({ correlationId, email: body.email, organizationId: body.organizationId, roles: body.roles, accessToken });
                    return workflowResponse(outcome, correlationId);
                }
                case "/invite/accept": {
                    const outcome = await config.sso.acceptInvite({ correlationId, invitationToken: body.invitationToken, password: body.password, currentRefreshToken });
                    if (outcome.kind === "issued" && outcome.session) {
                        return sessionResponse(cookieCodec, outcome, correlationId, "invite-accept");
                    }
                    return workflowResponse(outcome, correlationId);
                }
                case "/invite/cancel": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.cancelInvite({ correlationId, inviteId: body.inviteId, accessToken });
                    return workflowResponse(outcome, correlationId, (data) => ({ cancelled: data.cancelled }));
                }
                case "/invite/resend": {
                    const accessToken = bearerAccessToken(request);
                    if (accessToken === undefined) return rejectionResponse(DEFINITIVE_SESSION_REJECTION, correlationId);
                    const outcome = await config.sso.resendInvite({ correlationId, inviteId: body.inviteId, accessToken });
                    return workflowResponse(outcome, correlationId);
                }
                default:
                    return errorResponse("INTERNAL_FAILURE", correlationId);
            }
        } catch {
            return errorResponse("INTERNAL_FAILURE", correlationId);
        }
    };
}
