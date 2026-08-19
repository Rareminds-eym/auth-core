import { extractBearer } from "./internal/bearer.js";
import { dispatchBrowserAuthRequest } from "./internal/browser-route-guard.js";
import { resolveConfig } from "./internal/config.js";
import { correlationIdFor } from "./internal/correlation.js";
import { classifyFailure, CoreFailure, errorResponse } from "./internal/errors.js";
import { SafeObserver } from "./internal/observability.js";
import { createVerifier } from "./internal/verifier.js";
import { createCookieCodec } from "./internal/cookieCodec.js";
import { createWorkflowRouteHandler } from "./internal/browser-workflow-routes.js";
import type {
    Auth,
    AuthCoreConfig,
    AuthCoreErrorCode,
    AuthenticatedHandler,
    FeatureCheck,
    VerifiedAuthContext
} from "./types/public.js";

type AuthorizationDenialCode =
    | "INACTIVE_MEMBERSHIP"
    | "FORBIDDEN_ROLE"
    | "FORBIDDEN_PRODUCT"
    | "FORBIDDEN_FEATURE";

function allowedValues(values: readonly string[], field: string): ReadonlySet<string> {
    if (
        !Array.isArray(values) || values.length === 0 ||
        values.some((value) => typeof value !== "string" || value.length === 0 || value !== value.trim())
    ) {
        throw new TypeError(`${field} must contain normalized non-empty strings.`);
    }
    const allowed = new Set(values);
    if (allowed.size !== values.length) {
        throw new TypeError(`${field} must not contain duplicates.`);
    }
    return allowed;
}

function verificationReason(code: AuthCoreErrorCode) {
    switch (code) {
        case "MISSING_CREDENTIALS":
        case "INVALID_TOKEN":
        case "EXPIRED_TOKEN":
        case "INVALID_RESPONSE":
        case "UPSTREAM_UNAVAILABLE":
        case "INTERNAL_FAILURE":
            return code;
        default:
            return "INTERNAL_FAILURE" as const;
    }
}

function invokeHandler(
    handler: AuthenticatedHandler,
    request: Request,
    context: VerifiedAuthContext,
): Promise<Response> {
    return Promise.resolve(handler(request, context));
}

/** Creates one immutable Auth Core instance with no process-global verifier state. */
export function createAuth(config: AuthCoreConfig): Auth {
    const resolved = resolveConfig(config);
    const telemetry = new SafeObserver(resolved.observer);
    const verify = createVerifier(resolved, telemetry);
    const cookieCodec = createCookieCodec(resolved.cookieMaxAgeSeconds);
    const workflowHandler = createWorkflowRouteHandler(resolved, telemetry, cookieCodec);
    const verifiedRequests = new WeakMap<VerifiedAuthContext, Request>();

    const guarded = (
        code: AuthorizationDenialCode,
        predicate: (request: Request, context: VerifiedAuthContext) => Promise<boolean> | boolean,
        handler: AuthenticatedHandler,
    ): AuthenticatedHandler => async (request, context) => {
        // Structural lookalikes and contexts from prior/other requests are not authentication evidence.
        if (verifiedRequests.get(context) !== request) {
            return errorResponse("INVALID_TOKEN");
        }
        let permitted: boolean;
        try {
            // Policy callbacks must explicitly approve; arbitrary truthy values fail closed at runtime.
            permitted = await predicate(request, context) === true;
        } catch {
            telemetry.event("authorization_rejected", context.correlationId, { outcome: "rejected", reason: "INTERNAL_FAILURE" });
            telemetry.counter("auth.authorization.denial.total", context.correlationId, { outcome: "rejected", reason: "INTERNAL_FAILURE" });
            return errorResponse("INTERNAL_FAILURE", context.correlationId);
        }
        if (!permitted) {
            telemetry.event("authorization_rejected", context.correlationId, { outcome: "rejected", reason: code });
            telemetry.counter("auth.authorization.denial.total", context.correlationId, { outcome: "rejected", reason: code });
            return errorResponse(code, context.correlationId);
        }
        // Handler failures belong to authenticated request processing, not authorization policy evaluation.
        return invokeHandler(handler, request, context);
    };

    const authenticate = (handler: AuthenticatedHandler) => async (request: Request) => {
        let correlationId: string | undefined;
        const startedAt = Date.now();
        try {
            correlationId = correlationIdFor(request, resolved);
            const bearer = extractBearer(request);
            if (bearer.ok === false) throw new CoreFailure(bearer.code);
            const context = await verify(bearer.token, correlationId);
            telemetry.histogram("auth.jwt.verification.duration", correlationId, Date.now() - startedAt, { outcome: "succeeded" });
            verifiedRequests.set(context, request);
            try {
                return await invokeHandler(handler, request, context);
            } finally {
                verifiedRequests.delete(context);
            }
        } catch (error) {
            const code = classifyFailure(error);
            if (correlationId !== undefined) {
                const details = { outcome: "rejected" as const, reason: verificationReason(code) };
                telemetry.event("jwt_verification_rejected", correlationId, { ...details, durationMs: Date.now() - startedAt });
                telemetry.counter("auth.jwt.verification.failure.total", correlationId, details);
                telemetry.histogram("auth.jwt.verification.duration", correlationId, Date.now() - startedAt, details);
            }
            return errorResponse(code, correlationId);
        }
    };

    const requireActiveMembership = (handler: AuthenticatedHandler) => guarded(
        "INACTIVE_MEMBERSHIP",
        (_request, context) => context.user.membership_status === "active",
        handler,
    );
    const requireRole = (allowed: readonly string[], handler: AuthenticatedHandler) => {
        const roles = allowedValues(allowed, "allowed roles");
        return guarded(
            "FORBIDDEN_ROLE",
            (_request, context) => context.user.roles.some((role) => roles.has(role)),
            handler,
        );
    };

    const requireProduct = (allowed: readonly string[], handler: AuthenticatedHandler) => {
        const products = allowedValues(allowed, "allowed products");
        return guarded(
            "FORBIDDEN_PRODUCT",
            (_request, context) => context.user.products.some((product) => products.has(product)),
            handler,
        );
    };

    const requireFeature = (check: FeatureCheck, handler: AuthenticatedHandler) => {
        if (typeof check !== "function") {
            throw new TypeError("Feature check must be a function.");
        }
        return guarded("FORBIDDEN_FEATURE", check, handler);
    };

    const handleBrowserRequest = async (request: Request) => {
        try {
            const dispatched = await dispatchBrowserAuthRequest(request, resolved, workflowHandler);
            if (dispatched.rejectionReason !== undefined) {
                console.log("[AuthCore Guard Rejection Reason]:", dispatched.rejectionReason);
                // Rejections intentionally avoid caller hooks so malformed input always receives the static 403.
                const details = { outcome: "rejected" as const, reason: dispatched.rejectionReason };
                telemetry.event("csrf_rejected", "browser-request-rejected", details);
                telemetry.counter("auth.csrf.rejection.total", "browser-request-rejected", details);
            }
            return dispatched.response;
        } catch {
            return errorResponse("INTERNAL_FAILURE");
        }
    };

    return Object.freeze({
        authenticate,
        requireActiveMembership,
        requireRole,
        requireProduct,
        requireFeature,
        handleBrowserRequest,
    });
}
