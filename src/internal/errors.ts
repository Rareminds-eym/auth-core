import type { AuthCoreErrorCode, AuthCoreErrorDescriptor } from "../types/public.js";
import { isValidCorrelationId } from "./correlation-format.js";

interface ErrorDefinition {
    readonly status: number;
    readonly retryable: boolean;
    readonly message: string;
    readonly processing?: "pre_handler";
}

export const ERROR_DEFINITIONS: Readonly<Record<AuthCoreErrorCode, ErrorDefinition>> = Object.freeze({
    REQUEST_VALIDATION_REJECTED: Object.freeze({ status: 403, retryable: false, message: "Request validation failed." }),
    MISSING_CREDENTIALS: Object.freeze({ status: 401, retryable: false, message: "Authentication credentials are required." }),
    INVALID_TOKEN: Object.freeze({ status: 401, retryable: false, message: "The access token is invalid." }),
    EXPIRED_TOKEN: Object.freeze({
        status: 401,
        retryable: false,
        message: "The access token has expired.",
        processing: "pre_handler",
    }),
    INACTIVE_MEMBERSHIP: Object.freeze({ status: 403, retryable: false, message: "Active membership is required." }),
    FORBIDDEN_ROLE: Object.freeze({ status: 403, retryable: false, message: "The required role is not available." }),
    FORBIDDEN_PRODUCT: Object.freeze({ status: 403, retryable: false, message: "The required product is not available." }),
    FORBIDDEN_FEATURE: Object.freeze({ status: 403, retryable: false, message: "The required feature is not available." }),
    INVALID_COOKIE: Object.freeze({ status: 401, retryable: false, message: "The session credential is invalid." }),
    REFRESH_REJECTED: Object.freeze({ status: 401, retryable: false, message: "The session could not be refreshed." }),
    REVOCATION_UNCONFIRMED: Object.freeze({ status: 503, retryable: true, message: "Session revocation could not be confirmed." }),
    INVALID_REQUEST_BODY: Object.freeze({ status: 400, retryable: false, message: "The request body is invalid." }),
    NOT_FOUND: Object.freeze({ status: 404, retryable: false, message: "The requested resource was not found." }),
    CONFLICT: Object.freeze({ status: 409, retryable: false, message: "The request conflicts with the current state." }),
    REAUTHENTICATION_REQUIRED: Object.freeze({ status: 401, retryable: false, message: "Legacy credentials must be cleared." }),
    INVALID_RESPONSE: Object.freeze({ status: 502, retryable: false, message: "An invalid upstream response was received." }),
    UPSTREAM_UNAVAILABLE: Object.freeze({ status: 503, retryable: true, message: "The authentication service is unavailable." }),
    INTERNAL_FAILURE: Object.freeze({ status: 500, retryable: false, message: "An internal authentication error occurred." }),
});

export class CoreFailure extends Error {
    readonly code: AuthCoreErrorCode;

    constructor(code: AuthCoreErrorCode) {
        super(ERROR_DEFINITIONS[code].message);
        this.name = "CoreFailure";
        this.code = code;
    }
}
export function describeError(
    code: AuthCoreErrorCode,
    correlationId?: string,
): AuthCoreErrorDescriptor {
    const definition = ERROR_DEFINITIONS[code];
    return Object.freeze({
        code,
        status: definition.status,
        retryable: definition.retryable,
        message: definition.message,
        ...(definition.processing === undefined ? {} : { processing: definition.processing }),
        ...(isValidCorrelationId(correlationId) ? { correlationId } : {}),
    });
}

/** Serializes only allowlisted static fields; exception details never enter the body. */
export function errorResponse(code: AuthCoreErrorCode, correlationId?: string): Response {
    const error = describeError(code, correlationId);
    return new Response(JSON.stringify({ error }), {
        status: error.status,
        headers: {
            "Cache-Control": "no-store, no-cache",
            "Pragma": "no-cache",
            "Content-Type": "application/json; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
        },
    });
}

export function classifyFailure(error: unknown): AuthCoreErrorCode {
    return error instanceof CoreFailure ? error.code : "INTERNAL_FAILURE";
}
