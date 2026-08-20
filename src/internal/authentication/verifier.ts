import type { JWSHeaderParameters, JWTPayload } from "jose";
import { decodeProtectedHeader, errors, jwtVerify } from "jose";
import type { MembershipStatus, VerifiedAuthUser } from "../../types/public.js";
import type { ResolvedAuthCoreConfig } from "../config.js";
import { createVerifiedContext } from "../context.js";
import { CoreFailure } from "../errors.js";
import { JwksKeyStore } from "./jwks-key-store.js";
import type { SafeObserver } from "../telemetry/observability.js";

const CLOCK_TOLERANCE_SECONDS = 30;
const REQUIRED_CLAIMS = Object.freeze([
    "exp",
    "iat",
    "sub",
    "email",
    "org_id",
    "roles",
    "products",
    "membership_status",
    "is_email_verified",
] as const);
const MEMBERSHIP_STATUSES = new Set<MembershipStatus>([
    "active",
    "inactive",
    "suspended",
    "expired",
]);

function invalidToken(): never {
    throw new CoreFailure("INVALID_TOKEN");
}

function assertProtectedHeader(header: JWSHeaderParameters): string {
    if (
        header.alg !== "RS256" ||
        typeof header.kid !== "string" ||
        header.kid.length === 0 ||
        header.kid !== header.kid.trim() ||
        header.typ !== "JWT" ||
        header.crit !== undefined
    ) {
        invalidToken();
    }
    return header.kid;
}

function assertExactClaims(
    payload: JWTPayload,
    config: ResolvedAuthCoreConfig,
    nowSeconds: number,
): void {
    const { exp, iat, nbf } = payload;
    if (
        payload.iss !== config.issuer || payload.aud !== config.audience ||
        typeof exp !== "number" || !Number.isFinite(exp) ||
        typeof iat !== "number" || !Number.isFinite(iat) ||
        (nbf !== undefined && (typeof nbf !== "number" || !Number.isFinite(nbf))) ||
        iat > nowSeconds ||
        (nbf !== undefined && nbf > nowSeconds + CLOCK_TOLERANCE_SECONDS)
    ) {
        invalidToken();
    }
    // Expiration remains strict; the configured skew allowance applies only to optional nbf.
    if (exp <= nowSeconds) {
        throw new CoreFailure("EXPIRED_TOKEN");
    }
    if (exp <= iat || (nbf !== undefined && exp <= nbf)) {
        invalidToken();
    }
}

function stringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function verifiedUser(payload: Record<string, unknown>): VerifiedAuthUser {
    const status = payload.membership_status;
    if (
        typeof payload.sub !== "string" || payload.sub.length === 0 ||
        typeof payload.email !== "string" || payload.email.length === 0 ||
        typeof payload.org_id !== "string" || payload.org_id.length === 0 ||
        !stringArray(payload.roles) || !stringArray(payload.products) ||
        typeof status !== "string" || !MEMBERSHIP_STATUSES.has(status as MembershipStatus) ||
        typeof payload.is_email_verified !== "boolean" ||
        (payload.user_metadata !== undefined &&
            (payload.user_metadata === null || typeof payload.user_metadata !== "object" || Array.isArray(payload.user_metadata)))
    ) {
        throw new CoreFailure("INVALID_TOKEN");
    }

    return {
        sub: payload.sub,
        email: payload.email,
        org_id: payload.org_id,
        roles: payload.roles,
        products: payload.products,
        membership_status: status as MembershipStatus,
        is_email_verified: payload.is_email_verified,
        ...(payload.user_metadata === undefined
            ? {}
            : { user_metadata: payload.user_metadata as Record<string, unknown> }),
    };
}
/** Creates one verifier with an authoritative key lifecycle owned by this Auth instance. */
export function createVerifier(config: ResolvedAuthCoreConfig, telemetry: SafeObserver) {
    const keys = new JwksKeyStore(config, telemetry);
    return async (token: string, correlationId: string) => {
        let kid: string;
        try {
            // Reject untrusted routing metadata before it can select a key or trigger an RPC.
            kid = assertProtectedHeader(decodeProtectedHeader(token));
        } catch (error) {
            if (error instanceof CoreFailure) throw error;
            throw new CoreFailure("INVALID_TOKEN");
        }

        const keySet = await keys.keySetFor(kid, correlationId);
        const currentDate = new Date();
        try {
            const result = await jwtVerify(token, keySet, {
                issuer: config.issuer,
                audience: config.audience,
                algorithms: ["RS256"],
                requiredClaims: [...REQUIRED_CLAIMS],
                clockTolerance: CLOCK_TOLERANCE_SECONDS,
                currentDate,
            });
            assertProtectedHeader(result.protectedHeader);
            assertExactClaims(result.payload, config, currentDate.getTime() / 1000);
            return createVerifiedContext(
                verifiedUser(result.payload as Record<string, unknown>),
                correlationId,
            );
        } catch (error) {
            if (error instanceof CoreFailure) throw error;
            if (error instanceof errors.JWTExpired) {
                throw new CoreFailure("EXPIRED_TOKEN");
            }
            throw new CoreFailure("INVALID_TOKEN");
        }
    };
}
