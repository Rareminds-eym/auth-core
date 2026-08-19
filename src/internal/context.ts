import type { VerifiedAuthContext, VerifiedAuthUser } from "../types/public.js";

function cloneAndFreeze(value: unknown): unknown {
    if (Array.isArray(value)) {
        return Object.freeze(value.map(cloneAndFreeze));
    }
    if (value !== null && typeof value === "object") {
        const clone: Record<string, unknown> = {};
        for (const [key, child] of Object.entries(value)) {
            // defineProperty preserves hostile JSON keys such as "__proto__" as data.
            Object.defineProperty(clone, key, {
                configurable: false,
                enumerable: true,
                writable: false,
                value: cloneAndFreeze(child),
            });
        }
        return Object.freeze(clone);
    }
    return value;
}

/** Detaches verified claims from JOSE payload storage before publication. */
export function createVerifiedContext(
    user: VerifiedAuthUser,
    correlationId: string,
): VerifiedAuthContext {
    const immutableUser: VerifiedAuthUser = Object.freeze({
        sub: user.sub,
        email: user.email,
        org_id: user.org_id,
        roles: Object.freeze([...user.roles]),
        products: Object.freeze([...user.products]),
        membership_status: user.membership_status,
        is_email_verified: user.is_email_verified,
        ...(user.user_metadata === undefined
            ? {}
            : { user_metadata: cloneAndFreeze(user.user_metadata) as Readonly<Record<string, unknown>> }),
    });

    return Object.freeze({
        user: immutableUser,
        verification: "verified" as const,
        correlationId,
    });
}
