import type { ContextWithUser } from "../types/auth.js";
import { jsonError } from "../utils/jsonError.js";

/**
 * Requires that one or more features be available for the current request.
 *
 * This guard is intentionally GENERIC: `auth-core` does not know anything about
 * subscriptions, plans, or entitlements. The concrete decision is delegated to
 * the `check` callback supplied by the consuming application, which receives the
 * request context and the normalized list of feature keys and returns whether
 * access should be granted.
 *
 * Composes the same way as `requireRole` / `requireProduct`, e.g.:
 *
 * ```ts
 * withAuth(requireFeature("advanced-reports", appCheck, handler));
 * ```
 *
 * @param featureKey A single feature key or a list of feature keys to require.
 * @param check Application-supplied predicate that decides whether the feature(s)
 *   are available for the given context. Receives the normalized `keys` array.
 * @param handler The handler to invoke when the feature check passes.
 * @returns A handler that responds with 403 when the check fails, otherwise the
 *   wrapped handler's response.
 */
export function requireFeature(
    featureKey: string | string[],
    check: (context: ContextWithUser, keys: string[]) => Promise<boolean>,
    handler: (context: ContextWithUser) => Promise<Response> | Response
) {
    const keys = Array.isArray(featureKey) ? featureKey : [featureKey];

    return async (context: ContextWithUser): Promise<Response> => {
        if (!(await check(context, keys))) {
            return jsonError("Forbidden: feature not available", 403);
        }

        return handler(context);
    };
}
