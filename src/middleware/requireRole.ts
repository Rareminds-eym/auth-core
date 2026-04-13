import type { ContextWithUser } from "../types/auth.js";
import { jsonError } from "../utils/jsonError.js";

/**
 * Requires the authenticated user to have at least one of the specified roles.
 */
export function requireRole(
  role: string | string[],
  handler: (context: ContextWithUser) => Promise<Response> | Response
) {
  const roles = Array.isArray(role) ? role : [role];

  return async (context: ContextWithUser): Promise<Response> => {
    const user = context.data.user;

    if (!user || !user.roles || !roles.some((r) => user.roles.includes(r))) {
      return jsonError("Forbidden: insufficient role", 403);
    }

    return handler(context);
  };
}
