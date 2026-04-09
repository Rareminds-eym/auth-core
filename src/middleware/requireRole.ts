import type { ContextWithUser } from "../types/auth";

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
      return new Response(JSON.stringify({ error: "Forbidden: insufficient role" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    return handler(context);
  };
}
