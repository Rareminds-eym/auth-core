import type { ContextWithUser } from "../types/auth.js";
import { jsonError } from "../utils/jsonError.js";

/**
 * Requires the authenticated user to have access to at least one of the specified products.
 */
export function requireProduct(
  product: string | string[],
  handler: (context: ContextWithUser) => Promise<Response> | Response
) {
  const products = Array.isArray(product) ? product : [product];

  return async (context: ContextWithUser): Promise<Response> => {
    const user = context.data.user;

    if (!user || !user.products || !products.some((p) => user.products.includes(p))) {
      return jsonError("Forbidden: product access denied", 403);
    }

    return handler(context);
  };
}
