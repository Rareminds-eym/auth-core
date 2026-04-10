import { errors } from "jose";
import { verifyJWT } from "../jwt/verifyJWT";
import { extractToken } from "../utils/extractToken";
import { getRefreshToken } from "../utils/getRefreshToken";
import { jsonError } from "../utils/jsonError";
import { refreshAccessToken } from "../session/refreshAccessToken";
import { validateSession } from "../session/validateSession";
import { getConfig } from "../config";
import type { ContextWithUser, AuthenticatedContext } from "../types/auth";

export function withAuth(
  handler: (context: AuthenticatedContext) => Promise<Response> | Response
) {
  return async (context: ContextWithUser): Promise<Response> => {
    const token = extractToken(context.request);

    // 1. Try access token
    if (token) {
      try {
        const user = await verifyJWT(token);

        if (user.membership_status !== "active") {
          return jsonError("Inactive membership", 403);
        }

        context.data.user = user;
        return handler(context as AuthenticatedContext);
      } catch (err) {
        // Only fall through to refresh if the token is expired.
        // Tampered, wrong issuer/audience, or otherwise invalid tokens → 401 immediately.
        if (!(err instanceof errors.JWTExpired)) {
          return jsonError("Invalid token", 401);
        }
      }
    }

    // 2. Fallback to refresh token
    const refreshToken = getRefreshToken(context.request);
    if (!refreshToken) {
      return jsonError("Unauthorized: no valid token or refresh token", 401);
    }

    // 3. Optionally validate session is still active in SSO DB
    const { validateSessionBeforeRefresh } = getConfig();
    if (validateSessionBeforeRefresh) {
      try {
        const session = await validateSession(refreshToken);
        if (!session.valid) {
          return jsonError("Session expired or revoked", 401);
        }
      } catch {
        return jsonError("Session validation failed", 502);
      }
    }

    // 4. Get new access token
    let access_token: string;
    try {
      ({ access_token } = await refreshAccessToken(refreshToken));
    } catch {
      return jsonError("Token refresh failed", 502);
    }

    // 5. Verify the new access token
    try {
      const user = await verifyJWT(access_token);

      if (user.membership_status !== "active") {
        return jsonError("Inactive membership", 403);
      }

      context.data.user = user;
    } catch {
      return jsonError("Refreshed token is invalid", 500);
    }

    // 6. Run handler and attach new token to response (safe for immutable responses)
    const response = await handler(context as AuthenticatedContext);
    const newHeaders = new Headers(response.headers);
    newHeaders.set("X-Access-Token", access_token);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };
}
