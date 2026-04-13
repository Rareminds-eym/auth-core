import { errors } from "jose";
import { verifyJWT } from "../jwt/verifyJWT.js";
import { extractToken } from "../utils/extractToken.js";
import { getRefreshToken } from "../utils/getRefreshToken.js";
import { jsonError } from "../utils/jsonError.js";
import { refreshAccessToken } from "../session/refreshAccessToken.js";
import type { ContextWithUser, AuthenticatedContext } from "../types/auth.js";

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

    // 3. Get new access token (includes Set-Cookie headers from the worker)
    let access_token: string;
    let setCookieHeaders: string[];
    try {
      ({ access_token, setCookieHeaders } = await refreshAccessToken(refreshToken));
    } catch {
      return jsonError("Token refresh failed", 502);
    }

    // 4. Verify the new access token
    try {
      const user = await verifyJWT(access_token);

      if (user.membership_status !== "active") {
        return jsonError("Inactive membership", 403);
      }

      context.data.user = user;
    } catch {
      return jsonError("Refreshed token is invalid", 500);
    }

    // 5. Run handler and attach new token + forwarded cookies to response
    const response = await handler(context as AuthenticatedContext);
    const newHeaders = new Headers(response.headers);
    newHeaders.set("X-Access-Token", access_token);

    // Forward Set-Cookie headers from the SSO worker so the browser
    // gets the rotated access_token + refresh_token cookies.
    for (const cookie of setCookieHeaders) {
      newHeaders.append("Set-Cookie", cookie);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };
}
