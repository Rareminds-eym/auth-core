import { errors } from "jose";
import { verifyJWT } from "../jwt/verifyJWT.js";
import { refreshAccessToken } from "../session/refreshAccessToken.js";
import type { AuthenticatedContext, ContextWithUser } from "../types/auth.js";
import { extractToken } from "../utils/extractToken.js";
import { getRefreshToken } from "../utils/getRefreshToken.js";
import { jsonError } from "../utils/jsonError.js";

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
      // Forward CF-Connecting-IP and User-Agent for audit/session metadata (Requirement 16.1, 16.2)
      const ip = context.request.headers.get("CF-Connecting-IP") ?? undefined;
      const ua = context.request.headers.get("User-Agent") ?? undefined;
      ({ access_token, setCookieHeaders } = await refreshAccessToken(refreshToken, ip, ua));
    } catch (err) {
      return jsonError(
        err instanceof Error ? `Token refresh failed: ${err.message}` : "Session expired",
        401
      );
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
    // gets the rotated refresh_token cookie.
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
