import { getConfig } from "../config";
import { fetchWithTimeout } from "../utils/fetchWithTimeout";

/**
 * Revoke the current session by calling POST /auth/logout on the SSO worker.
 * Accepts the refresh token from the cookie (server-side extraction).
 *
 * Returns the Set-Cookie headers from the worker (clearing cookies)
 * so the caller can forward them to the browser.
 */
export async function logout(
  refreshToken: string
): Promise<{ success: boolean; setCookieHeaders: string[] }> {
  const { ssoDomain } = getConfig();

  const res = await fetchWithTimeout(`${ssoDomain}/auth/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  const setCookieHeaders: string[] = [];
  res.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") {
      setCookieHeaders.push(value);
    }
  });

  // Logout is best-effort — even if the worker returns an error,
  // the caller should still clear local state.
  return { success: res.ok, setCookieHeaders };
}
