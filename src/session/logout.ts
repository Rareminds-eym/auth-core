import { getConfig } from "../config.js";

/**
 * Revoke the current session by calling the SSO worker via True RPC.
 * Accepts the refresh token from the cookie (server-side extraction).
 *
 * Returns the Set-Cookie headers from the worker (clearing cookies)
 * so the caller can forward them to the browser.
 */
const COOKIE_OPTIONS = "HttpOnly; Secure; Path=/; SameSite=None";

export async function logout(
  refreshToken: string,
  ip?: string,
  ua?: string
): Promise<{ success: boolean; setCookieHeaders: string[] }> {
  const { ssoRpc } = getConfig();

  const res = await ssoRpc.logoutSession(refreshToken, ip, ua);
  
  const setCookieHeaders = [
    `access_token=; Max-Age=0; ${COOKIE_OPTIONS}`,
    `refresh_token=; Max-Age=0; ${COOKIE_OPTIONS}`
  ];
  
  return { success: res.success, setCookieHeaders };
}
