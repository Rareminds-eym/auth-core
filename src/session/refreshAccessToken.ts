import { getConfig } from "../config.js";

const COOKIE_OPTIONS = "HttpOnly; Secure; Path=/; SameSite=None";
const REFRESH_MAX_AGE = 30 * 24 * 60 * 60;

export async function refreshAccessToken(
  refreshToken: string,
  ip?: string,
  ua?: string
): Promise<{ access_token: string; setCookieHeaders: string[] }> {
  const { ssoRpc } = getConfig();

  const { access_token, refresh_token } = await ssoRpc.refreshSession(refreshToken, ip, ua);

  // Return ONLY refresh_token cookie (Requirement 9.3).
  // Access token is delivered via X-Access-Token header (set by withAuth) and JSON body.
  // The legacy access_token cookie was removed per the cookie module consolidation.
  const config = getConfig();
  const domain = config.refreshCookieDomain ? `; Domain=${config.refreshCookieDomain}` : "";
  const setCookieHeaders = [
    `refresh_token=${refresh_token}; ${COOKIE_OPTIONS}${domain}; Max-Age=${REFRESH_MAX_AGE}`
  ];

  return { access_token, setCookieHeaders };
}
