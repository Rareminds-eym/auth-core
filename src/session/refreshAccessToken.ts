import { getConfig } from "../config.js";

const COOKIE_OPTIONS = "HttpOnly; Secure; Path=/; SameSite=None";
const ACCESS_TOKEN_MAX_AGE = 900;
const REFRESH_MAX_AGE = 30 * 24 * 60 * 60;

export async function refreshAccessToken(
  refreshToken: string,
  ip?: string,
  ua?: string
): Promise<{ access_token: string; setCookieHeaders: string[] }> {
  const { ssoRpc } = getConfig();

  const { access_token, refresh_token } = await ssoRpc.refreshSession(refreshToken, ip, ua);
  
  const setCookieHeaders = [
    `access_token=${access_token}; ${COOKIE_OPTIONS}; Max-Age=${ACCESS_TOKEN_MAX_AGE}`,
    `refresh_token=${refresh_token}; ${COOKIE_OPTIONS}; Max-Age=${REFRESH_MAX_AGE}`
  ];
  
  return { access_token, setCookieHeaders };
}
