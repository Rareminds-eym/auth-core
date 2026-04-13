/** Maximum reasonable JWT length (8 KB). Anything longer is rejected early. */
const MAX_TOKEN_LENGTH = 8192;

/**
 * Extract access token from a request.
 * Checks Authorization header first, then falls back to the access_token cookie.
 * Mirrors the SSO worker's extraction logic.
 */
export function extractToken(request: Request): string | null {
  // 1. Authorization header (preferred — explicit, works everywhere)
  const authHeader = request.headers.get("Authorization");
  if (authHeader) {
    if (!authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.slice(7);
    if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;
    return token;
  }

  // 2. Cookie fallback (browser clients where the worker sets HttpOnly cookies)
  return getCookieValue(request, "access_token");
}

/**
 * Parse a specific cookie value from the Cookie header.
 * Matches the SSO worker's getCookie implementation exactly.
 */
function getCookieValue(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;

  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) {
      const idx = trimmed.indexOf("=");
      if (idx === -1) return null;
      const value = trimmed.slice(idx + 1).trim();
      if (!value || value.length > MAX_TOKEN_LENGTH) return null;
      return value;
    }
  }
  return null;
}
