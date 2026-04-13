/**
 * Extracts the refresh_token from the Cookie header.
 * Returns the raw value without URI decoding — matches the SSO worker's
 * getCookie implementation which also returns raw values.
 * The worker hashes the raw token, so we must not transform it.
 */
export function getRefreshToken(request: Request): string | null {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  for (const part of cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith("refresh_token=")) {
      const idx = trimmed.indexOf("=");
      if (idx === -1) return null;
      const value = trimmed.slice(idx + 1).trim();
      return value || null;
    }
  }

  return null;
}
