/**
 * Extracts the refresh_token from the Cookie header.
 * Handles whitespace and avoids partial name matches.
 */
export function getRefreshToken(request: Request): string | null {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  const pairs = cookie.split(";");
  for (const pair of pairs) {
    const [name, ...rest] = pair.split("=");
    if (name.trim() === "refresh_token") {
      const value = rest.join("=").trim(); // rejoin in case value contains '='
      return value ? decodeURIComponent(value) : null;
    }
  }

  return null;
}
