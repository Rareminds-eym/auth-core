/** Maximum reasonable JWT length (8 KB). Anything longer is rejected early. */
const MAX_TOKEN_LENGTH = 8192;

export function extractToken(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);

  // Reject obviously oversized tokens before triggering a JWKS fetch
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;

  return token;
}
