export function extractToken(request: Request): string | null {
  const authHeader = request.headers.get("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;

  return authHeader.slice(7);
}
