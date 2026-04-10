import type { SessionValidationResponse } from "../types/auth";
import { getConfig } from "../config";
import { fetchWithTimeout } from "../utils/fetchWithTimeout";

export async function validateSession(
  refreshToken: string
): Promise<SessionValidationResponse> {
  const { ssoDomain } = getConfig();

  const res = await fetchWithTimeout(`${ssoDomain}/auth/validate-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!res.ok) return { valid: false };

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { valid: false };
  }

  if (!body || typeof body !== "object" || typeof (body as Record<string, unknown>).valid !== "boolean") {
    return { valid: false };
  }

  return body as SessionValidationResponse;
}
