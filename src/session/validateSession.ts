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

  const body = await res.json();

  if (!body || typeof body.valid !== "boolean") {
    return { valid: false };
  }

  return body as SessionValidationResponse;
}
