import type { SessionValidationResponse } from "../types/auth.js";
import { getConfig } from "../config.js";
import { fetchWithTimeout } from "../utils/fetchWithTimeout.js";

/**
 * Validates the current session by calling GET /auth/me on the SSO worker.
 * Requires a valid access token (passed as Bearer header).
 *
 * Note: validateSessionBeforeRefresh defaults to false because the
 * refresh endpoint already rejects revoked/expired sessions.
 * This function is available for explicit session checks if needed.
 */
export async function validateSession(
  accessToken: string
): Promise<SessionValidationResponse> {
  const { ssoDomain } = getConfig();

  const res = await fetchWithTimeout(`${ssoDomain}/auth/me`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!res.ok) return { valid: false };

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { valid: false };
  }

  if (
    !body ||
    typeof body !== "object" ||
    typeof (body as Record<string, unknown>).sub !== "string"
  ) {
    return { valid: false };
  }

  return { valid: true, user: body as SessionValidationResponse["user"] };
}
