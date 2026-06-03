import type { SessionValidationResponse } from "../types/auth.js";
import { getConfig } from "../config.js";

/**
 * Validates the current session by calling the SSO worker via True RPC.
 * Requires a valid access token.
 *
 * Note: validateSessionBeforeRefresh defaults to false because the
 * refresh endpoint already rejects revoked/expired sessions.
 * This function is available for explicit session checks if needed.
 */
export async function validateSession(
  accessToken: string
): Promise<SessionValidationResponse> {
  const { ssoRpc } = getConfig();

  try {
    const body = await ssoRpc.getMe(accessToken);
    if (
      !body ||
      typeof body !== "object" ||
      typeof (body as Record<string, unknown>).sub !== "string"
    ) {
      return { valid: false };
    }
    return { valid: true, user: body as unknown as SessionValidationResponse["user"] };
  } catch {
    return { valid: false };
  }
}
