import { getConfig } from "../config";
import { fetchWithTimeout } from "../utils/fetchWithTimeout";

export async function refreshAccessToken(
  refreshToken: string
): Promise<{ access_token: string }> {
  const { ssoDomain } = getConfig();

  const res = await fetchWithTimeout(`${ssoDomain}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!res.ok) {
    throw new Error(`Refresh failed: ${res.status}`);
  }

  const body = await res.json();

  if (!body || typeof body.access_token !== "string") {
    throw new Error("Invalid refresh response from SSO");
  }

  return { access_token: body.access_token };
}
