import { getConfig } from "../config";
import { fetchWithTimeout } from "../utils/fetchWithTimeout";

export async function refreshAccessToken(
  refreshToken: string
): Promise<{ access_token: string; setCookieHeaders: string[] }> {
  const { ssoDomain } = getConfig();

  const res = await fetchWithTimeout(`${ssoDomain}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!res.ok) {
    throw new Error(`Refresh failed: ${res.status}`);
  }

  // Capture Set-Cookie headers so callers can forward them to the browser.
  // The worker sends rotated access_token + refresh_token cookies.
  const setCookieHeaders: string[] = [];
  res.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") {
      setCookieHeaders.push(value);
    }
  });

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new Error("Invalid JSON in refresh response from SSO");
  }

  if (
    !body ||
    typeof body !== "object" ||
    typeof (body as Record<string, unknown>).access_token !== "string"
  ) {
    throw new Error("Invalid refresh response from SSO");
  }

  return {
    access_token: (body as Record<string, unknown>).access_token as string,
    setCookieHeaders,
  };
}
