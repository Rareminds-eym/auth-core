import { getConfig } from "../config.js";
import { fetchWithTimeout } from "../utils/fetchWithTimeout.js";

export async function refreshAccessToken(
  refreshToken: string
): Promise<{ access_token: string; setCookieHeaders: string[] }> {
  const { ssoDomain } = getConfig();
  const maxRetries = 1;
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const res = await fetchWithTimeout(`${ssoDomain}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!res.ok) {
        // 4xx errors are non-retryable (invalid/expired refresh token)
        if (res.status >= 400 && res.status < 500) {
          throw new Error(`Refresh failed: ${res.status}`);
        }
        // 5xx errors: retry on last attempt only
        if (attempt < maxRetries) {
          lastError = new Error(`Refresh failed: ${res.status}`);
          continue;
        }
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
    } catch (err) {
      if (attempt < maxRetries) {
        // Exponential backoff: 500ms * 2^attempt
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
        continue;
      }
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError || new Error("Token refresh failed");
}
