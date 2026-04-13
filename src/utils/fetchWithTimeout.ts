import { getConfig } from "../config.js";

/**
 * Fetch wrapper with configurable timeout via AbortController.
 * Respects any caller-provided signal — aborts if either fires.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit
): Promise<Response> {
  const { ssoTimeoutMs } = getConfig();
  const controller = new AbortController();

  // If caller's signal is already aborted, abort immediately
  if (init.signal?.aborted) {
    controller.abort(init.signal.reason);
  }

  const timeout = setTimeout(
    () => controller.abort(new Error(`SSO request timed out after ${ssoTimeoutMs}ms: ${url}`)),
    ssoTimeoutMs
  );

  // If caller passed their own signal, abort ours when theirs fires
  if (init.signal && !init.signal.aborted) {
    init.signal.addEventListener("abort", () => controller.abort(init.signal!.reason), {
      once: true,
    });
  }

  try {
    const { signal: _discarded, ...rest } = init;
    return await fetch(url, { ...rest, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}
