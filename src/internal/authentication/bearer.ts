const MAX_BEARER_LENGTH = 8192;
const BEARER_PATTERN = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i;

type BearerResult =
    | { readonly ok: true; readonly token: string }
    | { readonly ok: false; readonly code: "MISSING_CREDENTIALS" | "INVALID_TOKEN" };

/** Parses one normalized Authorization credential without cookie fallback. */
export function extractBearer(request: Request): BearerResult {
    const value = request.headers.get("Authorization");
    if (value === null) {
        return { ok: false, code: "MISSING_CREDENTIALS" };
    }
    if (value.includes(",")) {
        return { ok: false, code: "INVALID_TOKEN" };
    }

    const match = BEARER_PATTERN.exec(value);
    const token = match?.[1];
    if (!token || token.length > MAX_BEARER_LENGTH) {
        return { ok: false, code: "INVALID_TOKEN" };
    }
    return { ok: true, token };
}
