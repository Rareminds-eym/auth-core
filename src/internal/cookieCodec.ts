const REFRESH_COOKIE_NAME = "__Host-rm-refresh";
const COOKIE_PATH = "/";
const COOKIE_SAME_SITE = "Strict";
const EPOCH = "Thu, 01 Jan 1970 00:00:00 GMT";
// The approved opaque value alphabet is ASCII-only, so code-unit length is
// identical to byte length for the fixed name-plus-value interoperability cap.
const MAX_COOKIE_NAME_VALUE_BYTES = 4096;
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// RFC6265bis cookie-octet: visible US-ASCII excluding DQUOTE, comma,
// semicolon, and backslash. Values are preserved verbatim, never decoded.
const COOKIE_OCTETS = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;
const CONFLICTING_NAMES = [
    REFRESH_COOKIE_NAME.toLowerCase(),
    "rm-refresh",
    "__secure-rm-refresh",
] as const;

/** Maximum value length after accounting for the fixed name in the 4096-byte cookie limit. */
export const MAX_REFRESH_COOKIE_VALUE_BYTES =
    MAX_COOKIE_NAME_VALUE_BYTES - REFRESH_COOKIE_NAME.length;

export interface CookiePolicy {
    readonly name: typeof REFRESH_COOKIE_NAME;
    readonly path: typeof COOKIE_PATH;
    readonly secure: true;
    readonly httpOnly: true;
    readonly sameSite: typeof COOKIE_SAME_SITE;
    readonly domain: undefined;
    readonly maxAgeSeconds: number;
}

export type CookieParseResult =
    | Readonly<{ kind: "present"; value: string }>
    | Readonly<{ kind: "missing"; code: "MISSING_CREDENTIALS" }>
    | Readonly<{ kind: "invalid"; code: "INVALID_COOKIE" }>;

export interface CookieCodec {
    readonly policy: CookiePolicy;
    parse(cookieHeader: unknown): CookieParseResult;
    create(value: string, authoritativeLifetimeSeconds: number): string;
    clear(): string;
}

const MISSING = Object.freeze({ kind: "missing", code: "MISSING_CREDENTIALS" } as const);
const INVALID = Object.freeze({ kind: "invalid", code: "INVALID_COOKIE" } as const);

function validBound(value: unknown): value is number {
    return typeof value === "number" && value > 0 &&
        value <= 9_007_199_254_740_991 && value === Math.floor(value);
}

function trimStartBadWhitespace(value: string): string {
    let index = 0;
    while (value[index] === " " || value[index] === "\t") index += 1;
    return value.slice(index);
}

function trimEndBadWhitespace(value: string): string {
    let index = value.length;
    while (value[index - 1] === " " || value[index - 1] === "\t") index -= 1;
    return value.slice(0, index);
}

function decodeValue(raw: string): string | undefined {
    const startsQuoted = raw.charAt(0) === '"';
    const endsQuoted = raw.charAt(raw.length - 1) === '"';
    if (startsQuoted || endsQuoted) {
        return raw.length >= 2 && startsQuoted && endsQuoted && COOKIE_OCTETS.test(raw.slice(1, -1))
            ? raw.slice(1, -1)
            : undefined;
    }
    return COOKIE_OCTETS.test(raw) ? raw : undefined;
}

function parsePair(rawPair: string): Readonly<{ name: string; value: string; rawValueBytes: number }> | undefined {
    const separator = rawPair.indexOf("=");
    if (separator <= 0) return undefined;

    // The current cookie grammar permits only SP/HTAB as bad whitespace
    // immediately around "="; broad Unicode trimming would create aliases.
    const name = trimEndBadWhitespace(rawPair.slice(0, separator));
    const rawValue = trimStartBadWhitespace(rawPair.slice(separator + 1));
    const value = decodeValue(rawValue);
    return TOKEN.test(name) && value !== undefined
        ? { name, value, rawValueBytes: rawValue.length }
        : undefined;
}

function parseCookieHeader(cookieHeader: unknown): CookieParseResult {
    if (cookieHeader === null || cookieHeader === undefined) return MISSING;
    if (typeof cookieHeader !== "string" || cookieHeader.length === 0) return INVALID;

    let configuredValue: string | undefined;
    const pairs = cookieHeader.split(";");
    for (let index = 0; index < pairs.length; index += 1) {
        const indexedPair = pairs[index]!;
        const rawPair = index === 0 ? indexedPair : indexedPair.charAt(0) === " "
            ? indexedPair.slice(1)
            : undefined;
        if (rawPair === undefined) return INVALID;

        const pair = parsePair(rawPair);
        if (pair === undefined) return INVALID;
        const { name, value, rawValueBytes } = pair;
        const normalizedName = name.toLowerCase();
        if (
            name !== REFRESH_COOKIE_NAME &&
            CONFLICTING_NAMES.some((candidate) => candidate === normalizedName)
        ) return INVALID;
        if (name !== REFRESH_COOKIE_NAME) continue;
        if (
            configuredValue !== undefined || value.length === 0 ||
            name.length + rawValueBytes > MAX_COOKIE_NAME_VALUE_BYTES
        ) return INVALID;
        configuredValue = value;
    }

    return configuredValue === undefined
        ? MISSING
        : Object.freeze({ kind: "present", value: configuredValue });
}

/**
 * Creates an instance-owned codec whose policy cannot be changed to a parent
 * domain or cross-site cookie by configuration or later mutation.
 */
export function createCookieCodec(configuredMaxAgeSeconds: number): CookieCodec {
    if (!validBound(configuredMaxAgeSeconds)) {
        throw new TypeError("Cookie Max-Age must be a positive finite safe integer.");
    }
    const policy: CookiePolicy = Object.freeze({
        name: REFRESH_COOKIE_NAME,
        path: COOKIE_PATH,
        secure: true,
        httpOnly: true,
        sameSite: COOKIE_SAME_SITE,
        domain: undefined,
        maxAgeSeconds: configuredMaxAgeSeconds,
    });
    const attributes = "Secure; HttpOnly; Path=/; SameSite=Strict";

    return Object.freeze({
        policy,
        parse: parseCookieHeader,
        create(value: string, authoritativeLifetimeSeconds: number): string {
            if (
                typeof value !== "string" || value.length === 0 ||
                value.length > MAX_REFRESH_COOKIE_VALUE_BYTES || !COOKIE_OCTETS.test(value)
            ) {
                throw new TypeError("Refresh cookie value is invalid.");
            }
            if (!validBound(authoritativeLifetimeSeconds)) {
                throw new TypeError("Authoritative cookie lifetime must be a positive finite safe integer.");
            }
            const maxAge = Math.min(configuredMaxAgeSeconds, authoritativeLifetimeSeconds);
            return `${REFRESH_COOKIE_NAME}=${value}; ${attributes}; Max-Age=${maxAge}`;
        },
        clear(): string {
            return `${REFRESH_COOKIE_NAME}=; ${attributes}; Max-Age=0; Expires=${EPOCH}`;
        },
    });
}
