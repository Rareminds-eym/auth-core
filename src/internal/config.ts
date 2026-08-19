import type {
    AuthCoreConfig,
    AuthObservation,
    SsoServiceBinding
} from "../types/public.js";

const MAX_TIMER_DELAY = 2_147_483_647;
const MAX_TEXT_LENGTH = 2048;
const CSRF_NAME = "X-RM-CSRF";
const CSRF_VALUE = "1";

export interface ResolvedAuthCoreConfig {
    readonly sso: SsoServiceBinding;
    readonly issuer: string;
    readonly audience: string;
    readonly approvedOrigins: ReadonlySet<string>;
    readonly basePath: string;
    readonly csrf: Readonly<{ name: "X-RM-CSRF"; value: "1" }>;
    readonly cookieMaxAgeSeconds: number;
    readonly jwksMaxAgeSeconds?: number;
    readonly ssoRequestTimeoutMs: number;
    readonly credentialedCorsOrigins: ReadonlySet<string>;
    readonly observer?: (event: AuthObservation) => void;
    readonly correlationId?: (request: Request) => string;
}

class InvalidConfigurationError extends TypeError { }

function invalidConfiguration(reason: string): never {
    throw new InvalidConfigurationError(`Invalid Auth Core configuration: ${reason}.`);
}

function requireText(value: unknown, field: string): string {
    if (
        typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_TEXT_LENGTH ||
        value !== value.trim() ||
        /[\u0000-\u001f\u007f]/.test(value)
    ) {
        invalidConfiguration(`${field} must be a non-empty normalized string`);
    }
    return value;
}
function isLocalhostHost(hostname: string): boolean {
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function isSecureOriginUrl(url: URL): boolean {
    if (url.protocol === "https:") return true;
    if (url.protocol === "http:") {
        return isLocalhostHost(url.hostname);
    }
    return false;
}

function parseOrigin(value: unknown, field: string): string {
    const input = requireText(value, field);
    if (input.includes("*") || input === "null") {
        invalidConfiguration(`${field} must not be wildcard or opaque`);
    }

    let parsed: URL;
    try {
        parsed = new URL(input);
    } catch {
        invalidConfiguration(`${field} must be an absolute HTTPS origin`);
    }

    if (
        !isSecureOriginUrl(parsed) ||
        parsed.origin === "null" ||
        parsed.username !== "" ||
        parsed.password !== "" ||
        parsed.pathname !== "/" ||
        parsed.search !== "" ||
        parsed.hash !== "" ||
        input !== parsed.origin
    ) {
        invalidConfiguration(`${field} must be an exact path-free HTTPS origin`);
    }
    return parsed.origin;
}

function parseOrigins(value: unknown, field: string): ReadonlySet<string> {
    if (!Array.isArray(value) || value.length === 0) {
        invalidConfiguration(`${field} must contain at least one origin`);
    }
    const parsed = value.map((origin, index) => parseOrigin(origin, `${field}[${index}]`));
    if (new Set(parsed).size !== parsed.length) {
        invalidConfiguration(`${field} must not contain duplicates`);
    }
    return new Set(parsed);
}

function parseBound(value: unknown, field: string): number {
    if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > MAX_TIMER_DELAY) {
        invalidConfiguration(`${field} must be a positive finite safe integer`);
    }
    return value as number;
}

function parseBasePath(value: unknown): string {
    const path = value === undefined ? "/api/auth" : requireText(value, "basePath");
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("?") || path.includes("#") || path.includes("\\")) {
        invalidConfiguration("basePath must be a same-origin absolute path");
    }
    const normalized = new URL(path, "https://auth-core.invalid").pathname;
    if (normalized !== path || (path.length > 1 && path.endsWith("/"))) {
        invalidConfiguration("basePath must be normalized and omit a trailing slash");
    }
    return path;
}
function parseCorsOrigins(
    value: AuthCoreConfig["credentialedCors"],
    approvedOrigins: ReadonlySet<string>,
): ReadonlySet<string> {
    if (value === undefined || value === false) {
        return new Set();
    }
    const origins = parseOrigins(value.origins, "credentialedCors.origins");
    for (const origin of origins) {
        if (!approvedOrigins.has(origin)) {
            invalidConfiguration("credentialedCors origins must be approved origins");
        }
    }
    return origins;
}

/** Captures every verifier-affecting value in a new instance-owned closure. */
export function resolveConfig(config: AuthCoreConfig): ResolvedAuthCoreConfig {
    try {
        if (config === null || typeof config !== "object") {
            invalidConfiguration("config must be an object");
        }

        // Read every caller-controlled property once to prevent accessor-based
        // time-of-check/time-of-use changes while constructing the instance.
        const {
            sso,
            issuer,
            audience,
            approvedOrigins: configuredOrigins,
            basePath,
            csrf,
            cookieMaxAgeSeconds,
            jwksMaxAgeSeconds: configuredJwksMaxAge,
            ssoRequestTimeoutMs,
            credentialedCors,
            observer,
            correlationId,
        } = config;
        const getJwksMethod = (sso as SsoServiceBinding | undefined)?.getJwks;

        if (sso === null || typeof sso !== "object" || typeof getJwksMethod !== "function") {
            invalidConfiguration("sso must provide getJwks");
        }
        // Pass the RPC stub through untouched. Spreading a workerd service-binding
        // stub drops every RPC method: they are exposed only through the proxy get
        // trap, never as own enumerable properties.
        const boundSso = sso as SsoServiceBinding;
        if (csrf?.name !== CSRF_NAME || csrf?.value !== CSRF_VALUE) {
            invalidConfiguration("csrf must be exactly X-RM-CSRF: 1");
        }
        if (observer !== undefined && typeof observer !== "function") {
            invalidConfiguration("observer must be a function");
        }
        if (correlationId !== undefined && typeof correlationId !== "function") {
            invalidConfiguration("correlationId must be a function");
        }

        const approvedOrigins = parseOrigins(configuredOrigins, "approvedOrigins");
        const jwksMaxAgeSeconds = configuredJwksMaxAge === undefined
            ? undefined
            : parseBound(configuredJwksMaxAge, "jwksMaxAgeSeconds");
        return Object.freeze({
            sso: boundSso,
            issuer: requireText(issuer, "issuer"),
            audience: requireText(audience, "audience"),
            approvedOrigins,
            basePath: parseBasePath(basePath),
            csrf: Object.freeze({ name: CSRF_NAME, value: CSRF_VALUE }),
            cookieMaxAgeSeconds: parseBound(cookieMaxAgeSeconds, "cookieMaxAgeSeconds"),
            ...(jwksMaxAgeSeconds === undefined ? {} : { jwksMaxAgeSeconds }),
            ssoRequestTimeoutMs: parseBound(ssoRequestTimeoutMs, "ssoRequestTimeoutMs"),
            credentialedCorsOrigins: parseCorsOrigins(credentialedCors, approvedOrigins),
            ...(observer === undefined ? {} : { observer }),
            ...(correlationId === undefined ? {} : { correlationId }),
        });
    } catch (error) {
        if (error instanceof InvalidConfigurationError) {
            throw error;
        }
        // Configuration accessors and proxies are untrusted input. Their
        // exception details must not cross the factory boundary.
        invalidConfiguration("configuration could not be read");
    }
}
