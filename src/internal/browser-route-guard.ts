import type { ResolvedAuthCoreConfig } from "./config.js";
import { errorResponse } from "./errors.js";

const ROUTE_SUFFIXES = Object.freeze([
    "/login",
    "/signup",
    "/signup-member",
    "/session",
    "/session/organization",
    "/me",
    "/organizations",
    "/invite",
    "/invite/accept",
    "/invite/cancel",
    "/invite/resend",
    "/verification/request",
    "/verification/complete",
    "/password/forgot",
    "/password/reset",
    "/logout/current",
    "/logout/all",
] as const);

/** Read-only routes consumed by the SDK's identity workflows. */
const ROUTE_METHODS: Readonly<Partial<Record<BrowserRouteSuffix, "GET" | "POST">>> = Object.freeze({
    "/me": "GET",
    "/organizations": "GET",
});

export type BrowserRouteSuffix = typeof ROUTE_SUFFIXES[number];
export type BrowserGuardRejectionReason =
    | "route"
    | "method"
    | "origin"
    | "csrf"
    | "fetch_site"
    | "fetch_mode"
    | "fetch_destination"
    | "media_type";

export interface BrowserAuthRoute {
    readonly suffix: BrowserRouteSuffix;
    readonly path: string;
    readonly method: "GET" | "POST";
}

interface AcceptedBrowserRequest {
    readonly ok: true;
    readonly kind: "actual" | "preflight";
    readonly route: BrowserAuthRoute;
    readonly corsOrigin?: string;
}

interface RejectedBrowserRequest {
    readonly ok: false;
    readonly reason: BrowserGuardRejectionReason;
    readonly corsOrigin?: string;
}

export type BrowserGuardResult = AcceptedBrowserRequest | RejectedBrowserRequest;

interface HeadersWithRawValues extends Headers {
    getAll?: (name: string) => string[];
    raw?: () => Record<string, string[]>;
}

export function rawHeaderValues(headers: HeadersWithRawValues, name: string): string[] | undefined | null {
    try {
        if (typeof headers.raw === "function") {
            const raw = headers.raw();
            const values = Object.entries(raw)
                .filter(([key]) => key.toLowerCase() === name.toLowerCase())
                .flatMap(([, entries]) => entries);
            return values.length === 0 ? undefined : values;
        }
        if (typeof headers.getAll === "function") {
            const values = headers.getAll(name);
            return values.length === 0 ? undefined : values;
        }
        return undefined;
    } catch {
        // In workerd (Cloudflare Workers), getAll() throws TypeError for
        // non-Set-Cookie headers. This is a runtime limitation, not evidence
        // of header injection — return undefined so headerValue() falls back
        // to the standard headers.get() value.
        return undefined;
    }
}


export function headerValue(
    headers: Headers,
    name: string,
    commaAllowed = false,
): string | undefined {
    let normalized: string | null;
    try {
        normalized = headers.get(name);
    } catch {
        return undefined;
    }
    if (normalized === null) return undefined;

    const raw = rawHeaderValues(headers as HeadersWithRawValues, name);
    if (raw === null || (raw !== undefined && raw.length !== 1)) return undefined;
    const value = (raw?.[0] ?? normalized).trim();
    if (
        value.length === 0 ||
        /[\u0000-\u001f\u007f]/.test(value) ||
        (!commaAllowed && value.includes(",")) ||
        (raw !== undefined && value !== normalized)
    ) {
        return undefined;
    }
    return value;
}

export function validApprovedOrigin(value: string | undefined, approved: ReadonlySet<string>): value is string {
    if (value === undefined || !approved.has(value)) return false;
    try {
        const parsed = new URL(value);
        const isSecure = parsed.protocol === "https:" || (parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]"));
        return isSecure && parsed.origin === value && parsed.pathname === "/" &&
            parsed.search === "" && parsed.hash === "" && parsed.username === "" && parsed.password === "";
    } catch {
        return false;
    }
}

const TOKEN_CHARACTER = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]$/;

function consumeToken(value: string, from: number): number {
    let cursor = from;
    while (cursor < value.length && TOKEN_CHARACTER.test(value[cursor] as string)) cursor += 1;
    return cursor;
}

function consumeOptionalWhitespace(value: string, from: number): number {
    let cursor = from;
    while (value[cursor] === " " || value[cursor] === "\t") cursor += 1;
    return cursor;
}

function consumeParameterValue(value: string, from: number): number {
    if (value[from] !== "\"") return consumeToken(value, from);
    let cursor = from + 1;
    while (cursor < value.length) {
        const character = value[cursor];
        if (character === "\"") return cursor + 1;
        if (character === "\\") {
            cursor += 1;
            if (cursor >= value.length || /[\u0000-\u001f\u007f]/.test(value[cursor] as string)) return from;
        } else if (character === undefined || /[\u0000-\u001f\u007f]/.test(character)) {
            return from;
        }
        cursor += 1;
    }
    return from;
}

export function isApplicationJson(value: string | undefined): boolean {
    if (value === undefined || value.includes(",")) return false;
    let cursor = consumeOptionalWhitespace(value, 0);
    const mediaStart = cursor;
    cursor = consumeToken(value, cursor);
    const type = value.slice(mediaStart, cursor).toLowerCase();
    if (value[cursor] !== "/") return false;
    cursor += 1;
    const subtypeStart = cursor;
    cursor = consumeToken(value, cursor);
    const subtype = value.slice(subtypeStart, cursor).toLowerCase();
    if (type !== "application" || subtype !== "json") return false;

    const parameters = new Set<string>();
    cursor = consumeOptionalWhitespace(value, cursor);
    while (cursor < value.length) {
        if (value[cursor] !== ";") return false;
        cursor = consumeOptionalWhitespace(value, cursor + 1);
        const nameStart = cursor;
        cursor = consumeToken(value, cursor);
        const name = value.slice(nameStart, cursor).toLowerCase();
        if (name.length === 0 || parameters.has(name)) return false;
        parameters.add(name);
        cursor = consumeOptionalWhitespace(value, cursor);
        if (value[cursor] !== "=") return false;
        cursor = consumeOptionalWhitespace(value, cursor + 1);
        const valueStart = cursor;
        cursor = consumeParameterValue(value, cursor);
        if (cursor === valueStart) return false;
        cursor = consumeOptionalWhitespace(value, cursor);
    }
    return true;
}

function exactPreflightHeaders(value: string | undefined, csrfName: string): boolean {
    if (value === undefined) return false;
    const fields = value.split(",").map((field) => field.trim().toLowerCase());
    const unique = new Set(fields);
    if (unique.size !== fields.length) return false;
    // Required: content-type and csrf header. Optional: authorization (for GET endpoints like /me, /organizations).
    const hasRequired = unique.has("content-type") && unique.has(csrfName.toLowerCase());
    if (fields.length === 2) return hasRequired;
    if (fields.length === 3) return hasRequired && unique.has("authorization");
    return false;
}

export function matchRoute(request: Request, config: ResolvedAuthCoreConfig): BrowserAuthRoute | undefined {
    try {
        const url = new URL(request.url);
        if (url.search !== "" || url.hash !== "") return undefined;
        const suffix = ROUTE_SUFFIXES.find((candidate) => url.pathname === `${config.basePath}${candidate}`);
        return suffix === undefined
            ? undefined
            : Object.freeze({ suffix, path: `${config.basePath}${suffix}`, method: ROUTE_METHODS[suffix] ?? ("POST" as const) });
    } catch {
        return undefined;
    }
}

function rejected(reason: BrowserGuardRejectionReason, corsOrigin?: string): RejectedBrowserRequest {
    return Object.freeze({ ok: false, reason, ...(corsOrigin === undefined ? {} : { corsOrigin }) });
}

/** Validates only request metadata; it never reads body, Cookie, or Authorization values. */
export function validateBrowserAuthRequest(
    request: Request,
    config: ResolvedAuthCoreConfig,
): BrowserGuardResult {
    const route = matchRoute(request, config);
    if (route === undefined) return rejected("route");

    const preflight = request.method === "OPTIONS";
    if (!preflight && request.method !== route.method) return rejected("method");
    if (preflight && headerValue(request.headers, "Access-Control-Request-Method") !== route.method) {
        return rejected("method");
    }

    let origin = headerValue(request.headers, "Origin");
    if (origin === undefined && route.method === "GET") {
        try {
            const urlOrigin = new URL(request.url).origin;
            if (config.approvedOrigins.has(urlOrigin)) {
                origin = urlOrigin;
            }
        } catch {
            origin = undefined;
        }
    }
    if (!validApprovedOrigin(origin, config.approvedOrigins)) return rejected("origin");
    const corsOrigin = config.credentialedCorsOrigins.has(origin) ? origin : undefined;
    if (preflight && corsOrigin === undefined) return rejected("origin");

    if (preflight) {
        if (!exactPreflightHeaders(headerValue(request.headers, "Access-Control-Request-Headers", true), config.csrf.name)) {
            return rejected("csrf", corsOrigin);
        }
    } else if (headerValue(request.headers, config.csrf.name) !== config.csrf.value) {
        return rejected("csrf", corsOrigin);
    }

    const fetchSite = headerValue(request.headers, "Sec-Fetch-Site");
    if (fetchSite !== "same-origin" && fetchSite !== "same-site" && fetchSite !== "cross-site") return rejected("fetch_site", corsOrigin);
    if (headerValue(request.headers, "Sec-Fetch-Mode") !== "cors") return rejected("fetch_mode", corsOrigin);
    if (headerValue(request.headers, "Sec-Fetch-Dest") !== "empty") return rejected("fetch_destination", corsOrigin);

    // Bodyless GET routes carry no Content-Type; POST routes must be application/json.
    if (!preflight && route.method === "POST" && !isApplicationJson(headerValue(request.headers, "Content-Type"))) {
        return rejected("media_type", corsOrigin);
    }
    return Object.freeze({ ok: true, kind: preflight ? "preflight" : "actual", route, ...(corsOrigin === undefined ? {} : { corsOrigin }) });
}

function corsResponse(
    response: Response,
    corsOrigin: string | undefined,
    routeMethod: "GET" | "POST",
    csrfName: "X-RM-CSRF",
): Response {
    const headers = new Headers(response.headers);
    for (const name of [...headers.keys()]) {
        if (name.toLowerCase().startsWith("access-control-")) headers.delete(name);
    }
    if (corsOrigin !== undefined) {
        headers.set("Access-Control-Allow-Origin", corsOrigin);
        headers.set("Access-Control-Allow-Credentials", "true");
        headers.set("Access-Control-Allow-Methods", routeMethod);
        headers.set("Access-Control-Allow-Headers", `Content-Type, ${csrfName}, Authorization`);
        headers.set("Vary", "Origin");
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export interface BrowserDispatchResult {
    readonly response: Response;
    readonly rejectionReason?: BrowserGuardRejectionReason;
}

export type AcceptedBrowserRouteHandler = (
    route: BrowserAuthRoute,
    request: Request,
) => Promise<Response> | Response;

/** Dispatches only after the complete guard and applies the closed CORS response policy. */
export async function dispatchBrowserAuthRequest(
    request: Request,
    config: ResolvedAuthCoreConfig,
    handler: AcceptedBrowserRouteHandler,
): Promise<BrowserDispatchResult> {
    const guard = validateBrowserAuthRequest(request, config);
    if (!guard.ok) {
        return Object.freeze({
            response: corsResponse(
                errorResponse("REQUEST_VALIDATION_REJECTED"),
                guard.corsOrigin,
                "POST",
                config.csrf.name,
            ),
            rejectionReason: guard.reason,
        });
    }
    if (guard.kind === "preflight") {
        return Object.freeze({
            response: corsResponse(new Response(null, { status: 204 }), guard.corsOrigin, guard.route.method, config.csrf.name),
        });
    }
    return Object.freeze({
        response: corsResponse(await handler(guard.route, request), guard.corsOrigin, guard.route.method, config.csrf.name),
    });
}
