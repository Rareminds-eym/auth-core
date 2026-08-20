import { describe, expect, it } from "vitest";
import {
    createCookieCodec,
    MAX_REFRESH_COOKIE_VALUE_BYTES,
} from "../../../src/internal/browser/cookie-codec.js";

const codec = createCookieCodec(3600);
const maxLengthValue = new Array(MAX_REFRESH_COOKIE_VALUE_BYTES + 1).join("a");
const overLimitValue = `${maxLengthValue}a`;

describe("immutable host-only Cookie Codec", () => {
    it("should expose only the frozen approved host-only policy", () => {
        expect(codec.policy).toEqual({
            name: "__Host-rm-refresh",
            path: "/",
            secure: true,
            httpOnly: true,
            sameSite: "Strict",
            domain: undefined,
            maxAgeSeconds: 3600,
        });
        expect(Object.isFrozen(codec)).toBe(true);
        expect(Object.isFrozen(codec.policy)).toBe(true);
        expect(() => {
            (codec.policy as { maxAgeSeconds: number }).maxAgeSeconds = 1;
        }).toThrow(TypeError);
    });

    it("should reject parent-domain and cross-site policy shapes instead of making them configurable", () => {
        const prohibitedPolicies = [
            { maxAgeSeconds: 3600, domain: ".example.com" },
            { maxAgeSeconds: 3600, sameSite: "None" },
            { maxAgeSeconds: 3600, name: "__Secure-rm-refresh" },
        ];

        for (const prohibitedPolicy of prohibitedPolicies) {
            expect(() => createCookieCodec(prohibitedPolicy as unknown as number))
                .toThrow("Cookie Max-Age must be a positive finite safe integer.");
        }
    });

    it("should parse exactly one configured value without decoding it", () => {
        expect(codec.parse("theme=dark; __Host-rm-refresh=abc%2Fdef==; locale=en"))
            .toEqual({ kind: "present", value: "abc%2Fdef==" });
        expect(codec.parse('__Host-rm-refresh =\t"opaque-token"'))
            .toEqual({ kind: "present", value: "opaque-token" });
        expect(Object.isFrozen(codec.parse("__Host-rm-refresh=opaque"))).toBe(true);
    });

    it("should accept every permitted cookie octet without transforming it", () => {
        const value = "!#$%&'()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        expect(codec.parse(`__Host-rm-refresh=${value}`))
            .toEqual({ kind: "present", value });
        expect(codec.create(value, 900)).toContain(`=${value}; Secure`);
    });

    it("should accept the exact name-plus-value byte boundary", () => {
        expect(codec.parse(`__Host-rm-refresh=${maxLengthValue}`))
            .toEqual({ kind: "present", value: maxLengthValue });
        expect(codec.create(maxLengthValue, 900)).toContain(`=${maxLengthValue}; Secure`);
    });

    it("should return a frozen typed missing result only for valid fields without the configured name", () => {
        expect(codec.parse(null)).toEqual({ kind: "missing", code: "MISSING_CREDENTIALS" });
        expect(codec.parse(undefined)).toEqual({ kind: "missing", code: "MISSING_CREDENTIALS" });
        expect(codec.parse("theme=dark; locale=en"))
            .toEqual({ kind: "missing", code: "MISSING_CREDENTIALS" });
        expect(Object.isFrozen(codec.parse(null))).toBe(true);
    });

    it.each([
        ["an empty field", ""],
        ["a non-string field", 42],
        ["an empty pair", "theme=dark;"],
        ["a delimiter without required SP", "theme=dark;locale=en"],
        ["a missing name", "=value"],
        ["a missing separator", "theme"],
        ["leading whitespace before a name", " theme=dark"],
        ["trailing whitespace after a value", "theme=dark "],
        ["non-ASCII whitespace aliasing", "\u00a0__Host-rm-refresh=opaque"],
        ["non-OWS control whitespace", "\v__Host-rm-refresh=opaque"],
        ["an invalid value octet", "__Host-rm-refresh=bad value"],
        ["a backslash value octet", "__Host-rm-refresh=bad\\value"],
        ["a malformed quoted value", '__Host-rm-refresh="opaque'],
        ["a comma-combined field", "__Host-rm-refresh=one, other=two"],
        ["an empty configured value", "__Host-rm-refresh="],
        ["duplicate configured names", "__Host-rm-refresh=one; __Host-rm-refresh=two"],
        ["an unprefixed conflict", "rm-refresh=one"],
        ["a secure-prefix conflict", "__Secure-rm-refresh=one"],
        ["a case-conflicting host prefix", "__host-rm-refresh=one"],
        ["a conflict alongside the configured cookie", "__Host-rm-refresh=one; __Secure-rm-refresh=two"],
        ["an over-limit configured value", `__Host-rm-refresh=${overLimitValue}`],
    ])("should reject %s as a typed invalid cookie", (_case, header) => {
        const result = codec.parse(header);
        expect(result).toEqual({ kind: "invalid", code: "INVALID_COOKIE" });
        expect(Object.isFrozen(result)).toBe(true);
    });

    it("should cap creation to the shorter configured or authoritative lifetime", () => {
        expect(codec.create("opaque-token", 7200)).toBe(
            "__Host-rm-refresh=opaque-token; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=3600",
        );
        expect(codec.create("opaque-token", 900)).toBe(
            "__Host-rm-refresh=opaque-token; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=900",
        );
    });

    it.each([
        ["empty", ""],
        ["space octet", "bad value"],
        ["quote octet", 'bad"value'],
        ["over-limit", overLimitValue],
    ])(
        "should reject a %s creation value with a static redacted error",
        (_case, value) => {
            expect(() => codec.create(value, 900)).toThrow("Refresh cookie value is invalid.");
        },
    );

    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
        "should reject invalid authoritative lifetime %s",
        (lifetime) => {
            expect(() => codec.create("opaque-token", lifetime)).toThrow(/positive finite safe integer/);
        },
    );

    it("should clear with creation-symmetric attributes and zero/epoch expiry", () => {
        const created = codec.create("opaque-token", 900);
        const cleared = codec.clear();

        for (const attribute of ["Secure", "HttpOnly", "Path=/", "SameSite=Strict"]) {
            expect(created).toContain(`; ${attribute}`);
            expect(cleared).toContain(`; ${attribute}`);
        }
        expect(cleared).toBe(
            "__Host-rm-refresh=; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=0; " +
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        );
        expect(created).not.toMatch(/Domain=|SameSite=None/);
        expect(cleared).not.toMatch(/Domain=|SameSite=None/);
    });

    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
        "should reject invalid configured Max-Age %s",
        (maxAge) => {
            expect(() => createCookieCodec(maxAge)).toThrow(/positive finite safe integer/);
        },
    );
});
