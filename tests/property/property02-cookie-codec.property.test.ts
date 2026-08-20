import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { retainedPropertyParameters } from "../../../tools/auth-test-infrastructure/pbt.mjs";
import {
    createCookieCodec,
    MAX_REFRESH_COOKIE_VALUE_BYTES,
} from "../../src/internal/browser/cookie-codec.js";

const FEATURE_PROPERTY_LABEL =
    "Feature: auth-sdk-token-hardening, Property 12: Cookie codec round trips and clears symmetrically";
const COOKIE_NAME = "__Host-rm-refresh";
const SHARED_ATTRIBUTES = ["Secure", "HttpOnly", "Path=/", "SameSite=Strict"] as const;
const COOKIE_OCTETS =
    "!#$%&'()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~".split("");
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const maxLengthValue = new Array(MAX_REFRESH_COOKIE_VALUE_BYTES + 1).join("a");
const overLimitValue = `${maxLengthValue}a`;
const lifetimeArbitrary = fc.integer({ min: 1, max: MAX_SAFE_INTEGER });
const shortValueArbitrary = fc.array(fc.constantFrom(...COOKIE_OCTETS), {
    minLength: 1,
    maxLength: 96,
}).map((characters) => characters.join(""));
const validValueArbitrary = fc.oneof(
    shortValueArbitrary,
    fc.constant(maxLengthValue),
);

type ValidScenario = Readonly<{
    kind: "valid";
    value: string;
    configuredLifetime: number;
    authoritativeLifetime: number;
}>;
type HostileScenario = Readonly<{
    kind: "hostile";
    header: string;
    expected: "invalid" | "missing";
    createValue?: string;
    configuredLifetime: number;
    authoritativeLifetime: number;
}>;
type Scenario = ValidScenario | HostileScenario;

function splitSetCookie(serialized: string): Readonly<{
    name: string;
    value: string;
    attributes: readonly string[];
}> {
    const [pair = "", ...attributes] = serialized.split("; ");
    const separator = pair.indexOf("=");
    return {
        name: pair.slice(0, separator),
        value: pair.slice(separator + 1),
        attributes,
    };
}

function verifyValidScenario(scenario: ValidScenario): void {
    const codec = createCookieCodec(scenario.configuredLifetime);
    const expectedLifetime = Math.min(scenario.configuredLifetime, scenario.authoritativeLifetime);
    const created = codec.create(scenario.value, scenario.authoritativeLifetime);
    const createdParts = splitSetCookie(created);
    const cookieHeader = `theme=dark; ${createdParts.name}=${createdParts.value}; locale=en`;
    const parsed = codec.parse(cookieHeader);

    expect(parsed).toEqual({ kind: "present", value: scenario.value });
    if (parsed.kind !== "present") throw new Error("Expected generated valid cookie to parse.");
    const reserialized = codec.create(parsed.value, scenario.authoritativeLifetime);
    expect(reserialized).toBe(created);
    expect(codec.parse(`${createdParts.name}=${createdParts.value}`)).toEqual(parsed);
    expect(createdParts).toEqual({
        name: COOKIE_NAME,
        value: scenario.value,
        attributes: [...SHARED_ATTRIBUTES, `Max-Age=${expectedLifetime}`],
    });
    expect(created).not.toMatch(/(?:^|; )Domain=|SameSite=None/);

    const clearedParts = splitSetCookie(codec.clear());
    expect(clearedParts).toEqual({
        name: COOKIE_NAME,
        value: "",
        attributes: [
            ...SHARED_ATTRIBUTES,
            "Max-Age=0",
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        ],
    });
    expect(clearedParts.attributes.slice(0, SHARED_ATTRIBUTES.length))
        .toEqual(createdParts.attributes.slice(0, SHARED_ATTRIBUTES.length));
}

function verifyHostileScenario(scenario: HostileScenario): void {
    const codec = createCookieCodec(scenario.configuredLifetime);
    let rpcCalls = 0;
    const parsed = codec.parse(scenario.header);
    if (parsed.kind === "present") rpcCalls += 1;

    expect(parsed.kind).toBe(scenario.expected);
    expect(parsed).not.toHaveProperty("value");
    expect(rpcCalls).toBe(0);
    if (scenario.createValue !== undefined) {
        expect(() => codec.create(scenario.createValue!, scenario.authoritativeLifetime))
            .toThrow("Refresh cookie value is invalid.");
    }
}

const invalidValueArbitrary = fc.tuple(
    fc.array(fc.constantFrom(...COOKIE_OCTETS), { maxLength: 16 }),
    fc.constantFrom(" ", "\"", ",", ";", "\\", "\u0000", "\u007f", "\u00a0"),
    fc.array(fc.constantFrom(...COOKIE_OCTETS), { maxLength: 16 }),
).map(([before, invalid, after]) => `${before.join("")}${invalid}${after.join("")}`);

const hostileHeaderArbitrary = fc.oneof(
    invalidValueArbitrary.map((value) => ({
        header: `${COOKIE_NAME}=${value}`,
        expected: "invalid" as const,
        createValue: value,
    })),
    fc.tuple(validValueArbitrary, validValueArbitrary).map(([left, right]) => ({
        header: `${COOKIE_NAME}=${left}; ${COOKIE_NAME}=${right}`,
        expected: "invalid" as const,
    })),
    fc.tuple(
        fc.constantFrom("rm-refresh", "__Secure-rm-refresh", "__host-rm-refresh"),
        validValueArbitrary,
        fc.boolean(),
    ).map(([name, value, alongsideConfigured]) => ({
        header: alongsideConfigured
            ? `${COOKIE_NAME}=${value}; ${name}=${value}`
            : `${name}=${value}`,
        expected: "invalid" as const,
    })),
    fc.constant({
        header: `${COOKIE_NAME}=${overLimitValue}`,
        expected: "invalid" as const,
        createValue: overLimitValue,
    }),
    fc.constantFrom(
        COOKIE_NAME,
        "=opaque",
        `theme=dark;${COOKIE_NAME}=opaque`,
        ` ${COOKIE_NAME}=opaque`,
        `${COOKIE_NAME}=opaque; `,
        `${COOKIE_NAME}=one, other=two`,
        `${COOKIE_NAME}=`,
    ).map((header) => ({
        header,
        expected: "invalid" as const,
        ...(header === `${COOKIE_NAME}=` ? { createValue: "" } : {}),
    })),
    fc.tuple(
        fc.constantFrom("refresh_token", "__Host-refresh_token", "__Secure-refresh_token", "access_token"),
        validValueArbitrary,
    ).map(([name, value]) => ({
        header: `${name}=${value}`,
        expected: "missing" as const,
    })),
);

const scenarioArbitrary: fc.Arbitrary<Scenario> = fc.oneof(
    fc.record({
        kind: fc.constant("valid" as const),
        value: validValueArbitrary,
        configuredLifetime: lifetimeArbitrary,
        authoritativeLifetime: lifetimeArbitrary,
    }),
    fc.record({
        kind: fc.constant("hostile" as const),
        configuredLifetime: lifetimeArbitrary,
        authoritativeLifetime: lifetimeArbitrary,
        hostile: hostileHeaderArbitrary,
    }).map(({ hostile, ...scenario }) => ({ ...scenario, ...hostile })),
);

describe(FEATURE_PROPERTY_LABEL, () => {
    it(FEATURE_PROPERTY_LABEL, () => {
        // **Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.8, 11.9, 11.12, 20.9, 20.11, 20.12**
        fc.assert(fc.property(scenarioArbitrary, (scenario) => {
            if (scenario.kind === "valid") verifyValidScenario(scenario);
            else verifyHostileScenario(scenario);
        }), retainedPropertyParameters({
            suiteId: "auth-hardening.property",
            property: "property-12-cookie-codec-round-trips-and-clears-symmetrically",
        }, { parameters: { numRuns: 150 } }));
    });
});
