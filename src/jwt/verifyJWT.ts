import { jwtVerify, createRemoteJWKSet } from "jose";
import type { AuthUser, MembershipStatus } from "../types/auth";
import { getConfig, onConfigReset } from "../config";

let _jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

// Clear JWKS when initAuth is called again with a new domain
onConfigReset(() => {
  _jwks = null;
});

function getJWKS(): ReturnType<typeof createRemoteJWKSet> {
  if (!_jwks) {
    const { ssoDomain } = getConfig();
    _jwks = createRemoteJWKSet(
      new URL(`${ssoDomain}/.well-known/jwks.json`)
    );
  }
  return _jwks;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

const VALID_MEMBERSHIP_STATUSES: Set<string> = new Set([
  "active",
  "inactive",
  "suspended",
  "expired",
]);

/**
 * Validates that a decoded JWT payload contains all required AuthUser fields
 * with correct types, including array element validation.
 */
function assertAuthUser(payload: Record<string, unknown>): AuthUser {
  const { sub, org_id, roles, products, membership_status } = payload;

  if (typeof sub !== "string") {
    throw new Error("JWT missing required claim: sub");
  }
  if (typeof org_id !== "string") {
    throw new Error("JWT missing required claim: org_id");
  }
  if (!isStringArray(roles)) {
    throw new Error("JWT claim 'roles' must be an array of strings");
  }
  if (!isStringArray(products)) {
    throw new Error("JWT claim 'products' must be an array of strings");
  }
  if (
    typeof membership_status !== "string" ||
    !VALID_MEMBERSHIP_STATUSES.has(membership_status)
  ) {
    throw new Error(
      "JWT claim 'membership_status' must be one of: active, inactive, suspended, expired"
    );
  }

  return {
    sub,
    org_id,
    roles,
    products,
    membership_status: membership_status as MembershipStatus,
  };
}

export async function verifyJWT(token: string): Promise<AuthUser> {
  const config = getConfig();

  const verifyOptions: { issuer?: string; audience?: string } = {};
  if (config.issuer) verifyOptions.issuer = config.issuer;
  if (config.audience) verifyOptions.audience = config.audience;

  const { payload } = await jwtVerify(token, getJWKS(), verifyOptions);
  return assertAuthUser(payload as Record<string, unknown>);
}
