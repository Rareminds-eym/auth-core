import { jwtVerify, createRemoteJWKSet } from "jose";
import type { AuthUser, MembershipStatus } from "../types/auth.js";
import { getConfig, onConfigReset } from "../config.js";

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
  const { sub, email, org_id, roles, products, membership_status, is_email_verified } = payload;

  if (typeof sub !== "string") {
    throw new Error("JWT missing required claim: sub");
  }
  if (typeof email !== "string") {
    throw new Error("JWT missing required claim: email");
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
  if (typeof is_email_verified !== "boolean") {
    throw new Error("JWT claim 'is_email_verified' must be a boolean");
  }

  return {
    sub,
    email,
    org_id,
    roles,
    products,
    membership_status: membership_status as MembershipStatus,
    is_email_verified,
  };
}

export async function verifyJWT(token: string): Promise<AuthUser> {
  const config = getConfig();

  const { payload } = await jwtVerify(token, getJWKS(), {
    issuer: config.issuer,
    audience: config.audience,
  });
  return assertAuthUser(payload as Record<string, unknown>);
}
