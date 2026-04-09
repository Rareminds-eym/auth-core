import { jwtVerify, createRemoteJWKSet } from "jose";
import type { AuthUser } from "../types/auth";
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
  if (typeof membership_status !== "string") {
    throw new Error("JWT missing required claim: membership_status");
  }

  return { sub, org_id, roles, products, membership_status } as AuthUser;
}

export async function verifyJWT(token: string): Promise<AuthUser> {
  const { payload } = await jwtVerify(token, getJWKS());
  return assertAuthUser(payload as Record<string, unknown>);
}
