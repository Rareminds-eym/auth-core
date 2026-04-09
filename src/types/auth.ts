export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

export interface AuthUser {
  sub: string;
  org_id: string;
  roles: string[];
  products: string[];
  membership_status: MembershipStatus;
}

export interface SessionValidationResponse {
  valid: boolean;
  user?: AuthUser;
}

/**
 * Extends the base Cloudflare-style context.
 * Generic `Env` lets consumers pass their own env bindings.
 */
export interface ContextWithUser<Env = Record<string, unknown>> {
  request: Request;
  env: Env;
  params: Record<string, string>;
  data: {
    user?: AuthUser;
    [key: string]: unknown;
  };
  waitUntil: (promise: Promise<unknown>) => void;
  passThroughOnException: () => void;
}
