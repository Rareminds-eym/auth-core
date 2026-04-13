export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

export interface AuthUser {
  sub: string;
  email: string;
  org_id: string;
  roles: string[];
  products: string[];
  membership_status: MembershipStatus;
  is_email_verified: boolean;
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

/**
 * Context type where `user` is guaranteed to exist.
 * Use this in handlers wrapped by `withAuth`.
 */
export interface AuthenticatedContext<Env = Record<string, unknown>>
  extends ContextWithUser<Env> {
  data: {
    user: AuthUser;
    [key: string]: unknown;
  };
}
