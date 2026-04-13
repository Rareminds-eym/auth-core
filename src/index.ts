export { initAuth, getConfig, onConfigReset } from "./config";
export type { AuthCoreConfig, ResolvedAuthCoreConfig } from "./config";

export { verifyJWT } from "./jwt/verifyJWT";

export { withAuth } from "./middleware/withAuth";
export { requireRole } from "./middleware/requireRole";
export { requireProduct } from "./middleware/requireProduct";
export { withErrorHandler } from "./middleware/withErrorHandler";

export { getRefreshToken } from "./utils/getRefreshToken";
export { extractToken } from "./utils/extractToken";
export { fetchWithTimeout } from "./utils/fetchWithTimeout";
export { jsonError } from "./utils/jsonError";

export { refreshAccessToken } from "./session/refreshAccessToken";
export { validateSession } from "./session/validateSession";
export { logout } from "./session/logout";

export type {
  AuthUser,
  MembershipStatus,
  ContextWithUser,
  AuthenticatedContext,
  SessionValidationResponse,
} from "./types/auth";
