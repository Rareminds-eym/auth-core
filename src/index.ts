export { initAuth, getConfig, onConfigReset } from "./config";
export type { AuthCoreConfig } from "./config";

export { verifyJWT } from "./jwt/verifyJWT";

export { withAuth } from "./middleware/withAuth";
export { requireRole } from "./middleware/requireRole";
export { requireProduct } from "./middleware/requireProduct";
export { withErrorHandler } from "./middleware/withErrorHandler";

export { getRefreshToken } from "./utils/getRefreshToken";
export { extractToken } from "./utils/extractToken";
export { fetchWithTimeout } from "./utils/fetchWithTimeout";

export { refreshAccessToken } from "./session/refreshAccessToken";
export { validateSession } from "./session/validateSession";

export type {
  AuthUser,
  MembershipStatus,
  ContextWithUser,
  SessionValidationResponse,
} from "./types/auth";
