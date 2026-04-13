export { initAuth, getConfig, onConfigReset } from "./config.js";
export type { AuthCoreConfig, ResolvedAuthCoreConfig } from "./config.js";

export { verifyJWT } from "./jwt/verifyJWT.js";

export { withAuth } from "./middleware/withAuth.js";
export { requireRole } from "./middleware/requireRole.js";
export { requireProduct } from "./middleware/requireProduct.js";
export { withErrorHandler } from "./middleware/withErrorHandler.js";

export { getRefreshToken } from "./utils/getRefreshToken.js";
export { extractToken } from "./utils/extractToken.js";
export { fetchWithTimeout } from "./utils/fetchWithTimeout.js";
export { jsonError } from "./utils/jsonError.js";

export { refreshAccessToken } from "./session/refreshAccessToken.js";
export { validateSession } from "./session/validateSession.js";
export { logout } from "./session/logout.js";

export type {
  AuthUser,
  MembershipStatus,
  ContextWithUser,
  AuthenticatedContext,
  SessionValidationResponse,
} from "./types/auth.js";
