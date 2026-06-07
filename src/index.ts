export { getConfig, initAuth, onConfigReset } from "./config.js";
export type { AuthCoreConfig, ResolvedAuthCoreConfig } from "./config.js";

export { verifyJWT } from "./jwt/verifyJWT.js";

export { requireFeature } from "./middleware/requireFeature.js";
export { requireProduct } from "./middleware/requireProduct.js";
export { requireRole } from "./middleware/requireRole.js";
export { withAuth } from "./middleware/withAuth.js";
export { withErrorHandler } from "./middleware/withErrorHandler.js";

export { extractToken } from "./utils/extractToken.js";
export { getRefreshToken } from "./utils/getRefreshToken.js";
export { jsonError } from "./utils/jsonError.js";

export { logout } from "./session/logout.js";
export { refreshAccessToken } from "./session/refreshAccessToken.js";
export { validateSession } from "./session/validateSession.js";

export type {
  AuthUser, AuthenticatedContext, ContextWithUser, MembershipStatus, SessionValidationResponse
} from "./types/auth.js";

