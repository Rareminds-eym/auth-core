import { getConfig } from "../src/config.js";
import { verifyJWT } from "../src/jwt/verifyJWT.js";
import { withAuth } from "../src/middleware/withAuth.js";
import { refreshAccessToken } from "../src/session/refreshAccessToken.js";
import { extractToken } from "../src/utils/extractToken.js";
import type { AuthUser } from "../src/types/auth.js";

export const legacySurface: unknown[] = [getConfig, verifyJWT, withAuth, refreshAccessToken, extractToken];
export type LegacyUser = AuthUser;
