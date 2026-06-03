export interface SsoRpcService {
  getJWKS(): Promise<{ keys: any[] }>;
  refreshSession(refreshToken: string, ip?: string, ua?: string): Promise<{ access_token: string, refresh_token: string }>;
  getMe(accessToken: string): Promise<Record<string, unknown>>;
  logoutSession(refreshToken: string, ip?: string, ua?: string): Promise<{ success: boolean }>;
}

export interface AuthCoreConfig {
  /**
   * Required Cloudflare Service Binding for the SSO worker.
   * auth-core strictly uses true RPC methods for zero-latency
   * inter-worker communication, enforcing a 100% RPC ecosystem.
   */
  ssoRpc: SsoRpcService;

  /**
   * Expected JWT issuer claim.
   * Default: "sso-api" (matches the SSO worker).
   */
  issuer?: string;
  /**
   * Expected JWT audience claim.
   * Default: "sso-client" (matches the SSO worker).
   */
  audience?: string;

  /**
   * Whether to validate the session before refreshing.
   * When true, calls GET /auth/me before /auth/refresh.
   * Set to false (recommended) since /auth/refresh already rejects revoked sessions.
   * Default: false
   */
  validateSessionBeforeRefresh?: boolean;
}

/** Default JWT issuer — matches the SSO worker's signing config */
const DEFAULT_ISSUER = "sso-api";

/** Default JWT audience — matches the SSO worker's signing config */
const DEFAULT_AUDIENCE = "sso-client";

export interface ResolvedAuthCoreConfig extends AuthCoreConfig {
  issuer: string;
  audience: string;
  validateSessionBeforeRefresh: boolean;
  ssoRpc: SsoRpcService;
}

let _config: ResolvedAuthCoreConfig | null = null;
let _onReset: (() => void)[] = [];

/**
 * Register a callback to run when initAuth resets config.
 * Used internally to clear caches (e.g. JWKS) on re-init.
 * Returns an unsubscribe function.
 */
export function onConfigReset(fn: () => void): () => void {
  _onReset.push(fn);
  return () => {
    _onReset = _onReset.filter((f) => f !== fn);
  };
}

/**
 * Initialize auth-core with runtime config.
 * Must be called before any auth middleware runs.
 * Safe to call again — clears all internal caches (JWKS, etc).
 */
export function initAuth(config: AuthCoreConfig): void {
  if (!config.ssoRpc) {
    throw new Error("ssoRpc is strictly required. You must provide a True RPC Service Binding to the SSO worker.");
  }

  _config = {
    ...config,
    issuer: config.issuer ?? DEFAULT_ISSUER,
    audience: config.audience ?? DEFAULT_AUDIENCE,
    validateSessionBeforeRefresh: config.validateSessionBeforeRefresh ?? false,
    ssoRpc: config.ssoRpc,
  };

  // Flush all cached state that depends on config
  for (const fn of _onReset) fn();
}

export function getConfig(): ResolvedAuthCoreConfig {
  if (!_config) {
    throw new Error(
      "auth-core not initialized. Call initAuth({ ssoRpc: env.SSO_SERVICE }) before using any middleware."
    );
  }
  return _config;
}
