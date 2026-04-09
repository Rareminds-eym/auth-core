export interface AuthCoreConfig {
  ssoDomain: string;
  /** Timeout in ms for SSO fetch calls. Default: 5000 */
  ssoTimeoutMs?: number;
  /**
   * Whether to call /auth/validate-session before /auth/refresh.
   * Set to false if your /auth/refresh endpoint already rejects revoked sessions.
   * Default: true
   */
  validateSessionBeforeRefresh?: boolean;
}

let _config: AuthCoreConfig | null = null;
let _onReset: (() => void)[] = [];

/**
 * Register a callback to run when initAuth resets config.
 * Used internally to clear caches (e.g. JWKS) on re-init.
 */
export function onConfigReset(fn: () => void): void {
  _onReset.push(fn);
}

/**
 * Initialize auth-core with runtime config.
 * Must be called before any auth middleware runs.
 * Safe to call again — clears all internal caches (JWKS, etc).
 */
export function initAuth(config: AuthCoreConfig): void {
  _config = { ssoTimeoutMs: 5000, validateSessionBeforeRefresh: true, ...config };
  // Flush all cached state that depends on config
  for (const fn of _onReset) fn();
}

export function getConfig(): AuthCoreConfig {
  if (!_config) {
    throw new Error(
      "auth-core not initialized. Call initAuth({ ssoDomain: '...' }) before using any middleware."
    );
  }
  return _config;
}
