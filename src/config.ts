export interface AuthCoreConfig {
  ssoDomain: string;
  /** Expected JWT issuer claim. Recommended for multi-service setups. */
  issuer?: string;
  /** Expected JWT audience claim. Recommended for multi-service setups. */
  audience?: string;
  /** Timeout in ms for SSO fetch calls. Default: 5000 */
  ssoTimeoutMs?: number;
  /**
   * Whether to call /auth/validate-session before /auth/refresh.
   * Set to false if your /auth/refresh endpoint already rejects revoked sessions.
   * Default: true
   */
  validateSessionBeforeRefresh?: boolean;
}

/**
 * Internal resolved config where defaults have been applied.
 * Guarantees ssoTimeoutMs and validateSessionBeforeRefresh are set.
 */
export interface ResolvedAuthCoreConfig extends AuthCoreConfig {
  ssoTimeoutMs: number;
  validateSessionBeforeRefresh: boolean;
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
  if (!config.ssoDomain || typeof config.ssoDomain !== "string") {
    throw new Error("ssoDomain is required and must be a non-empty string");
  }

  // Validate it's a parseable URL
  try {
    new URL(config.ssoDomain);
  } catch {
    throw new Error(`ssoDomain is not a valid URL: ${config.ssoDomain}`);
  }

  const timeout = config.ssoTimeoutMs ?? 5000;
  if (timeout <= 0) {
    throw new Error("ssoTimeoutMs must be a positive number");
  }

  // Normalize: strip trailing slash to avoid double-slash in constructed URLs
  const ssoDomain = config.ssoDomain.replace(/\/+$/, "");

  _config = {
    ...config,
    ssoDomain,
    ssoTimeoutMs: timeout,
    validateSessionBeforeRefresh: config.validateSessionBeforeRefresh ?? true,
  };

  // Flush all cached state that depends on config
  for (const fn of _onReset) fn();
}

export function getConfig(): ResolvedAuthCoreConfig {
  if (!_config) {
    throw new Error(
      "auth-core not initialized. Call initAuth({ ssoDomain: '...' }) before using any middleware."
    );
  }
  return _config;
}
