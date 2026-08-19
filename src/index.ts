/**
 * Creates an isolated trusted-runtime authentication facade.
 *
 * Each call captures immutable verifier-affecting configuration, so instances
 * cannot share issuer, audience, algorithm, or service-binding state.
 */
export { createAuth } from "./createAuth.js";

export type {
  Auth,
  AuthCoreConfig,
  AuthCoreErrorCode,
  AuthCoreErrorDescriptor, AuthCounterName,
  AuthHistogramName, AuthObservation,
  AuthObservationEventName,
  AuthObservationOutcome,
  AuthObservationReason, AuthenticatedContext, AuthenticatedHandler, ContextWithUser, FeatureCheck,
  MembershipStatus,
  RequestHandler,
  VerifiedAuthContext,
  VerifiedAuthUser,
  VerifiedAuthUser as AuthUser,
} from "./types/public.js";

