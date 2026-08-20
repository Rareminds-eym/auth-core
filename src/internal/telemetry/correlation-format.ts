const CORRELATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PROHIBITED_CORRELATION = /(?:(?:^|[._:-])(?:bearer|cookie|password|secret|credential|authorization|access.?token|refresh.?token|token.?hash|token.?prefix|token.?suffix|private.?key|signing.?key|invitation.?token|verification.?token|reset.?token|refresh.?family|rotation|overlap|reuse|raw.?claim|database|subject|user.?id|organization.?id|session.?id|key.?id|stack|exception|full.?url|ip.?address|user.?agent)(?:[._:-]|$)|https?:|[\w.+-]+@[\w.-]+|(?:\d{1,3}\.){3}\d{1,3}|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.)/iu;

/** Accepts only non-secret, bounded correlation identifiers used at public boundaries. */
export function isValidCorrelationId(value: unknown): value is string {
    return typeof value === "string" && CORRELATION_PATTERN.test(value) && !PROHIBITED_CORRELATION.test(value);
}
