import type { ResolvedAuthCoreConfig } from "./config.js";
import { isValidCorrelationId } from "./correlation-format.js";
import { CoreFailure } from "./errors.js";

export { isValidCorrelationId } from "./correlation-format.js";

export function correlationIdFor(
    request: Request,
    config: ResolvedAuthCoreConfig,
): string {
    let value: unknown;
    try {
        value = config.correlationId === undefined
            ? globalThis.crypto.randomUUID()
            : config.correlationId(request);
    } catch {
        throw new CoreFailure("INTERNAL_FAILURE");
    }
    if (!isValidCorrelationId(value)) {
        throw new CoreFailure("INTERNAL_FAILURE");
    }
    return value;
}
