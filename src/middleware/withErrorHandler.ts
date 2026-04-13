import type { ContextWithUser } from "../types/auth.js";

export function withErrorHandler(
  handler: (context: ContextWithUser) => Promise<Response> | Response
) {
  return async (context: ContextWithUser): Promise<Response> => {
    try {
      return await handler(context);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      const stack = err instanceof Error ? err.stack : undefined;
      const url = context.request?.url ?? "unknown";
      const timestamp = new Date().toISOString();

      console.error(
        JSON.stringify({
          level: "error",
          message,
          stack,
          url,
          timestamp,
        })
      );

      return new Response(
        JSON.stringify({
          error: "Internal Server Error",
          timestamp,
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  };
}
