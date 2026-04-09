import type { ContextWithUser } from "../types/auth";

export function withErrorHandler(
  handler: (context: ContextWithUser) => Promise<Response> | Response
) {
  return async (context: ContextWithUser): Promise<Response> => {
    try {
      return await handler(context);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      const url = context.request?.url ?? "unknown";

      console.error(
        JSON.stringify({
          level: "error",
          message,
          url,
          timestamp: new Date().toISOString(),
        })
      );

      return new Response(
        JSON.stringify({
          error: "Internal Server Error",
          timestamp: new Date().toISOString(),
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  };
}
