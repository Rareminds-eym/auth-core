import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        watch: false,
        passWithNoTests: false,
        exclude: ["**/node_modules/**", "**/auth-core/**"],
        isolate: true,
        fileParallelism: false,
        maxWorkers: 1,
        minWorkers: 1,
        retry: 0,
        allowOnly: false,
        sequence: { shuffle: false },
        fakeTimers: { shouldAdvanceTime: false },
        coverage: {
            provider: "istanbul",
            reporter: ["text", "json-summary"],
            include: [
                "src/internal/verifier.ts",
                "src/internal/jwks-key-store.ts",
                "src/internal/bearer.ts",
                "src/internal/browser-route-guard.ts",
            ],
            thresholds: {
                statements: 100,
                branches: 100,
                functions: 100,
                lines: 100,
            },
        },
    },
});
