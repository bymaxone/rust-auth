import { defineConfig } from "vitest/config";

/**
 * The frontend unit suite. `jsdom` backs the `./react` hook tests; the `./shared`,
 * `./client`, and `./nextjs` suites are environment-agnostic. Workers are capped so a CI
 * run (or a parallel agent) never fans out into an unbounded fork pool.
 */
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "tests/**/*.test.ts", "tests/**/*.test.tsx"],
    maxWorkers: "50%",
    minWorkers: 1,
  },
});
