import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

/**
 * The frontend unit suite. `jsdom` backs the `./react` hook tests; the `./shared`,
 * `./client`, and `./nextjs` suites are environment-agnostic. Workers are capped so a CI
 * run (or a parallel agent) never fans out into an unbounded fork pool.
 *
 * Two test-only module aliases let the server (`./nextjs`) modules run under Node:
 *  - `server-only` → a no-op stub, since the real marker package throws outside the
 *    React Server Components (`react-server`) condition the Node runner does not set.
 *  - the bundler-target `bymax_auth_wasm.js` wrapper (whose direct `.wasm` import Node
 *    cannot resolve) → a shim that instantiates the SAME wasm artifact synchronously, so
 *    the suite verifies tokens against the real Rust HS256 codec rather than a stub.
 */
export default defineConfig({
  resolve: {
    alias: [
      {
        find: "server-only",
        replacement: fileURLToPath(new URL("./tests/server-only-stub.ts", import.meta.url)),
      },
      {
        find: /^.*bymax_auth_wasm\.js$/,
        replacement: fileURLToPath(new URL("./tests/wasm-node-glue.ts", import.meta.url)),
      },
    ],
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "tests/**/*.test.ts", "tests/**/*.test.tsx"],
    maxWorkers: "50%",
    minWorkers: 1,
  },
});
