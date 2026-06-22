import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "tsup";

/**
 * Dual ESM + CJS build, one entry per published subpath. `./shared`, `./client`, and
 * `./react` are pure TypeScript; `./nextjs` is WASM-backed and keeps the bundled
 * `bymax-auth-wasm` glue (under `wasm/`) external so the single wasm-init instance is
 * preserved (see the scoped `sideEffects` in package.json). A post-build check asserts
 * every subpath emitted its three artefacts (`.mjs`/`.cjs`/`.d.ts`).
 */
export default defineConfig({
  entry: {
    "shared/index": "src/shared/index.ts",
    "client/index": "src/client/index.ts",
    "react/index": "src/react/index.ts",
    "nextjs/index": "src/nextjs/index.ts",
  },
  format: ["esm", "cjs"],
  outDir: "dist",
  outExtension: ({ format }) => ({ js: format === "esm" ? ".mjs" : ".cjs" }),
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  splitting: false,
  // React/Next and the bundled wasm glue must never be inlined into the output.
  external: [
    "react",
    "react-dom",
    "next",
    "next/server",
    "server-only",
    /^\.\.\/wasm\//,
    /bymax_auth_wasm/,
  ],
  onSuccess: async () => {
    const subpaths = ["shared", "client", "react", "nextjs"];
    const targets = subpaths.flatMap((sub) =>
      [".mjs", ".cjs", ".d.ts"].map((ext) => `dist/${sub}/index${ext}`),
    );
    // The `.d.ts` files come from tsup's separate (parallel) declaration build, which can
    // finish after this hook fires; poll briefly so the check observes the final output
    // rather than racing the declaration emit.
    const deadline = Date.now() + 15_000;
    let missing: string[] = targets;
    while (missing.length > 0 && Date.now() < deadline) {
      missing = targets.filter((file) => !existsSync(resolve(file)));
      if (missing.length > 0) {
        await new Promise((done) => setTimeout(done, 100));
      }
    }
    if (missing.length > 0) {
      throw new Error(`build-integrity: missing artefacts: ${missing.join(", ")}`);
    }
  },
});
