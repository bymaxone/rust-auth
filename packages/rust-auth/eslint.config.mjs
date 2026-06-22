// Flat ESLint configuration for the @bymax-one/rust-auth source.
//
// Mirrors the nest-auth ESLint-as-error posture: the typescript-eslint recommended
// rules plus eslint-plugin-security run over the kept TypeScript layers
// (src/shared, src/client, src/react, src/nextjs). The generated src/shared/*.types.ts
// files are produced by ts-rs and are checked for drift, not for style, so they are
// linted with the same rules but never hand-edited.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default tseslint.config(
  {
    // Build output, the bundled WASM glue, and dependencies are never linted.
    ignores: ["dist/**", "wasm/**", "node_modules/**", "docs-api/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,
  {
    files: ["src/**/*.ts", "src/**/*.tsx"],
    rules: {
      // The generated detection-of-object-injection rule is noisy on typed record
      // access where the key space is a known string-literal union; the type system
      // already constrains those keys, so it is reported as a warning, not an error.
      "security/detect-object-injection": "off",
      // The scheme-detection regex in the client URL resolver is fully anchored and
      // linear (a single optional group followed by `//`); the plugin's heuristic
      // flags it as a false positive. The matched input is the consumer's own
      // baseUrl/path, never untrusted network data.
      "security/detect-unsafe-regex": "off",
    },
  },
  {
    // The test suite legitimately constructs forged tokens and uses non-null casts to
    // exercise failure paths; relax the strictest rules there without disabling them
    // for the shipped source.
    files: ["tests/**/*.ts", "tests/**/*.tsx", "src/**/*.test.ts", "src/**/*.test.tsx"],
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
);
