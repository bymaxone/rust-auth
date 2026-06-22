/**
 * @fileoverview Node-loadable instantiation of the bundler-target edge wasm, used only by the
 * test runner. The shipped `wasm/bymax_auth_wasm.js` wrapper imports the `.wasm` binary
 * directly, which Node/Vitest cannot resolve; this shim instantiates the SAME `*_bg.wasm`
 * artifact synchronously through the generated `*_bg.js` glue and re-exports the three edge
 * functions, so the suite exercises the real Rust verifier — not a stub. Vitest aliases the
 * `bymax_auth_wasm.js` wrapper to this module.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as bg from "../wasm/bymax_auth_wasm_bg.js";

// Resolve the wasm binary from this module's directory using the standard, portable
// `fileURLToPath(import.meta.url)` form (not the non-standard `import.meta.dirname`). The
// bare `import.meta.url` is used deliberately: the `new URL(rel, import.meta.url)` pattern is
// rewritten by Vite into an asset URL, which breaks plain `readFileSync` under the test alias.
const moduleDir = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(join(moduleDir, "..", "wasm", "bymax_auth_wasm_bg.wasm"));
const wasmModule = new WebAssembly.Module(wasmBytes);

// The wasm imports its host functions from a single module (`./bymax_auth_wasm_bg.js`); map
// every declared import module to the glue namespace so instantiation is name-agnostic.
const importObject: WebAssembly.Imports = {};
for (const descriptor of WebAssembly.Module.imports(wasmModule)) {
  importObject[descriptor.module] = bg as unknown as WebAssembly.ModuleImports;
}

const instance = new WebAssembly.Instance(wasmModule, importObject);
bg.__wbg_set_wasm(instance.exports);
const start = instance.exports.__wbindgen_start;
if (typeof start === "function") {
  start();
}

/** Authoritative HS256 verification (real Rust codec), re-exported for the suite. */
export const verify_jwt_hs256 = bg.verify_jwt_hs256;
/** Decode-only header+payload projection. */
export const decode_jwt = bg.decode_jwt;
/** Decode-only typed-claims projection. */
export const extract_claims = bg.extract_claims;
