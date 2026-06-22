/**
 * Pre-publish npm smoke for @bymax-one/rust-auth.
 *
 * It consumes the installed package (the real published layout via `file:`) and proves
 * the to-be-shipped frontend surface works:
 *
 *  1. the four subpaths import and the public symbols are present (a layout/exports
 *     regression fails here);
 *  2. a token signed by the backend's HS256 (reproduced with Node `crypto`) verifies at
 *     the edge through the shipped WASM, and a wrong-secret / tampered / expired token
 *     is rejected — server/edge parity.
 *
 * The edge `verifyJwtToken` loads the bundler-target WASM wrapper, whose direct `.wasm`
 * import a plain Node process cannot resolve; this smoke instantiates the SAME shipped
 * `*_bg.wasm` through the generated glue (mirroring the package's own Node test shim),
 * so it exercises the real Rust verifier rather than a stub.
 */
import { createHmac } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

// 1. The published subpaths must import and expose their public surface. The
// browser-safe layers (./client, ./shared) are imported as values; ./nextjs is
// server-only (it guards with the `server-only` package, which throws outside a React
// Server Component), so its surface is imported type-only — the typecheck proves the
// subpath and its types resolve, while the WASM edge verifier is exercised directly
// below against the shipped artefact.
import { createAuthClient, createAuthFetch } from "@bymax-one/rust-auth/client";
import { AUTH_ACCESS_COOKIE_NAME, AuthClientError } from "@bymax-one/rust-auth/shared";
import type { createAuthProxy, decodeJwtToken } from "@bymax-one/rust-auth/nextjs";

const SECRET = "a-smoke-edge-hs256-secret-key-0123456789";

/** base64url without padding — the JWS segment encoding. */
function b64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Sign a compact HS256 JWS exactly as the Rust backend does. */
function signHs256(payload: Record<string, unknown>, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signature = b64url(createHmac("sha256", secret).update(signingInput).digest());
  return `${signingInput}.${signature}`;
}

/** Instantiate the shipped `*_bg.wasm` through the generated glue (Node-loadable). */
async function loadWasm(): Promise<{
  verify_jwt_hs256: (token: string, secret: string, leeway?: bigint | null) => string | undefined;
}> {
  // The `wasm/` assets are shipped in the package's `files` but are not an exports
  // subpath. The exports map also hides `./package.json`, so resolve a known subpath
  // (`./shared` -> dist/shared/index.mjs) and walk up to the package root.
  const require = createRequire(import.meta.url);
  const sharedEntry = require.resolve("@bymax-one/rust-auth/shared");
  // dist/shared/index.mjs -> dist/shared -> dist -> <package root>
  const pkgRoot = dirname(dirname(dirname(sharedEntry)));
  const wasmDir = join(pkgRoot, "wasm");
  const wrapperPath = join(wasmDir, "bymax_auth_wasm_bg.js");
  const bg = (await import(wrapperPath)) as {
    __wbg_set_wasm: (exports: unknown) => void;
    verify_jwt_hs256: (token: string, secret: string, leeway?: bigint | null) => string | undefined;
  };

  const wasmBytes = readFileSync(join(wasmDir, "bymax_auth_wasm_bg.wasm"));
  const wasmModule = new WebAssembly.Module(wasmBytes);
  const imports: WebAssembly.Imports = {};
  for (const descriptor of WebAssembly.Module.imports(wasmModule)) {
    imports[descriptor.module] = bg as unknown as WebAssembly.ModuleImports;
  }
  const instance = new WebAssembly.Instance(wasmModule, imports);
  bg.__wbg_set_wasm(instance.exports);
  const start = instance.exports.__wbindgen_start;
  if (typeof start === "function") start();
  return { verify_jwt_hs256: bg.verify_jwt_hs256 };
}

async function main(): Promise<void> {
  // The browser-safe subpath symbols exist (a missing export throws at import).
  assert.equal(typeof createAuthClient, "function");
  assert.equal(typeof createAuthFetch, "function");
  assert.equal(AUTH_ACCESS_COOKIE_NAME, "access_token");
  assert.equal(typeof AuthClientError, "function");
  // The ./nextjs surface is referenced type-only (it is server-only at runtime); these
  // bindings prove the types resolve without importing the server-guarded module.
  type ProxyFactory = typeof createAuthProxy;
  type Decoder = typeof decodeJwtToken;
  const _proxyType: ProxyFactory | undefined = undefined;
  const _decoderType: Decoder | undefined = undefined;
  void _proxyType;
  void _decoderType;

  const now = Math.floor(Date.now() / 1000);
  const claims = {
    sub: "u_smoke",
    jti: "jti_smoke",
    tenantId: "t_smoke",
    role: "member",
    type: "dashboard",
    status: "active",
    mfaEnabled: false,
    mfaVerified: false,
    iat: now,
    exp: now + 300,
  };
  const token = signHs256(claims, SECRET);

  const { verify_jwt_hs256 } = await loadWasm();

  // A valid backend-signed token verifies at the edge and yields the claims.
  const verified = verify_jwt_hs256(token, SECRET, null);
  assert.ok(verified, "a valid backend-signed token must verify at the edge");
  const decoded = JSON.parse(verified) as { sub: string; tenantId: string };
  assert.equal(decoded.sub, "u_smoke");
  assert.equal(decoded.tenantId, "t_smoke");

  // A wrong secret, a tampered signature, and an expired token are all rejected.
  assert.equal(verify_jwt_hs256(token, "the-wrong-secret-the-wrong-secret-xx", null), undefined);
  const tampered = `${token.slice(0, -2)}xx`;
  assert.equal(verify_jwt_hs256(tampered, SECRET, null), undefined);
  const expired = signHs256({ ...claims, iat: now - 600, exp: now - 300 }, SECRET);
  assert.equal(verify_jwt_hs256(expired, SECRET, null), undefined);

  console.log("npm smoke OK — server/edge HS256 parity verified against the shipped wasm.");
}

main().catch((error: unknown) => {
  console.error("npm smoke FAILED:", error);
  process.exit(1);
});
