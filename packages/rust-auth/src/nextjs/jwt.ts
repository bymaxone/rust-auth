// This module receives the HS256 secret and loads the edge verifier; it must never reach a
// browser bundle. The `server-only` import makes a Client-Component import a build error.
import "server-only";

import type {
  DashboardJwtPayload,
  MfaTempPayload,
  PlatformJwtPayload,
} from "../shared/jwt-payload.types";

/**
 * @fileoverview Edge JWT helpers backed by the WASM verifier. `verifyJwtToken` runs the exact
 * Rust HS256 codec the backend signs with (authoritative); `decodeJwtToken` and the
 * decode-only fallback never check a signature and must never gate an authorization decision.
 *
 * The WASM glue self-initializes on import (its top-level `__wbindgen_start`), so it is loaded
 * lazily via a memoized dynamic `import()` on first use rather than at module load: importing
 * this module — or the `/nextjs` barrel — must have NO WASM side effect, so a Next build's
 * page-data collection (which cannot instantiate the edge WASM) can evaluate the barrel.
 * @layer nextjs-server
 */

/** The edge codec surface this module consumes from the bundled `bymax-auth-wasm` glue. */
type EdgeWasm = typeof import("../../wasm/bymax_auth_wasm.js");

/** The memoized in-flight (then resolved) WASM import; `undefined` until first use. */
let edgeWasm: Promise<EdgeWasm> | undefined;

/**
 * Load the edge WASM codec lazily and at most once. The dynamic `import()` defers the glue's
 * self-initialization to first use and caches the module namespace, so repeated calls share a
 * single wasm-init instance and importing this module stays side-effect-free.
 */
function loadEdgeWasm(): Promise<EdgeWasm> {
  edgeWasm ??= import("../../wasm/bymax_auth_wasm.js");
  return edgeWasm;
}

/** The three claim shapes the backend issues, discriminated by their `type` field. */
export type AuthJwtPayload = DashboardJwtPayload | PlatformJwtPayload | MfaTempPayload;

/** The decoded JOSE header of a compact JWS. */
export interface JwtHeader {
  /** The signature algorithm; always `HS256` for backend-issued tokens. */
  alg: string;
  /** The token type, typically `JWT`. */
  typ?: string;
}

/**
 * The result of decoding or verifying a token. `isValid` means "structurally decodable" for
 * {@link decodeJwtToken} and "signature + temporally valid" for the authoritative
 * {@link verifyJwtToken}. `payload`/`header` are present only when `isValid` is `true`.
 *
 * `isValid` alone must never gate an authorization decision: it is `true` on the decode-only
 * paths, where no signature was checked and the claims are whatever the bearer wrote. Gate on
 * {@link DecodedToken.signatureVerified} instead.
 */
export interface DecodedToken {
  /** Whether the token decoded (decode path) or verified (verify path) successfully. */
  isValid: boolean;
  /**
   * Whether the signature was actually checked against a secret.
   *
   * `true` only on the authoritative branch of {@link verifyJwtToken} — a real HS256
   * verification against a non-empty secret, with `exp`/`iat` and the `iss`/`aud` binding
   * enforced. `false` on every decode-only result, including the ones that carry a fully
   * populated `payload`.
   *
   * This flag exists because the two branches are otherwise indistinguishable at runtime:
   * a caller writing `if (decoded.isValid && decoded.payload.role === 'ADMIN')` — the natural
   * reading of a function called `verifyJwtToken` — would admit an unsigned token carrying an
   * arbitrary `sub`, `role`, `tenantId` and `status`. Any authorization decision reads this
   * field, not `isValid`.
   */
  signatureVerified: boolean;
  /** The claims, present when `isValid` is `true`. */
  payload?: AuthJwtPayload;
  /** The JOSE header, present for the decode-only paths. */
  header?: JwtHeader;
}

/** The `{ header, payload }` shape returned by the WASM `decode_jwt`. */
interface DecodedHeaderPayload {
  header: JwtHeader;
  payload: AuthJwtPayload;
}

/**
 * Decode a token's header and payload WITHOUT verifying its signature. Never throws: a
 * malformed token yields `{ isValid: false, signatureVerified: false }` — the flag is always
 * present, and always `false` here, since this function checks no signature. The result is non-authoritative — it proves
 * the token is well-formed, never that it is genuine — so it must not gate a decision.
 *
 * @param token - The compact JWS to decode.
 * @returns `{ isValid: true, signatureVerified: false, header, payload }` when decodable, else
 *   `{ isValid: false, signatureVerified: false }`. `signatureVerified` is `false` on every
 *   result this function can produce — it never checks a signature.
 */
export async function decodeJwtToken(token: string): Promise<DecodedToken> {
  try {
    const { decode_jwt } = await loadEdgeWasm();
    const raw = decode_jwt(token);
    if (raw === undefined) return { isValid: false, signatureVerified: false };
    const { header, payload } = JSON.parse(raw) as DecodedHeaderPayload;
    return { isValid: true, signatureVerified: false, header, payload };
  } catch {
    return { isValid: false, signatureVerified: false };
  }
}

/**
 * The `iss`/`aud` pair the backend was configured to stamp, when it was configured to stamp one.
 *
 * Pass it wherever `jwt.issuer` / `jwt.audience` are set on the backend. The backend refuses any
 * token that does not carry them; an edge that skips the check accepts tokens minted for a
 * different service, and with HS256 every holder of the secret is a potential minter. A token
 * carrying no such claim is refused as firmly as one carrying the wrong value, so omitting the
 * claim is not a way out of the check. Leave a field out only when the backend leaves it out.
 */
export interface TokenBinding {
  /** The `iss` the token must name. */
  issuer?: string | null;
  /** The `aud` the token must name. */
  audience?: string | null;
}

/**
 * Verify a token at the edge with the WASM HS256 verifier — it checks the signature, `exp`,
 * `iat` and the configured `iss`/`aud` binding, and rejects `none`/`RS256`/`ES256`. Never
 * throws: any failure resolves `{ isValid: false, signatureVerified: false }`.
 *
 * **A missing secret fails closed.** `null`, `undefined` and the empty string all make every
 * token invalid. This function used to fall back to a decode-only read, and that branch
 * returned the same shape with the same `isValid: true` — so a caller writing
 * `if (d.isValid && d.payload.role === 'ADMIN')`, the natural reading of the name, admitted a
 * token an attacker minted with `alg: none` and an arbitrary `sub`/`role`/`tenantId` the
 * moment the secret went missing. An unset environment variable was enough to arrange that. A
 * function that cannot verify must refuse rather than quietly answer a weaker question;
 * {@link decodeJwtToken} remains the explicit, correctly-named entry point for the
 * non-authoritative read.
 *
 * @param token - The compact JWS to verify.
 * @param secret - The HS256 secret. A missing or empty value makes every token invalid.
 * @param binding - The `iss`/`aud` pair the backend stamps. See {@link TokenBinding}.
 * @returns The verified {@link DecodedToken}. `signatureVerified` is `true` only when a
 *   signature was actually checked, and is the field an authorization decision reads.
 */
export async function verifyJwtToken(
  token: string,
  secret?: string | null,
  binding?: TokenBinding,
): Promise<DecodedToken> {
  // Fail closed on a missing or empty secret — see the doc comment above for rationale.
  if (typeof secret !== "string" || secret.length === 0) {
    return { isValid: false, signatureVerified: false };
  }
  try {
    const { verify_jwt_hs256 } = await loadEdgeWasm();
    const raw = verify_jwt_hs256(
      token,
      secret,
      undefined,
      binding?.issuer ?? undefined,
      binding?.audience ?? undefined,
    );
    if (raw === undefined) return { isValid: false, signatureVerified: false };
    return {
      isValid: true,
      signatureVerified: true,
      payload: JSON.parse(raw) as AuthJwtPayload,
    };
  } catch {
    return { isValid: false, signatureVerified: false };
  }
}

/** Current Unix time in whole seconds. */
function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Whether a decoded token is expired (or carries no usable `exp`). A token that did not decode,
 * or has no numeric `exp`, is treated as expired so callers fail closed.
 *
 * @param token - A {@link DecodedToken} from {@link decodeJwtToken} / {@link verifyJwtToken}.
 * @returns `true` when the token is expired or has no `exp`.
 */
export function isTokenExpired(token: DecodedToken): boolean {
  const exp = token.payload?.exp;
  if (typeof exp !== "number") return true;
  return exp <= nowUnixSeconds();
}

/**
 * The subject (user id) of a decoded token.
 *
 * @param token - A {@link DecodedToken}.
 * @returns The `sub` claim, or `''` when absent.
 */
export function getUserId(token: DecodedToken): string {
  return token.payload?.sub ?? "";
}

/**
 * The authorization role of a decoded token. MFA-temp tokens carry no role.
 *
 * @param token - A {@link DecodedToken}.
 * @returns The `role` claim, or `''` when the token has no role.
 */
export function getUserRole(token: DecodedToken): string {
  const payload = token.payload;
  if (payload && "role" in payload) return payload.role;
  return "";
}

/**
 * The tenant scope of a decoded token. Only dashboard tokens are tenant-scoped.
 *
 * @param token - A {@link DecodedToken}.
 * @returns The `tenantId` claim, or `undefined` for platform / MFA-temp tokens.
 */
export function getTenantId(token: DecodedToken): string | undefined {
  const payload = token.payload;
  if (payload && "tenantId" in payload) return payload.tenantId;
  return undefined;
}
