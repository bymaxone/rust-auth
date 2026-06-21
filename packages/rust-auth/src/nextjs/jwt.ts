// This module receives the HS256 secret and loads the edge verifier; it must never reach a
// browser bundle. The `server-only` import makes a Client-Component import a build error.
import "server-only";

import { decode_jwt, verify_jwt_hs256 } from "../../wasm/bymax_auth_wasm.js";
import type {
  DashboardJwtPayload,
  MfaTempPayload,
  PlatformJwtPayload,
} from "../shared/jwt-payload.types";

/**
 * @fileoverview Edge JWT helpers backed by the WASM verifier. `verifyJwtToken` runs the exact
 * Rust HS256 codec the backend signs with (authoritative); `decodeJwtToken` and the
 * decode-only fallback never check a signature and must never gate an authorization decision.
 * @layer nextjs-server
 */

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
 */
export interface DecodedToken {
  /** Whether the token decoded (decode path) or verified (verify path) successfully. */
  isValid: boolean;
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
 * malformed token yields `{ isValid: false }`. The result is non-authoritative — it proves
 * the token is well-formed, never that it is genuine — so it must not gate a decision.
 *
 * @param token - The compact JWS to decode.
 * @returns `{ isValid: true, header, payload }` when decodable, else `{ isValid: false }`.
 */
export function decodeJwtToken(token: string): DecodedToken {
  try {
    const raw = decode_jwt(token);
    if (raw === undefined) return { isValid: false };
    const { header, payload } = JSON.parse(raw) as DecodedHeaderPayload;
    return { isValid: true, header, payload };
  } catch {
    return { isValid: false };
  }
}

/**
 * Verify a token at the edge. When `secret` is a non-empty string, the WASM HS256 verifier is
 * authoritative — it checks the signature, `exp`, and `iat`, and rejects `none`/`RS256`/`ES256`.
 * When `secret` is `null`/`undefined`, it falls back to a decode-only read (non-authoritative).
 * Never throws: any failure resolves `{ isValid: false }`.
 *
 * @param token - The compact JWS to verify.
 * @param secret - The HS256 secret for authoritative verification, or `null`/`undefined` to
 *   decode only.
 * @returns The verified (or decoded) {@link DecodedToken}.
 */
export async function verifyJwtToken(
  token: string,
  secret?: string | null,
): Promise<DecodedToken> {
  try {
    if (typeof secret === "string" && secret.length > 0) {
      const raw = verify_jwt_hs256(token, secret);
      if (raw === undefined) return { isValid: false };
      return { isValid: true, payload: JSON.parse(raw) as AuthJwtPayload };
    }
    const raw = decode_jwt(token);
    if (raw === undefined) return { isValid: false };
    const { header, payload } = JSON.parse(raw) as DecodedHeaderPayload;
    return { isValid: true, header, payload };
  } catch {
    return { isValid: false };
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
