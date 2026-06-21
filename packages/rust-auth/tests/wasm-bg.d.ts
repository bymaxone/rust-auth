/**
 * @fileoverview Ambient types for the generated wasm-bindgen `*_bg.js` glue, which ships no
 * declaration file. Only the members the Node test shim instantiates and re-exports are
 * declared. The wildcard specifier matches the relative `../wasm/bymax_auth_wasm_bg.js` import.
 */
declare module "*bymax_auth_wasm_bg.js" {
  /** Wire the instantiated wasm exports into the glue (called once after instantiation). */
  export function __wbg_set_wasm(value: unknown): void;
  /** Decode-only header+payload projection; `undefined` when malformed. */
  export function decode_jwt(token: string): string | undefined;
  /** Decode-only typed-claims projection; `undefined` when malformed/unknown type. */
  export function extract_claims(token: string): string | undefined;
  /** Authoritative HS256 verification; claims JSON when valid, else `undefined`. */
  export function verify_jwt_hs256(
    token: string,
    secret: string,
    leewaySecs?: bigint | null,
  ): string | undefined;
}
