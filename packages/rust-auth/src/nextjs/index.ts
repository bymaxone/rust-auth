/**
 * @fileoverview Public barrel for the `./nextjs` subpath: the edge JWT helpers, the
 * middleware proxy and its edge-safe request/cookie helpers, and the same-origin route
 * handlers. Every member here is server-only — the WASM verifier and the HS256 secret must
 * never reach a browser bundle.
 * @layer nextjs-server
 */

export {
  decodeJwtToken,
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken,
} from "./jwt";
export type { AuthJwtPayload, DecodedToken, JwtHeader } from "./jwt";

export {
  buildSilentRefreshUrl,
  createAuthProxy,
  dedupeSetCookieHeaders,
  getSetCookieHeaders,
  isBackgroundRequest,
  parseSetCookieHeader,
  resolveSafeDestination,
} from "./proxy";
export type {
  AuthProxyConfig,
  AuthProxyInstance,
  AuthProxyRoleRule,
  ParsedSetCookie,
  ResolvedAuthProxyConfig,
} from "./proxy";

export {
  CLIENT_REFRESH_ROUTE,
  createClientRefreshHandler,
  createLogoutHandler,
  createSilentRefreshHandler,
  LOGOUT_ROUTE,
  SILENT_REFRESH_ROUTE,
} from "./handlers";
export type { AuthHandlerConfig } from "./handlers";
