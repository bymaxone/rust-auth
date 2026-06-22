/**
 * @fileoverview The same-origin Next route paths the proxy bounces through and the handlers
 * mount on. Kept in one place so the proxy (which redirects to silent-refresh) and the
 * handlers (which mount these routes) share a single source of truth without a cyclic import.
 * @layer nextjs-server
 */

/** The route that performs a cookie-to-cookie silent refresh, then redirects to the target. */
export const SILENT_REFRESH_ROUTE = "/api/auth/silent-refresh";

/** The route the client fetch wrapper POSTs to for a single-flight 401 refresh. */
export const CLIENT_REFRESH_ROUTE = "/api/auth/client-refresh";

/** The route that clears the session cookies and proxies a backend logout. */
export const LOGOUT_ROUTE = "/api/auth/logout";
