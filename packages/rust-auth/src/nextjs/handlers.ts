/**
 * @fileoverview The same-origin Next route handlers that bridge the browser's cookie session
 * to the rust-auth backend: a silent refresh (cookie-to-cookie, then redirect), a client
 * refresh (JSON for the fetch wrapper), and a logout. Each forwards the request cookies to
 * the backend and relays the backend's rotated `Set-Cookie` headers back, deduplicated.
 * @layer nextjs-server
 */

// The explicit `.js` extension keeps `next/server` resolvable when the built package is
// externalized and loaded by Node's native ESM resolver (see the note in `proxy.ts`): `next`
// ships no `exports` map, so Node ESM cannot resolve the extensionless subpath.
import { NextResponse } from "next/server.js";
import type { NextRequest } from "next/server.js";

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_PATH,
} from "../shared/cookie-defaults";
import { AUTH_ERROR_CODES } from "../shared/error-codes";
import { AUTH_ROUTE_PREFIX, AUTH_ROUTES } from "../shared/routes";
import { trimSlashes, trimTrailingSlashes } from "../shared/trim-slashes";
import {
  dedupeSetCookieHeaders,
  getSetCookieHeaders,
  NO_STORE_CACHE_CONTROL,
  resolveSafeDestination,
  toSameOriginPath,
} from "./proxy";

export {
  CLIENT_REFRESH_ROUTE,
  LOGOUT_ROUTE,
  SILENT_REFRESH_ROUTE,
} from "./edge-routes";

/** The default sign-in path a failed silent refresh redirects to. */
const DEFAULT_LOGIN_PATH = "/login";

/** Configuration shared by the three route-handler factories. */
export interface AuthHandlerConfig {
  /** The absolute origin of the rust-auth backend (e.g. `https://api.example.com`). */
  backendUrl: string;
  /** The backend mount prefix used to rebase the proxied routes. Defaults to `'auth'`. */
  routePrefix?: string;
  /** The sign-in path a failed silent refresh redirects to. Defaults to `/login`. */
  loginPath?: string;
  /**
   * The cookie `Domain` the backend planted the session with, when `cookies.resolve_domains` is
   * configured there. Leave unset for the host-only default.
   *
   * A browser matches a deletion on **name, domain AND path** (RFC 6265 §5.3). The clears below
   * used to emit no `Domain` at all, so on a subdomain-sharing deployment they created a new
   * host-only cookie and the `Domain=`-scoped originals survived the logout. The Rust half gets
   * this right — `clear_session` reuses `self.domain()` for exactly this reason — and this half
   * had no way to. The backend session is revoked either way, so what survived was a dead
   * credential in the jar plus a stale `has_session` driving pointless silent-refresh bounces.
   */
  cookieDomain?: string;
}

/** The fully-resolved handler configuration. */
interface ResolvedHandlerConfig {
  backendUrl: string;
  routePrefix: string;
  loginPath: string;
  cookieDomain: string | undefined;
}

/** Apply defaults and strip a trailing slash from the backend origin. */
function resolveHandlerConfig(
  config: AuthHandlerConfig,
): ResolvedHandlerConfig {
  return {
    backendUrl: trimTrailingSlashes(config.backendUrl),
    routePrefix: config.routePrefix ?? AUTH_ROUTE_PREFIX,
    loginPath: config.loginPath ?? DEFAULT_LOGIN_PATH,
    cookieDomain: config.cookieDomain,
  };
}

/** Rebase a default `/auth/...` route path onto the configured mount prefix. */
function rebaseRoute(routePath: string, routePrefix: string): string {
  const from = `/${AUTH_ROUTE_PREFIX}`;
  if (routePrefix === AUTH_ROUTE_PREFIX) return routePath;
  const to = `/${trimSlashes(routePrefix)}`;
  return routePath.startsWith(`${from}/`) || routePath === from
    ? `${to}${routePath.slice(from.length)}`
    : routePath;
}

/** Run a backend call, returning `null` instead of throwing on a transport failure. */
async function callBackend(
  config: ResolvedHandlerConfig,
  routePath: string,
  request: NextRequest,
): Promise<Response | null> {
  try {
    return await fetch(
      `${config.backendUrl}${rebaseRoute(routePath, config.routePrefix)}`,
      {
        method: "POST",
        headers: { cookie: request.headers.get("cookie") ?? "" },
      },
    );
  } catch {
    return null;
  }
}

/** Append the backend's rotated `Set-Cookie` headers (deduplicated) onto an outgoing response. */
function forwardSetCookies(from: Headers, to: NextResponse): void {
  for (const cookie of dedupeSetCookieHeaders(getSetCookieHeaders(from))) {
    to.headers.append("set-cookie", cookie);
  }
}

/**
 * Expire the three session cookies on an outgoing response.
 *
 * `domain` is carried through because a browser matches a deletion on name, domain AND path: a
 * clear that omits it cannot remove a cookie that was planted with one. See
 * {@link AuthHandlerConfig.cookieDomain}.
 */
function clearSessionCookies(
  response: NextResponse,
  domain: string | undefined,
): void {
  response.cookies.set(AUTH_ACCESS_COOKIE_NAME, "", {
    path: "/",
    maxAge: 0,
    domain,
  });
  response.cookies.set(AUTH_HAS_SESSION_COOKIE_NAME, "", {
    path: "/",
    maxAge: 0,
    domain,
  });
  response.cookies.set(AUTH_REFRESH_COOKIE_NAME, "", {
    path: AUTH_REFRESH_COOKIE_PATH,
    maxAge: 0,
    domain,
  });
}

/**
 * `Sec-Fetch-Site` values that prove a request did not come from another site. `same-origin` is
 * the app calling itself; `none` is a user-initiated navigation, which no attacker page causes.
 */
const SAFE_FETCH_SITES = new Set(["same-origin", "none"]);

/**
 * Whether the browser has stated this request came from another site.
 *
 * Every handler below ends by writing `Set-Cookie`, so a cross-site caller gets something out of
 * them without ever reading the response — which is what made them reachable with no CORS
 * cooperation. `POST /api/auth/logout` from an attacker's page sends no session cookie under
 * `Lax`, so the backend revocation no-ops, but the handler cleared the browser's cookies anyway;
 * a form POST is a top-level navigation, so they were applied first-party. Any page on the
 * internet could sign a visitor out, repeatably. The silent-refresh GET is the same shape from
 * an `<img>`.
 *
 * The decision is `Sec-Fetch-Site` alone. `Origin` cannot make it: a same-origin request sends
 * one too, and a route handler has no configured notion of its own origin — `nextUrl.origin`
 * derives from `Host`, which the client controls. `Sec-Fetch-Site` is unforgeable by a page and
 * shipped in Chrome 76, Firefox 90 and Safari 16.4; a request without it is an older browser or
 * a non-browser client, admitted for the same reason the backend's origin layer admits it.
 *
 * @param request - The incoming request.
 * @returns `true` when the request announced itself as cross-site.
 */
function isCrossSiteRequest(request: NextRequest): boolean {
  const fetchSite = request.headers.get("sec-fetch-site");
  return fetchSite !== null && !SAFE_FETCH_SITES.has(fetchSite);
}

/** The response a cross-site caller gets: no body, no cookies, nothing cacheable. */
function crossSiteRefused(): NextResponse {
  return new NextResponse(null, {
    status: 403,
    headers: { "cache-control": NO_STORE_CACHE_CONTROL },
  });
}

/**
 * Build the silent-refresh route handler: proxy a backend refresh using the request cookies,
 * relay the rotated cookies, and redirect to the (open-redirect-guarded) destination. On a
 * failed refresh it clears the session cookies and redirects to the sign-in page.
 *
 * @param config - The handler configuration; see {@link AuthHandlerConfig}.
 * @returns A Next route handler.
 */
export function createSilentRefreshHandler(
  config: AuthHandlerConfig,
): (request: NextRequest) => Promise<NextResponse> {
  const resolved = resolveHandlerConfig(config);
  return async (request) => {
    if (isCrossSiteRequest(request)) return crossSiteRefused();

    const origin = request.nextUrl.origin;
    const destination = resolveSafeDestination(
      request.nextUrl.searchParams.get("redirectTo"),
      origin,
      resolved.loginPath,
    );

    const backendResponse = await callBackend(
      resolved,
      AUTH_ROUTES.REFRESH,
      request,
    );
    if (!backendResponse || !backendResponse.ok) {
      const failure = NextResponse.redirect(
        buildLoginUrl(resolved.loginPath, origin),
      );
      clearSessionCookies(failure, resolved.cookieDomain);
      return failure;
    }

    // Reduced again on the way out. `resolveSafeDestination` already guarantees a same-origin
    // path, but this is the line that turns a string into a `Location`, and the guarantee a
    // redirect needs belongs to the code that writes the header rather than to the discipline of
    // whoever called it. Resolving against an origin is what makes a smuggled authority
    // (`//host`, which a path-shaped value can still be) into a redirect off-site.
    const success = NextResponse.redirect(new URL(toSameOriginPath(destination), origin));
    forwardSetCookies(backendResponse.headers, success);
    return success;
  };
}

/**
 * Build the client-refresh route handler: proxy a backend refresh and return its JSON body
 * with the rotated cookies relayed. This is the endpoint the client fetch wrapper POSTs to on
 * a 401. A failed refresh returns a `401` with the standard error envelope.
 *
 * @param config - The handler configuration; see {@link AuthHandlerConfig}.
 * @returns A Next route handler.
 */
export function createClientRefreshHandler(
  config: AuthHandlerConfig,
): (request: NextRequest) => Promise<NextResponse> {
  const resolved = resolveHandlerConfig(config);
  return async (request) => {
    if (isCrossSiteRequest(request)) return crossSiteRefused();

    const backendResponse = await callBackend(
      resolved,
      AUTH_ROUTES.REFRESH,
      request,
    );
    if (!backendResponse || !backendResponse.ok) {
      return NextResponse.json(
        // The code the BACKEND answers a failed rotation with. It used to be
        // `auth.session_expired`, which no backend ever sends — a client branching on it here
        // and on the real code everywhere else was branching on a code that only this proxy
        // invented.
        {
          error: {
            code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID,
            message: "Session expired.",
          },
        },
        { status: 401 },
      );
    }

    const body = await backendResponse.text();
    const response = new NextResponse(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    forwardSetCookies(backendResponse.headers, response);
    return response;
  };
}

/**
 * Build the logout route handler: best-effort proxy a backend logout, then clear the local
 * session cookies and resolve `200`.
 *
 * @param config - The handler configuration; see {@link AuthHandlerConfig}.
 * @returns A Next route handler.
 */
export function createLogoutHandler(
  config: AuthHandlerConfig,
): (request: NextRequest) => Promise<NextResponse> {
  const resolved = resolveHandlerConfig(config);
  return async (request) => {
    if (isCrossSiteRequest(request)) return crossSiteRefused();

    await callBackend(resolved, AUTH_ROUTES.LOGOUT, request);
    const response = NextResponse.json({ ok: true }, { status: 200 });
    clearSessionCookies(response, resolved.cookieDomain);
    return response;
  };
}

/** Build a sign-in URL carrying the `expired` reason. */
function buildLoginUrl(loginPath: string, origin: string): URL {
  const url = new URL(loginPath, origin);
  url.searchParams.set("reason", "expired");
  return url;
}
