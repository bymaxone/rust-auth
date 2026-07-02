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
import {
  dedupeSetCookieHeaders,
  getSetCookieHeaders,
  resolveSafeDestination,
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
}

/** The fully-resolved handler configuration. */
interface ResolvedHandlerConfig {
  backendUrl: string;
  routePrefix: string;
  loginPath: string;
}

/** Apply defaults and strip a trailing slash from the backend origin. */
function resolveHandlerConfig(config: AuthHandlerConfig): ResolvedHandlerConfig {
  return {
    backendUrl: config.backendUrl.replace(/\/+$/, ""),
    routePrefix: config.routePrefix ?? AUTH_ROUTE_PREFIX,
    loginPath: config.loginPath ?? DEFAULT_LOGIN_PATH,
  };
}

/** Rebase a default `/auth/...` route path onto the configured mount prefix. */
function rebaseRoute(routePath: string, routePrefix: string): string {
  const from = `/${AUTH_ROUTE_PREFIX}`;
  if (routePrefix === AUTH_ROUTE_PREFIX) return routePath;
  const to = `/${routePrefix.replace(/^\/+|\/+$/g, "")}`;
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
    return await fetch(`${config.backendUrl}${rebaseRoute(routePath, config.routePrefix)}`, {
      method: "POST",
      headers: { cookie: request.headers.get("cookie") ?? "" },
    });
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

/** Expire the three session cookies on an outgoing response. */
function clearSessionCookies(response: NextResponse): void {
  response.cookies.set(AUTH_ACCESS_COOKIE_NAME, "", { path: "/", maxAge: 0 });
  response.cookies.set(AUTH_HAS_SESSION_COOKIE_NAME, "", { path: "/", maxAge: 0 });
  response.cookies.set(AUTH_REFRESH_COOKIE_NAME, "", {
    path: AUTH_REFRESH_COOKIE_PATH,
    maxAge: 0,
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
    const origin = request.nextUrl.origin;
    const destination = resolveSafeDestination(
      request.nextUrl.searchParams.get("redirectTo"),
      origin,
      resolved.loginPath,
    );

    const backendResponse = await callBackend(resolved, AUTH_ROUTES.REFRESH, request);
    if (!backendResponse || !backendResponse.ok) {
      const failure = NextResponse.redirect(buildLoginUrl(resolved.loginPath, origin));
      clearSessionCookies(failure);
      return failure;
    }

    const success = NextResponse.redirect(new URL(destination, origin));
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
    const backendResponse = await callBackend(resolved, AUTH_ROUTES.REFRESH, request);
    if (!backendResponse || !backendResponse.ok) {
      return NextResponse.json(
        { error: { code: AUTH_ERROR_CODES.SESSION_EXPIRED, message: "Session expired." } },
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
    await callBackend(resolved, AUTH_ROUTES.LOGOUT, request);
    const response = NextResponse.json({ ok: true }, { status: 200 });
    clearSessionCookies(response);
    return response;
  };
}

/** Build a sign-in URL carrying the `expired` reason. */
function buildLoginUrl(loginPath: string, origin: string): URL {
  const url = new URL(loginPath, origin);
  url.searchParams.set("reason", "expired");
  return url;
}
