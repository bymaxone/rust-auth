/**
 * @fileoverview The edge middleware proxy and its edge-safe request/cookie helpers. The proxy
 * verifies the access token with the WASM verifier and applies the nest-auth security
 * patterns: background-request detection, a redirect-loop counter, an `expired` redirect
 * reason, the `has_session` silent-refresh signal, status blocking, RBAC, and UI-only
 * `x-user-*` propagation headers. A token is never placed in a URL.
 * @layer nextjs-server
 */

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_VALUE,
} from "../shared/cookie-defaults";
import { AUTH_ROUTE_PREFIX } from "../shared/routes";
import { SILENT_REFRESH_ROUTE } from "./edge-routes";
import {
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken,
} from "./jwt";

/** The query parameter that counts redirect bounces, used to break refresh loops. */
const REDIRECT_COUNT_PARAM = "_r";

/** The default sign-in path unauthenticated users are redirected to. */
const DEFAULT_LOGIN_PATH = "/login";

/** The default ceiling on redirect bounces before the proxy stops trying to recover. */
const DEFAULT_MAX_REDIRECTS = 3;

/** A single RBAC rule: the roles permitted under a path prefix. */
export interface AuthProxyRoleRule {
  /** The path prefix this rule guards (e.g. `/admin`). */
  pathPrefix: string;
  /** The roles allowed to access matched paths. */
  roles: readonly string[];
}

/** Configuration for {@link createAuthProxy}. Every field is optional. */
export interface AuthProxyConfig {
  /** Where to send unauthenticated users. Defaults to `/login`. */
  loginPath?: string;
  /** The HS256 secret for authoritative token verification; `null` decodes only (weaker). */
  accessTokenSecret?: string | null;
  /** Path prefixes that bypass auth entirely (e.g. `/_next`, `/public`). */
  publicPaths?: readonly string[];
  /** RBAC rules applied to the first matching `pathPrefix`. */
  roleRules?: readonly AuthProxyRoleRule[];
  /** Account statuses denied access to protected routes (e.g. `SUSPENDED`, `BANNED`). */
  blockedStatuses?: readonly string[];
  /** The same-origin route used to attempt a silent refresh. Defaults to the silent-refresh route. */
  silentRefreshPath?: string;
  /** The redirect-bounce ceiling before giving up. Defaults to `3`. */
  maxRedirects?: number;
  /** The backend mount prefix (reserved for prefix-aware extensions). Defaults to `'auth'`. */
  routePrefix?: string;
}

/** The fully-resolved proxy configuration, with every default applied. */
export interface ResolvedAuthProxyConfig {
  /** The resolved sign-in path. */
  loginPath: string;
  /** The resolved HS256 secret, or `null` for decode-only mode. */
  accessTokenSecret: string | null;
  /** The resolved public path-prefix list. */
  publicPaths: readonly string[];
  /** The resolved RBAC rules. */
  roleRules: readonly AuthProxyRoleRule[];
  /** The resolved blocked-status list. */
  blockedStatuses: readonly string[];
  /** The resolved silent-refresh route. */
  silentRefreshPath: string;
  /** The resolved redirect-bounce ceiling. */
  maxRedirects: number;
  /** The resolved backend mount prefix. */
  routePrefix: string;
}

/**
 * A proxy instance. The object is destructurable as `const { proxy } = createAuthProxy(...)`,
 * so it can be re-exported directly as a Next middleware `export const middleware = proxy`.
 */
export interface AuthProxyInstance {
  /** The middleware function: verify the request and return a `next`/redirect response. */
  readonly proxy: (request: NextRequest) => Promise<NextResponse>;
  /** The fully-resolved configuration driving this instance. */
  readonly config: ResolvedAuthProxyConfig;
}

/** Apply every default to a partial {@link AuthProxyConfig}. */
function resolveConfig(config: AuthProxyConfig): ResolvedAuthProxyConfig {
  return {
    loginPath: config.loginPath ?? DEFAULT_LOGIN_PATH,
    accessTokenSecret: config.accessTokenSecret ?? null,
    publicPaths: config.publicPaths ?? [],
    roleRules: config.roleRules ?? [],
    blockedStatuses: config.blockedStatuses ?? [],
    silentRefreshPath: config.silentRefreshPath ?? SILENT_REFRESH_ROUTE,
    maxRedirects: config.maxRedirects ?? DEFAULT_MAX_REDIRECTS,
    routePrefix: config.routePrefix ?? AUTH_ROUTE_PREFIX,
  };
}

/**
 * Build an edge middleware proxy that gates protected routes on a verified access token.
 *
 * @param config - The proxy configuration; see {@link AuthProxyConfig}.
 * @returns An {@link AuthProxyInstance} exposing `proxy` and the resolved `config`.
 */
export function createAuthProxy(config: AuthProxyConfig): AuthProxyInstance {
  const resolved = resolveConfig(config);

  const proxy = async (request: NextRequest): Promise<NextResponse> => {
    const { pathname } = request.nextUrl;
    if (isPublicPath(pathname, resolved.publicPaths)) {
      return NextResponse.next();
    }

    const token = request.cookies.get(AUTH_ACCESS_COOKIE_NAME)?.value;
    const decoded = token
      ? await verifyJwtToken(token, resolved.accessTokenSecret)
      : { isValid: false };

    if (!decoded.isValid || isTokenExpired(decoded)) {
      return handleUnauthenticated(request, resolved);
    }

    const payload = decoded.payload;
    const status = payload && "status" in payload ? payload.status : undefined;
    if (status !== undefined && resolved.blockedStatuses.includes(status)) {
      return redirectToLogin(request, resolved.loginPath, "blocked");
    }

    const role = getUserRole(decoded);
    const rule = resolved.roleRules.find((candidate) => pathname.startsWith(candidate.pathPrefix));
    if (rule && !rule.roles.includes(role)) {
      return redirectToLogin(request, resolved.loginPath, "forbidden");
    }

    return forwardWithUserHeaders(request, {
      id: getUserId(decoded),
      role,
      tenantId: getTenantId(decoded),
      status,
    });
  };

  return { proxy, config: resolved };
}

/** Handle a missing/invalid token: try a silent refresh when possible, else redirect to login. */
function handleUnauthenticated(
  request: NextRequest,
  config: ResolvedAuthProxyConfig,
): NextResponse {
  // A background (RSC/prefetch) request must never be redirected — that would poison the
  // router cache with a login document. Let it through unauthenticated instead.
  if (isBackgroundRequest(request)) {
    return NextResponse.next();
  }

  const bounces = redirectCount(request);
  const hasSession =
    request.cookies.get(AUTH_HAS_SESSION_COOKIE_NAME)?.value === AUTH_HAS_SESSION_COOKIE_VALUE;

  // A live `has_session` signal plus headroom under the bounce ceiling means a silent refresh
  // is worth attempting before falling back to the sign-in redirect.
  if (hasSession && bounces < config.maxRedirects) {
    const url = new URL(config.silentRefreshPath, request.nextUrl.origin);
    url.searchParams.set("redirectTo", request.nextUrl.pathname + request.nextUrl.search);
    url.searchParams.set(REDIRECT_COUNT_PARAM, String(bounces + 1));
    return NextResponse.redirect(url);
  }

  return redirectToLogin(request, config.loginPath, "expired");
}

/** Build a sign-in redirect carrying a `reason` and a same-origin `redirectTo`; never a token. */
function redirectToLogin(
  request: NextRequest,
  loginPath: string,
  reason: string,
): NextResponse {
  if (isBackgroundRequest(request)) {
    return NextResponse.next();
  }
  const url = new URL(loginPath, request.nextUrl.origin);
  url.searchParams.set("reason", reason);
  url.searchParams.set(
    "redirectTo",
    resolveSafeDestination(
      request.nextUrl.pathname + request.nextUrl.search,
      request.nextUrl.origin,
      loginPath,
    ),
  );
  return NextResponse.redirect(url);
}

/** Forward the request with UI-only `x-user-*` headers (advisory; never authoritative). */
function forwardWithUserHeaders(
  request: NextRequest,
  user: { id: string; role: string; tenantId: string | undefined; status: string | undefined },
): NextResponse {
  const headers = new Headers(request.headers);
  headers.set("x-user-id", user.id);
  headers.set("x-user-role", user.role);
  if (user.tenantId !== undefined) headers.set("x-user-tenant-id", user.tenantId);
  if (user.status !== undefined) headers.set("x-user-status", user.status);
  return NextResponse.next({ request: { headers } });
}

/** Whether a pathname is matched by any configured public prefix. */
function isPublicPath(pathname: string, publicPaths: readonly string[]): boolean {
  return publicPaths.some((prefix) => pathname === prefix || pathname.startsWith(prefix));
}

/** Read the redirect-bounce counter from the `_r` query parameter. */
function redirectCount(request: NextRequest): number {
  const raw = request.nextUrl.searchParams.get(REDIRECT_COUNT_PARAM);
  const parsed = raw === null ? 0 : Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

/** A parsed `Set-Cookie` header. {@link parseSetCookieHeader} never returns `null`. */
export interface ParsedSetCookie {
  /** The cookie name, or `''` for a malformed header. */
  name: string;
  /** The cookie value, when present. */
  value?: string;
  /** The `Path` attribute, when present. */
  path?: string;
  /** The `Domain` attribute, when present. */
  domain?: string;
  /** The `Max-Age` attribute as a number, when present. */
  maxAge?: number;
  /** The `Expires` attribute, when present. */
  expires?: string;
  /** Whether the `Secure` attribute is set. */
  secure?: boolean;
  /** Whether the `HttpOnly` attribute is set. */
  httpOnly?: boolean;
  /** The `SameSite` attribute, when present. */
  sameSite?: string;
}

/**
 * Read every `Set-Cookie` value from a `Headers` instance. Uses the standard
 * `Headers.getSetCookie()` when available (edge/undici), falling back to the single combined
 * header otherwise.
 *
 * @param headers - The response headers to read.
 * @returns The list of raw `Set-Cookie` header values (possibly empty).
 */
export function getSetCookieHeaders(headers: Headers): string[] {
  const withGetter = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === "function") {
    return withGetter.getSetCookie();
  }
  const combined = headers.get("set-cookie");
  return combined ? [combined] : [];
}

/**
 * Collapse duplicate `Set-Cookie` headers by cookie name, keeping the last value seen (so a
 * later rotation wins) while preserving first-seen order.
 *
 * @param cookies - Raw `Set-Cookie` header values.
 * @returns The deduplicated list.
 */
export function dedupeSetCookieHeaders(cookies: readonly string[]): string[] {
  const byName = new Map<string, string>();
  for (const raw of cookies) {
    const { name } = parseSetCookieHeader(raw);
    byName.set(name === "" ? raw : name, raw);
  }
  return [...byName.values()];
}

/** Split a `key=value` cookie attribute into its key and (possibly empty) value. */
function splitAttribute(attribute: string): [string, string] {
  const index = attribute.indexOf("=");
  if (index === -1) return [attribute.trim(), ""];
  return [attribute.slice(0, index).trim(), attribute.slice(index + 1).trim()];
}

/**
 * Parse a raw `Set-Cookie` header. Never returns `null`: a header with no `name=value` pair
 * yields `{ name: '' }`, so callers can branch on an empty name instead of a null check.
 *
 * @param raw - The raw `Set-Cookie` header value.
 * @returns The parsed cookie; `{ name: '' }` when malformed.
 */
export function parseSetCookieHeader(raw: string): ParsedSetCookie {
  const segments = raw.split(";").map((part) => part.trim()).filter((part) => part !== "");
  const pair = segments[0] ?? "";
  const eq = pair.indexOf("=");
  if (eq <= 0) return { name: "" };
  const name = pair.slice(0, eq).trim();
  if (name === "") return { name: "" };

  const parsed: ParsedSetCookie = { name, value: pair.slice(eq + 1).trim() };
  for (const attribute of segments.slice(1)) {
    const [key, value] = splitAttribute(attribute);
    switch (key.toLowerCase()) {
      case "path":
        parsed.path = value;
        break;
      case "domain":
        parsed.domain = value;
        break;
      case "max-age":
        parsed.maxAge = Number(value);
        break;
      case "expires":
        parsed.expires = value;
        break;
      case "secure":
        parsed.secure = true;
        break;
      case "httponly":
        parsed.httpOnly = true;
        break;
      case "samesite":
        parsed.sameSite = value;
        break;
      default:
        break;
    }
  }
  return parsed;
}

/**
 * Whether a request is a framework background fetch (an RSC payload or a prefetch) that must
 * not be redirected, since redirecting it would corrupt the client router cache.
 *
 * @param request - The incoming request.
 * @returns `true` for RSC/prefetch background requests.
 */
export function isBackgroundRequest(request: NextRequest): boolean {
  const headers = request.headers;
  if (headers.get("RSC") === "1") return true;
  if (headers.get("Next-Router-Prefetch") === "1") return true;
  const purpose = headers.get("Purpose") ?? headers.get("X-Purpose") ?? headers.get("X-Moz");
  if (purpose === "prefetch") return true;
  const secPurpose = headers.get("Sec-Purpose");
  return secPurpose !== null && secPurpose.includes("prefetch");
}

/**
 * Build the same-origin silent-refresh URL for a request, carrying the destination to return
 * to. The destination is never a token, only a path.
 *
 * @param request - The incoming request.
 * @param redirectTo - An explicit destination; defaults to the current path + query.
 * @returns The silent-refresh URL.
 */
export function buildSilentRefreshUrl(request: NextRequest, redirectTo?: string): URL {
  const url = new URL(SILENT_REFRESH_ROUTE, request.nextUrl.origin);
  url.searchParams.set(
    "redirectTo",
    redirectTo ?? request.nextUrl.pathname + request.nextUrl.search,
  );
  return url;
}

/**
 * Resolve a post-auth destination to a safe, same-origin path — the open-redirect guard.
 * Absolute URLs, protocol-relative (`//host`), backslash-tricked (`/\\host`), and any target
 * that resolves off-origin are rejected in favor of the `loginPath` fallback.
 *
 * @param raw - The requested destination (e.g. a `redirectTo` query value).
 * @param origin - The current request origin to compare against.
 * @param loginPath - The fallback returned when `raw` is unsafe or absent.
 * @returns A same-origin `path?query#hash`, or `loginPath`.
 */
export function resolveSafeDestination(
  raw: string | null | undefined,
  origin: string,
  loginPath: string,
): string {
  if (raw === null || raw === undefined || raw === "") return loginPath;
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return loginPath;
  try {
    const candidate = new URL(raw, origin);
    if (candidate.origin !== origin) return loginPath;
    return candidate.pathname + candidate.search + candidate.hash;
  } catch {
    return loginPath;
  }
}
