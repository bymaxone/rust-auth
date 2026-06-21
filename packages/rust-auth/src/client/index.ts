/**
 * @fileoverview Framework-agnostic, zero-runtime-dependency auth client for the rust-auth
 * backend. Exposes a `fetch`-compatible wrapper with a single-flight 401 refresh and a
 * small typed client over the eight first-party auth endpoints. The only import beyond the
 * platform `fetch` API is the frozen `./shared` surface, so this module is safe to ship to
 * the browser bundle.
 * @layer client
 */

import { AuthClientError } from "../shared/auth-client-error";
import type { AuthErrorResponse } from "../shared/auth-error.types";
import type {
  AuthResult,
  LoginResult,
} from "../shared/auth-result.types";
import type { AuthUserClient } from "../shared/auth-user.types";
import type { AuthErrorCode } from "../shared/error-codes";
import { buildAuthRefreshSkipSuffixes } from "../shared/refresh-skip";
import { AUTH_ROUTE_PREFIX, AUTH_ROUTES } from "../shared/routes";

export { AuthClientError } from "../shared/auth-client-error";
export type { AuthErrorCode } from "../shared/error-codes";
export type { AuthErrorResponse } from "../shared/auth-error.types";

/** The default endpoint the 401-refresh single-flight POSTs to (a same-origin Next route). */
const DEFAULT_REFRESH_ENDPOINT = "/api/auth/client-refresh";

/** The default request timeout, in milliseconds. `0` disables the timeout entirely. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** The default content type sent with every request unless the caller overrides it. */
const DEFAULT_HEADERS: Readonly<Record<string, string>> = { "Content-Type": "application/json" };

/**
 * A `fetch`-compatible function: it accepts the exact same arguments as the platform
 * `fetch` and resolves to a `Response`, so it can be passed anywhere a `fetch` is expected.
 */
export type AuthFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Configuration for {@link createAuthFetch}. Every field is optional; the defaults match the
 * cookie-based session model the backend ships (credentials included, JSON content type).
 */
export interface AuthFetchConfig {
  /** Prepended to relative request URLs (absolute and protocol-relative URLs pass through). */
  baseUrl?: string;
  /** The endpoint the single-flight 401 refresh POSTs to. Defaults to `/api/auth/client-refresh`. */
  refreshEndpoint?: string;
  /** The `credentials` mode for every request. Defaults to `'include'` (cookie sessions). */
  credentials?: RequestCredentials;
  /** Headers merged into every request; per-request headers win. Defaults to a JSON content type. */
  defaultHeaders?: Record<string, string>;
  /** Invoked once when a 401 refresh ultimately fails, so the host can route to sign-in. */
  onSessionExpired?: () => void;
  /** Per-request timeout in milliseconds enforced via `AbortController`. `0` disables it. */
  timeout?: number;
  /** The backend mount prefix used to rebase the refresh skip-list. Defaults to `'auth'`. */
  routePrefix?: string;
}

/**
 * Build a single `fetch`-compatible function that transparently handles cookie-session
 * auth: it merges the default headers/credentials, enforces a timeout, and — on a 401 from a
 * protected endpoint — performs ONE shared refresh (concurrent 401s await the same in-flight
 * refresh) and retries the original request exactly once. Requests to the credential-entry
 * and token-lifecycle endpoints never trigger a refresh (loop guard); a failed refresh calls
 * `onSessionExpired` and surfaces the original 401.
 *
 * @param config - Optional behavior overrides; see {@link AuthFetchConfig}.
 * @returns A reusable {@link AuthFetch}.
 */
export function createAuthFetch(config: AuthFetchConfig = {}): AuthFetch {
  const baseUrl = config.baseUrl ?? "";
  const refreshEndpoint = config.refreshEndpoint ?? DEFAULT_REFRESH_ENDPOINT;
  const credentials = config.credentials ?? "include";
  const defaultHeaders = config.defaultHeaders ?? { ...DEFAULT_HEADERS };
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const skipSuffixes = buildAuthRefreshSkipSuffixes(config.routePrefix);
  const onSessionExpired = config.onSessionExpired;

  // The shared in-flight refresh. Concurrent 401s read this same promise so the refresh
  // endpoint is hit at most once per burst (single-flight).
  let refreshInFlight: Promise<boolean> | null = null;

  const runRefresh = (): Promise<boolean> => {
    if (refreshInFlight === null) {
      refreshInFlight = performRefresh(refreshEndpoint, baseUrl, credentials, defaultHeaders);
      // Clear the slot once settled so a later 401 burst can refresh again.
      void refreshInFlight.finally(() => {
        refreshInFlight = null;
      });
    }
    return refreshInFlight;
  };

  return async (input, init) => {
    const resolvedUrl = resolveUrl(toUrlString(input), baseUrl);
    const mergedInit = mergeInit(init, credentials, defaultHeaders);
    const send = (): Promise<Response> => fetchWithTimeout(resolvedUrl, mergedInit, timeout);

    const response = await send();
    if (response.status !== 401 || isRefreshSkipped(resolvedUrl, skipSuffixes)) {
      return response;
    }

    const refreshed = await runRefresh();
    if (!refreshed) {
      onSessionExpired?.();
      return response;
    }
    return send();
  };
}

/** POST the refresh endpoint once and report whether it succeeded (2xx). Never throws. */
async function performRefresh(
  refreshEndpoint: string,
  baseUrl: string,
  credentials: RequestCredentials,
  defaultHeaders: Record<string, string>,
): Promise<boolean> {
  try {
    const response = await fetch(resolveUrl(refreshEndpoint, baseUrl), {
      method: "POST",
      credentials,
      headers: new Headers(defaultHeaders),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/** Merge the per-request init with the wrapper defaults; per-request values take precedence. */
function mergeInit(
  init: RequestInit | undefined,
  credentials: RequestCredentials,
  defaultHeaders: Record<string, string>,
): RequestInit {
  const headers = new Headers(defaultHeaders);
  if (init?.headers) {
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  }
  return { ...init, credentials: init?.credentials ?? credentials, headers };
}

/** Run a `fetch` bounded by an abort timeout; `timeout <= 0` disables the bound. */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeout: number,
): Promise<Response> {
  if (timeout <= 0) {
    return fetch(url, init);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeout);
  const signal = init.signal
    ? AbortSignal.any([init.signal, controller.signal])
    : controller.signal;
  try {
    return await fetch(url, { ...init, signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Normalize any `fetch` input to a URL string for matching and base-URL resolution. */
function toUrlString(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

/** Prepend `baseUrl` to a relative URL; absolute and protocol-relative URLs pass through. */
function resolveUrl(url: string, baseUrl: string): string {
  if (baseUrl === "" || /^([a-z][a-z0-9+.-]*:)?\/\//i.test(url)) {
    return url;
  }
  return `${baseUrl.replace(/\/+$/, "")}/${url.replace(/^\/+/, "")}`;
}

/** True when the request path ends with a refresh-skip suffix (query/hash ignored). */
function isRefreshSkipped(url: string, skipSuffixes: readonly string[]): boolean {
  const pathPart = url.split("?")[0]?.split("#")[0] ?? url;
  return skipSuffixes.some((suffix) => pathPart.endsWith(suffix));
}

/**
 * Credentials accepted by {@link AuthClient.login} / {@link AuthClient.register}. The
 * `tenantId` scopes the lookup to a tenant, matching the backend's multi-tenant model.
 */
export interface LoginInput {
  /** The account email. */
  email: string;
  /** The account password (sent over the wire to the backend, never stored). */
  password: string;
  /** The tenant the account belongs to. */
  tenantId: string;
}

/** Registration payload for {@link AuthClient.register}. */
export interface RegisterInput {
  /** The new account email. */
  email: string;
  /** The new account password. */
  password: string;
  /** The new account display name. */
  name: string;
  /** The tenant the account is created under. */
  tenantId: string;
}

/** The fields shared by every {@link ResetPasswordInput} variant. */
interface ResetPasswordBase {
  /** The account email. */
  email: string;
  /** The tenant the account belongs to. */
  tenantId: string;
  /** The new password to set. */
  newPassword: string;
}

/**
 * Password-reset payload: the base fields plus EXACTLY ONE proof of ownership — an emailed
 * reset `token`, a one-time `otp`, or a previously `verifiedToken`. The mutually-exclusive
 * `never` members make supplying two proofs a compile error.
 */
export type ResetPasswordInput =
  | (ResetPasswordBase & { token: string; otp?: never; verifiedToken?: never })
  | (ResetPasswordBase & { otp: string; token?: never; verifiedToken?: never })
  | (ResetPasswordBase & { verifiedToken: string; token?: never; otp?: never });

/**
 * The typed client over the eight first-party auth endpoints. Each method issues one request
 * through the configured {@link AuthFetch}, parses the success shape, and throws an
 * {@link AuthClientError} carrying the `{ error: { code, message } }` envelope on any non-2xx.
 */
export interface AuthClient {
  /** POST `/auth/login`; resolves a full {@link AuthResult} or an MFA challenge. */
  login(input: LoginInput): Promise<LoginResult>;
  /** POST `/auth/register`; resolves the created session as an {@link AuthResult}. */
  register(data: RegisterInput): Promise<AuthResult>;
  /** POST `/auth/logout`; resolves once the server has cleared the session. */
  logout(): Promise<void>;
  /** POST `/auth/refresh`; resolves the rotated session as an {@link AuthResult}. */
  refresh(): Promise<AuthResult>;
  /** GET `/auth/me`; resolves the current authenticated user. */
  getMe(): Promise<AuthUserClient>;
  /** POST `/auth/mfa/challenge` with the MFA temp token and TOTP code. */
  mfaChallenge(tempToken: string, code: string): Promise<AuthResult>;
  /** POST `/auth/password/forgot-password` to start a password reset. */
  forgotPassword(email: string, tenantId: string): Promise<void>;
  /** POST `/auth/password/reset-password` to complete a password reset. */
  resetPassword(input: ResetPasswordInput): Promise<void>;
}

/**
 * Configuration for {@link createAuthClient}. Extends {@link AuthFetchConfig} (minus
 * `baseUrl`, which becomes required) and lets the caller reuse an existing {@link AuthFetch}.
 */
export interface AuthClientConfig extends Omit<AuthFetchConfig, "baseUrl"> {
  /** The backend origin every endpoint is resolved against (e.g. `https://api.example.com`). */
  baseUrl: string;
  /** The backend mount prefix used to rebase endpoint paths. Defaults to `'auth'`. */
  routePrefix?: string;
  /** An existing fetch wrapper to reuse; one is built from this config when omitted. */
  authFetch?: AuthFetch;
}

/**
 * Build a typed {@link AuthClient}. When `config.authFetch` is supplied it is reused as-is;
 * otherwise a single-flight-refreshing {@link AuthFetch} is built from `config`.
 *
 * @param config - The client configuration; `baseUrl` is required.
 * @returns A typed client over the eight first-party auth endpoints.
 */
export function createAuthClient(config: AuthClientConfig): AuthClient {
  const authFetch = config.authFetch ?? createAuthFetch(config);
  const routePrefix = config.routePrefix ?? AUTH_ROUTE_PREFIX;
  const routes = {
    register: rebaseRoute(AUTH_ROUTES.REGISTER, routePrefix),
    login: rebaseRoute(AUTH_ROUTES.LOGIN, routePrefix),
    logout: rebaseRoute(AUTH_ROUTES.LOGOUT, routePrefix),
    refresh: rebaseRoute(AUTH_ROUTES.REFRESH, routePrefix),
    me: rebaseRoute(AUTH_ROUTES.ME, routePrefix),
    mfaChallenge: rebaseRoute(AUTH_ROUTES.MFA_CHALLENGE, routePrefix),
    forgotPassword: rebaseRoute(AUTH_ROUTES.PASSWORD_FORGOT, routePrefix),
    resetPassword: rebaseRoute(AUTH_ROUTES.PASSWORD_RESET, routePrefix),
  } as const;

  return {
    login: async (input) =>
      readJson<LoginResult>(await authFetch(routes.login, jsonPost(input))),
    register: async (data) =>
      readJson<AuthResult>(await authFetch(routes.register, jsonPost(data))),
    logout: async () => {
      await ensureOk(await authFetch(routes.logout, { method: "POST" }));
    },
    refresh: async () =>
      readJson<AuthResult>(await authFetch(routes.refresh, { method: "POST" })),
    getMe: async () => {
      const wrapper = await readJson<{ user: AuthUserClient }>(
        await authFetch(routes.me, { method: "GET" }),
      );
      return wrapper.user;
    },
    mfaChallenge: async (tempToken, code) =>
      readJson<AuthResult>(
        await authFetch(routes.mfaChallenge, jsonPost({ mfaTempToken: tempToken, code })),
      ),
    forgotPassword: async (email, tenantId) => {
      await ensureOk(await authFetch(routes.forgotPassword, jsonPost({ email, tenantId })));
    },
    resetPassword: async (input) => {
      await ensureOk(await authFetch(routes.resetPassword, jsonPost(input)));
    },
  };
}

/** Build a JSON `POST` init from a payload. */
function jsonPost(payload: unknown): RequestInit {
  return { method: "POST", body: JSON.stringify(payload) };
}

/** Rebase a default `/auth/...` route path onto a custom mount prefix. */
function rebaseRoute(routePath: string, routePrefix: string): string {
  const from = `/${AUTH_ROUTE_PREFIX}`;
  if (routePrefix === AUTH_ROUTE_PREFIX) return routePath;
  const to = `/${routePrefix.replace(/^\/+|\/+$/g, "")}`;
  return routePath.startsWith(`${from}/`) || routePath === from
    ? `${to}${routePath.slice(from.length)}`
    : routePath;
}

/** Throw an {@link AuthClientError} for a non-2xx response; otherwise return it unchanged. */
async function ensureOk(response: Response): Promise<Response> {
  if (response.ok) return response;
  throw await toAuthClientError(response);
}

/** Assert a 2xx response and parse its JSON body as `T`. */
async function readJson<T>(response: Response): Promise<T> {
  await ensureOk(response);
  return (await response.json()) as T;
}

/** Parse the `{ error: { code, message } }` envelope into an {@link AuthClientError}. */
async function toAuthClientError(response: Response): Promise<AuthClientError> {
  let body: AuthErrorResponse | undefined;
  let message = response.statusText || "Request failed";
  try {
    const parsed: unknown = await response.json();
    if (isErrorEnvelope(parsed)) {
      // The wire `code` is an open string; the shared union is forward-compatible and the
      // thrown error's `.code` is widened to `AuthResponseCode`, so this is a safe narrowing.
      body = { code: parsed.error.code as AuthErrorCode, message: parsed.error.message };
      message = parsed.error.message;
    }
  } catch {
    // A non-JSON or empty error body leaves only the HTTP status as a signal.
  }
  return new AuthClientError(message, response.status, body);
}

/** The backend error envelope: `{ error: { code, message, details? } }`. */
interface AuthErrorEnvelope {
  error: { code: string; message: string; details?: unknown };
}

/** Type guard for the backend `{ error: { code, message } }` envelope. */
function isErrorEnvelope(value: unknown): value is AuthErrorEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const error = (value as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === "string" && typeof message === "string";
}
