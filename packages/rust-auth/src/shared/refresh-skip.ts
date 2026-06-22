// Hand-written runtime — NOT ts-rs generated. Derives the refresh-skip suffix list from
// the generated route constants so it can never drift from the server's route table.

import { AUTH_ROUTE_PREFIX, AUTH_ROUTES } from "./routes";

/**
 * The route keys whose paths must NOT trigger a silent 401 → refresh → retry in the auth
 * fetch wrapper: the credential-entry, token-lifecycle, and public (pre-authentication)
 * endpoints. Refreshing on a 401 from any of these is either pointless (the caller is not
 * yet authenticated) or a refresh loop (the request IS the login/refresh/logout), so they
 * are skipped. Derived from the generated {@link AUTH_ROUTES}, never hand-listed paths.
 */
const SKIP_ROUTE_KEYS = [
  "LOGIN",
  "REGISTER",
  "REFRESH",
  "LOGOUT",
  "VERIFY_EMAIL",
  "RESEND_VERIFICATION",
  "MFA_CHALLENGE",
  "PASSWORD_FORGOT",
  "PASSWORD_RESET",
  "PASSWORD_VERIFY_OTP",
  "PASSWORD_RESEND_OTP",
  "PLATFORM_LOGIN",
  "PLATFORM_MFA_CHALLENGE",
  "PLATFORM_REFRESH",
  "PLATFORM_LOGOUT",
  "INVITATIONS_ACCEPT",
] as const satisfies readonly (keyof typeof AUTH_ROUTES)[];

/**
 * Build the list of path suffixes a request URL is matched against (by `endsWith`) to
 * decide whether the auth fetch wrapper should skip its single-flight 401 refresh.
 *
 * The generated {@link AUTH_ROUTES} are expressed under the default
 * {@link AUTH_ROUTE_PREFIX}; pass a custom `routePrefix` to rebase the suffixes when the
 * backend is mounted under a different prefix, so the skip-list tracks the actual mount.
 *
 * @param routePrefix - The server mount prefix (leading/trailing slashes are ignored);
 *   defaults to {@link AUTH_ROUTE_PREFIX} (`'auth'`).
 * @returns The frozen list of route-path suffixes to skip refresh for.
 */
export function buildAuthRefreshSkipSuffixes(
  routePrefix: string = AUTH_ROUTE_PREFIX,
): readonly string[] {
  const fromPrefix = `/${AUTH_ROUTE_PREFIX}`;
  const toPrefix = `/${routePrefix.replace(/^\/+|\/+$/g, "")}`;
  return Object.freeze(
    SKIP_ROUTE_KEYS.map((key) => AUTH_ROUTES[key].replace(fromPrefix, toPrefix)),
  );
}

/**
 * The default refresh-skip suffix list, built for the default {@link AUTH_ROUTE_PREFIX}.
 */
export const AUTH_REFRESH_SKIP_PATH_SUFFIXES: readonly string[] =
  buildAuthRefreshSkipSuffixes();
