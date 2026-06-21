import { describe, expect, it } from "vitest";

import { AuthClientError } from "./auth-client-error";
import { AUTH_ERROR_CODES } from "./error-codes";
import {
  AUTH_REFRESH_SKIP_PATH_SUFFIXES,
  buildAuthRefreshSkipSuffixes,
} from "./refresh-skip";
import { AUTH_ROUTES } from "./routes";

describe("AuthClientError", () => {
  it("is an Error subclass carrying status/code/body", () => {
    // instanceof must hold (the class is thrown and caught across the bundle boundary).
    const body = { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS, message: "bad creds" };
    const error = new AuthClientError("bad creds", 401, body);
    expect(error).toBeInstanceOf(AuthClientError);
    expect(error).toBeInstanceOf(Error);
    expect(error.status).toBe(401);
    expect(error.code).toBe("auth.invalid_credentials");
    expect(error.body).toEqual(body);
    expect(error.name).toBe("AuthClientError");
  });

  it("has an undefined code when no body is given", () => {
    // A transport-level failure has a status but no parsed envelope.
    const error = new AuthClientError("network", 0);
    expect(error.code).toBeUndefined();
    expect(error.body).toBeUndefined();
  });

  it("toJSON strips the echoed body, keeping only the diagnostic fields", () => {
    // Structured logs must never leak the (potentially DTO-echoing) body.
    const error = new AuthClientError("nope", 403, {
      code: AUTH_ERROR_CODES.FORBIDDEN,
      message: "nope",
    });
    expect(error.toJSON()).toEqual({
      name: "AuthClientError",
      message: "nope",
      status: 403,
      code: "auth.forbidden",
    });
    expect(JSON.stringify(error)).not.toContain("message\":\"nope\",\"code");
  });
});

describe("buildAuthRefreshSkipSuffixes", () => {
  it("includes the credential-entry and token-lifecycle routes, not /auth/me", () => {
    // A 401 on login/refresh/logout must never trigger a silent refresh (loop guard),
    // while the authenticated /auth/me route is NOT in the skip-list (it should refresh).
    const suffixes = buildAuthRefreshSkipSuffixes();
    expect(suffixes).toContain(AUTH_ROUTES.LOGIN);
    expect(suffixes).toContain(AUTH_ROUTES.REFRESH);
    expect(suffixes).toContain(AUTH_ROUTES.LOGOUT);
    expect(suffixes).toContain(AUTH_ROUTES.PASSWORD_RESET);
    expect(suffixes).not.toContain(AUTH_ROUTES.ME);
  });

  it("rebases the suffixes onto a custom route prefix", () => {
    // A backend mounted under a different prefix gets the suffixes rebased so the
    // endsWith match still fires.
    const suffixes = buildAuthRefreshSkipSuffixes("api/auth");
    expect(suffixes).toContain("/api/auth/login");
    expect(suffixes.every((s) => s.startsWith("/api/auth/"))).toBe(true);
    // Leading/trailing slashes on the prefix are tolerated.
    expect(buildAuthRefreshSkipSuffixes("/api/auth/")).toContain("/api/auth/login");
  });

  it("exposes a default frozen suffix list", () => {
    // The default export is the builder's output for the default prefix, and frozen.
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toEqual(buildAuthRefreshSkipSuffixes());
    expect(Object.isFrozen(AUTH_REFRESH_SKIP_PATH_SUFFIXES)).toBe(true);
  });
});
