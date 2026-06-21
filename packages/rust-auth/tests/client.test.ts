import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AuthClientError,
  createAuthClient,
  createAuthFetch,
} from "../src/client/index";
import type { AuthResult } from "../src/shared/auth-result.types";
import type { AuthUserClient } from "../src/shared/auth-user.types";

/** A `fetch`-shaped test handler. */
type FetchHandler = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** A captured `fetch` call, normalized for assertions. */
interface RecordedCall {
  url: string;
  init: RequestInit;
}

const originalFetch = globalThis.fetch;

/** Install a mocked global `fetch` and capture every call. */
function installFetch(handler: FetchHandler): RecordedCall[] {
  const calls: RecordedCall[] = [];
  const mock: FetchHandler = (input, init) => {
    calls.push({ url: String(input instanceof Request ? input.url : input), init: init ?? {} });
    return handler(input, init);
  };
  globalThis.fetch = vi.fn(mock) as unknown as typeof fetch;
  return calls;
}

/** Return the first array element or throw — keeps the tests free of non-null assertions. */
function first<T>(items: readonly T[]): T {
  const value = items[0];
  if (value === undefined) throw new Error("expected at least one element");
  return value;
}

/** Build a JSON `Response`. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fully-populated safe user fixture. */
function makeUser(): AuthUserClient {
  return {
    id: "u_1",
    email: "user@example.com",
    name: "User One",
    role: "member",
    status: "ACTIVE",
    tenantId: "t_1",
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: "2026-01-01T00:00:00Z",
  };
}

/** A successful auth result fixture. */
function makeAuthResult(): AuthResult {
  return { user: makeUser(), accessToken: "access.jwt", refreshToken: "refresh.opaque" };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("createAuthFetch — single-flight 401 refresh", () => {
  it("shares one in-flight refresh across two concurrent 401s", async () => {
    // Two concurrent protected requests both see a 401; the wrapper must hit the refresh
    // endpoint exactly once, then both retries succeed.
    let refreshCalls = 0;
    installFetch(async (input) => {
      const url = String(input);
      if (url.endsWith("/api/auth/client-refresh")) {
        refreshCalls += 1;
        return jsonResponse({ ok: true });
      }
      return refreshCalls > 0 ? jsonResponse({ user: makeUser() }) : jsonResponse({}, 401);
    });

    const authFetch = createAuthFetch({ timeout: 0 });
    const [a, b] = await Promise.all([authFetch("/auth/me"), authFetch("/auth/me")]);

    expect(refreshCalls).toBe(1);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });

  it("retries the original request exactly once after a successful refresh", async () => {
    // The first protected attempt is a 401; after one refresh the retry succeeds.
    let attempts = 0;
    let refreshCalls = 0;
    installFetch(async (input) => {
      const url = String(input);
      if (url.endsWith("/api/auth/client-refresh")) {
        refreshCalls += 1;
        return jsonResponse({ ok: true });
      }
      attempts += 1;
      return attempts === 1 ? jsonResponse({}, 401) : jsonResponse({ ok: true });
    });

    const authFetch = createAuthFetch({ timeout: 0 });
    const response = await authFetch("/auth/me");

    expect(response.status).toBe(200);
    expect(refreshCalls).toBe(1);
    expect(attempts).toBe(2);
  });

  it("does not refresh on a 401 from a skip-listed endpoint", async () => {
    // A 401 on the login route must never trigger a refresh (that would be a loop).
    let refreshCalls = 0;
    installFetch(async (input) => {
      const url = String(input);
      if (url.endsWith("/api/auth/client-refresh")) {
        refreshCalls += 1;
        return jsonResponse({});
      }
      return jsonResponse({ error: { code: "auth.invalid_credentials", message: "bad" } }, 401);
    });

    const authFetch = createAuthFetch({ timeout: 0 });
    const response = await authFetch("/auth/login", { method: "POST" });

    expect(response.status).toBe(401);
    expect(refreshCalls).toBe(0);
  });

  it("calls onSessionExpired and surfaces the 401 when the refresh fails", async () => {
    // A failed refresh notifies the host and returns the original 401 unchanged.
    const onSessionExpired = vi.fn();
    installFetch(async () => jsonResponse({}, 401));

    const authFetch = createAuthFetch({ timeout: 0, onSessionExpired });
    const response = await authFetch("/auth/me");

    expect(response.status).toBe(401);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
  });

  it("prepends baseUrl to relative URLs and merges the default JSON header", async () => {
    // The wrapper rebases relative paths onto baseUrl and adds the JSON content type.
    const calls = installFetch(async () => jsonResponse({ ok: true }));
    const authFetch = createAuthFetch({ baseUrl: "https://api.test", timeout: 0 });

    await authFetch("/auth/me", { method: "GET" });

    const call = first(calls);
    expect(call.url).toBe("https://api.test/auth/me");
    expect(new Headers(call.init.headers).get("content-type")).toBe("application/json");
    expect(call.init.credentials).toBe("include");
  });
});

describe("AuthClient — endpoint, payload, and error mapping", () => {
  const baseUrl = "https://api.test";

  it("login POSTs credentials to /auth/login and returns the LoginResult", async () => {
    const result = makeAuthResult();
    const calls = installFetch(async () => jsonResponse(result));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const value = await client.login({ email: "a@b.c", password: "pw", tenantId: "t_1" });

    expect(value).toEqual(result);
    const call = first(calls);
    expect(call.url).toBe("https://api.test/auth/login");
    expect(call.init.method).toBe("POST");
    expect(JSON.parse(String(call.init.body))).toEqual({
      email: "a@b.c",
      password: "pw",
      tenantId: "t_1",
    });
  });

  it("register POSTs to /auth/register and returns the AuthResult", async () => {
    const result = makeAuthResult();
    const calls = installFetch(async () => jsonResponse(result));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const value = await client.register({
      email: "a@b.c",
      password: "pw",
      name: "Ada",
      tenantId: "t_1",
    });

    expect(value).toEqual(result);
    expect(first(calls).url).toBe("https://api.test/auth/register");
  });

  it("logout POSTs to /auth/logout and resolves void on 2xx", async () => {
    const calls = installFetch(async () => new Response(null, { status: 204 }));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    await expect(client.logout()).resolves.toBeUndefined();
    expect(first(calls).url).toBe("https://api.test/auth/logout");
    expect(first(calls).init.method).toBe("POST");
  });

  it("refresh POSTs to /auth/refresh and returns the AuthResult", async () => {
    const result = makeAuthResult();
    const calls = installFetch(async () => jsonResponse(result));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const value = await client.refresh();

    expect(value).toEqual(result);
    expect(first(calls).url).toBe("https://api.test/auth/refresh");
  });

  it("getMe GETs /auth/me and unwraps the { user } envelope", async () => {
    const user = makeUser();
    const calls = installFetch(async () => jsonResponse({ user }));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const value = await client.getMe();

    expect(value).toEqual(user);
    expect(first(calls).url).toBe("https://api.test/auth/me");
    expect(first(calls).init.method).toBe("GET");
  });

  it("mfaChallenge POSTs { mfaTempToken, code } to /auth/mfa/challenge", async () => {
    const result = makeAuthResult();
    const calls = installFetch(async () => jsonResponse(result));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const value = await client.mfaChallenge("temp.jwt", "123456");

    expect(value).toEqual(result);
    expect(first(calls).url).toBe("https://api.test/auth/mfa/challenge");
    expect(JSON.parse(String(first(calls).init.body))).toEqual({
      mfaTempToken: "temp.jwt",
      code: "123456",
    });
  });

  it("forgotPassword POSTs { email, tenantId } and resolves void", async () => {
    const calls = installFetch(async () => jsonResponse({ ok: true }));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    await expect(client.forgotPassword("a@b.c", "t_1")).resolves.toBeUndefined();
    expect(first(calls).url).toBe("https://api.test/auth/password/forgot-password");
    expect(JSON.parse(String(first(calls).init.body))).toEqual({
      email: "a@b.c",
      tenantId: "t_1",
    });
  });

  it("resetPassword POSTs the discriminated payload to /auth/password/reset-password", async () => {
    const calls = installFetch(async () => jsonResponse({ ok: true }));
    const client = createAuthClient({ baseUrl, timeout: 0 });

    await expect(
      client.resetPassword({
        email: "a@b.c",
        tenantId: "t_1",
        newPassword: "newpw",
        token: "reset.token",
      }),
    ).resolves.toBeUndefined();
    expect(first(calls).url).toBe("https://api.test/auth/password/reset-password");
    expect(JSON.parse(String(first(calls).init.body))).toEqual({
      email: "a@b.c",
      tenantId: "t_1",
      newPassword: "newpw",
      token: "reset.token",
    });
  });

  it("throws an AuthClientError carrying the { error } envelope on a non-2xx", async () => {
    // login is skip-listed, so a 401 throws directly instead of triggering a refresh.
    installFetch(async () =>
      jsonResponse({ error: { code: "auth.invalid_credentials", message: "Bad credentials" } }, 401),
    );
    const client = createAuthClient({ baseUrl, timeout: 0 });

    const error = await client
      .login({ email: "a@b.c", password: "pw", tenantId: "t_1" })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(AuthClientError);
    if (!(error instanceof AuthClientError)) throw new Error("expected AuthClientError");
    expect(error.status).toBe(401);
    expect(error.code).toBe("auth.invalid_credentials");
    expect(error.message).toBe("Bad credentials");
  });

  it("rebases endpoint paths onto a custom routePrefix", async () => {
    const calls = installFetch(async () => jsonResponse(makeAuthResult()));
    const client = createAuthClient({ baseUrl, routePrefix: "api/auth", timeout: 0 });

    await client.login({ email: "a@b.c", password: "pw", tenantId: "t_1" });

    expect(first(calls).url).toBe("https://api.test/api/auth/login");
  });
});
