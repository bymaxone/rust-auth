import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
} from "../src/shared/cookie-defaults";
import {
  createClientRefreshHandler,
  createLogoutHandler,
  createSilentRefreshHandler,
} from "../src/nextjs/handlers";

/**
 * The three same-origin route handlers that bridge the browser's cookie session to the
 * backend. They are the only place in the package that writes `Set-Cookie` on the way back to
 * the browser, so their contract is narrow and worth pinning exactly: forward the request
 * cookies, relay the rotated cookies verbatim (deduplicated), and never send the browser
 * anywhere it did not ask to go.
 */

const BACKEND = "https://api.example.com";

/** A request carrying a session cookie, optionally with a `redirectTo` query. */
function requestWith(query = ""): NextRequest {
  return new NextRequest(`https://app.example.com/auth/silent-refresh${query}`, {
    headers: { cookie: `${AUTH_REFRESH_COOKIE_NAME}=r_1` },
  });
}

/** A backend response carrying rotated cookies. */
function backendOk(cookies: string[], body = '{"accessToken":"a_1"}'): Response {
  const headers = new Headers({ "content-type": "application/json" });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(body, { status: 200, headers });
}

/** Every `Set-Cookie` value on a response, in order. */
function setCookies(response: { headers: Headers }): string[] {
  const getter = response.headers as Headers & { getSetCookie?: () => string[] };
  return getter.getSetCookie?.() ?? [];
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("createSilentRefreshHandler", () => {
  // The happy path: the rotated cookies must reach the browser, or the refresh silently
  // succeeded on the backend while the browser kept the token it just rotated away.
  it("relays the rotated cookies and redirects to the requested destination", async () => {
    const fetchMock = vi.fn().mockResolvedValue(backendOk(["at=a_1; Path=/", "rt=r_2; Path=/auth"]));
    vi.stubGlobal("fetch", fetchMock);

    const response = await createSilentRefreshHandler({ backendUrl: BACKEND })(
      requestWith("?redirectTo=/dashboard"),
    );

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://app.example.com/dashboard");
    expect(setCookies(response)).toEqual(["at=a_1; Path=/", "rt=r_2; Path=/auth"]);
    // The request's own cookies are what authorize the refresh, so they must be forwarded.
    expect(fetchMock).toHaveBeenCalledWith(
      `${BACKEND}/auth/refresh`,
      expect.objectContaining({ method: "POST", headers: { cookie: `${AUTH_REFRESH_COOKIE_NAME}=r_1` } }),
    );
  });

  // Open-redirect guard. `redirectTo` is attacker-controllable, so an absolute off-origin URL
  // must not become the `Location` — otherwise the auth flow itself is the redirector.
  it("refuses an off-origin destination and falls back to the sign-in path", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(backendOk([])));

    const response = await createSilentRefreshHandler({ backendUrl: BACKEND })(
      requestWith("?redirectTo=https://evil.example.com/steal"),
    );

    expect(response.headers.get("location")).toBe("https://app.example.com/login");
  });

  // A failed refresh must not leave the browser holding cookies the backend no longer honors:
  // the session is cleared and the user is sent to sign in with the reason attached.
  it("clears the session cookies and redirects to sign-in when the backend rejects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));

    const response = await createSilentRefreshHandler({ backendUrl: BACKEND, loginPath: "/entrar" })(
      requestWith(),
    );

    expect(response.headers.get("location")).toBe("https://app.example.com/entrar?reason=expired");
    const cleared = setCookies(response).join(" ");
    for (const name of [
      AUTH_ACCESS_COOKIE_NAME,
      AUTH_HAS_SESSION_COOKIE_NAME,
      AUTH_REFRESH_COOKIE_NAME,
    ]) {
      expect(cleared).toContain(`${name}=`);
    }
    expect(cleared).toContain("Max-Age=0");
  });

  // A backend that is down is not an authentication decision, but it must fail closed the same
  // way — a thrown fetch cannot be allowed to surface as a 500 that leaves the session ambiguous.
  it("treats a transport failure as a failed refresh", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));

    const response = await createSilentRefreshHandler({ backendUrl: BACKEND })(requestWith());

    expect(response.headers.get("location")).toBe("https://app.example.com/login?reason=expired");
  });
});

describe("createClientRefreshHandler", () => {
  // The fetch wrapper POSTs here on a 401 and expects the backend's body verbatim, with the
  // rotated cookies applied by the browser.
  it("returns the backend body and relays the rotated cookies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(backendOk(["at=a_2; Path=/"])));

    const response = await createClientRefreshHandler({ backendUrl: BACKEND })(requestWith());

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    await expect(response.text()).resolves.toBe('{"accessToken":"a_1"}');
    expect(setCookies(response)).toEqual(["at=a_2; Path=/"]);
  });

  // The client distinguishes "refresh failed" from every other error by this envelope, so the
  // shape is a contract with the fetch wrapper, not a detail.
  it("answers 401 with the session-expired envelope when the refresh fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));

    const response = await createClientRefreshHandler({ backendUrl: BACKEND })(requestWith());

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: { code: "auth.session_expired", message: "Session expired." },
    });
    expect(setCookies(response)).toEqual([]);
  });
});

describe("createLogoutHandler", () => {
  // Logout is best-effort against the backend but unconditional locally: whatever the backend
  // answers, the browser must end up without session cookies.
  it("clears the session cookies even when the backend call fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));

    const response = await createLogoutHandler({ backendUrl: BACKEND })(requestWith());

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
    const cleared = setCookies(response).join(" ");
    expect(cleared).toContain(`${AUTH_ACCESS_COOKIE_NAME}=`);
    expect(cleared).toContain(`${AUTH_REFRESH_COOKIE_NAME}=`);
  });

  // The backend logout must be reached at the mounted prefix, not at the default one: a
  // deployment that mounts the routes elsewhere would otherwise log nobody out server-side.
  it("calls the backend logout rebased onto the configured route prefix", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await createLogoutHandler({ backendUrl: `${BACKEND}/`, routePrefix: "identity" })(requestWith());

    expect(fetchMock).toHaveBeenCalledWith(
      `${BACKEND}/identity/logout`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  // A request with no cookies at all still forwards a header, because the backend distinguishes
  // "no cookie" from "no header" only by the value it receives.
  it("forwards an empty cookie header when the request carries none", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await createLogoutHandler({ backendUrl: BACKEND })(
      new NextRequest("https://app.example.com/auth/logout"),
    );

    expect(fetchMock).toHaveBeenCalledWith(
      `${BACKEND}/auth/logout`,
      expect.objectContaining({ headers: { cookie: "" } }),
    );
  });
});
