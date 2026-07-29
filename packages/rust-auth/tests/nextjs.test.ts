import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { NextRequest } from "next/server";
import type { NextResponse } from "next/server";
import { describe, expect, it } from "vitest";

import {
  decodeJwtToken,
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken,
} from "../src/nextjs/jwt";
import { createAuthProxy, isBackgroundRequest, resolveSafeDestination } from "../src/nextjs/proxy";

/** The shared HS256 secret used to sign and verify test tokens (server == edge). */
const SECRET = "an-edge-test-hs256-secret-key-0123456789";

/** Base64url-encode a string or buffer. */
function base64url(input: string): string {
  return Buffer.from(input).toString("base64url");
}

/**
 * Sign a compact HS256 JWS with Node crypto — the SAME HMAC-SHA256 the backend uses — so the
 * WASM verifier exercises a genuine backend-shaped token (server/edge parity).
 */
function signHs256(payload: Record<string, unknown>, secret: string): string {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signature = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

/** Build a dashboard token whose validity window spans now, with optional claim overrides. */
function dashboardToken(overrides: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  return signHs256(
    {
      sub: "u_1",
      jti: "jti-1",
      tenantId: "t_1",
      role: "member",
      type: "dashboard",
      status: "ACTIVE",
      mfaEnabled: true,
      mfaVerified: false,
      iat: now - 10,
      exp: now + 3600,
      ...overrides,
    },
    SECRET,
  );
}

/** Build an MFA-temp (`type: "mfa_challenge"`) token whose validity window spans now. */
function mfaTempToken(): string {
  const now = Math.floor(Date.now() / 1000);
  return signHs256(
    {
      sub: "u_1",
      jti: "jti-1",
      type: "mfa_challenge",
      context: "dashboard",
      iat: now - 10,
      exp: now + 300,
    },
    SECRET,
  );
}

/** Build a GET request to a protected path carrying the access cookie set to `token`. */
function protectedRequest(token: string): NextRequest {
  return new NextRequest("https://app.test/dashboard", {
    headers: { cookie: `access_token=${token}` },
  });
}

/**
 * Build a GET request to a protected path carrying the given background headers (and,
 * optionally, an access cookie) — the shape a forged RSC/prefetch/state-tree probe takes.
 */
function backgroundRequest(background: Record<string, string>, token = ""): NextRequest {
  const cookie: Record<string, string> =
    token.length > 0 ? { cookie: `access_token=${token}` } : {};
  return new NextRequest("https://app.test/dashboard", {
    headers: { ...background, ...cookie },
  });
}

/** Flip the final signature character so the signature is wrong but the framing intact. */
function tamperSignature(token: string): string {
  const last = token.slice(-1);
  return `${token.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}

/** Whether a proxy response forwarded the UI-only x-user-id header (i.e. admitted). */
function admittedUserId(response: { headers: Headers }): string | null {
  return response.headers.get("x-middleware-request-x-user-id");
}

/** Whether a proxy response redirected to the sign-in path (i.e. rejected). */
function redirectedToLogin(response: { headers: Headers }): boolean {
  const location = response.headers.get("location");
  return location !== null && location.includes("/login");
}

describe("verifyJwtToken — real WASM HS256 parity (server == edge)", () => {
  it("verifies a backend-signed token under the matching secret and exposes its claims", async () => {
    const result = await verifyJwtToken(dashboardToken(), SECRET);

    expect(result.isValid).toBe(true);
    expect(getUserId(result)).toBe("u_1");
    expect(getUserRole(result)).toBe("member");
    expect(getTenantId(result)).toBe("t_1");
    expect(isTokenExpired(result)).toBe(false);
  });

  it("rejects a token signed with a different secret", async () => {
    const result = await verifyJwtToken(dashboardToken(), "a-different-edge-secret-9876543210ab-xx");
    expect(result.isValid).toBe(false);
  });

  it("rejects a tampered signature under authoritative verification", async () => {
    const result = await verifyJwtToken(tamperSignature(dashboardToken()), SECRET);
    expect(result.isValid).toBe(false);
  });

  it("rejects an already-expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyJwtToken(dashboardToken({ iat: now - 7200, exp: now - 3600 }), SECRET);
    expect(result.isValid).toBe(false);
  });
});

describe("verifyJwtToken — decode-only fallback is non-authoritative", () => {
  it("decodes a forged token without a secret even though authoritative verification rejects it", async () => {
    const forged = tamperSignature(dashboardToken());

    // Authoritative verification (with the secret) rejects the forged signature.
    expect((await verifyJwtToken(forged, SECRET)).isValid).toBe(false);

    // Decode-only (no secret) returns the claims but never checks the signature.
    const decoded = await verifyJwtToken(forged, null);
    expect(decoded.isValid).toBe(true);
    expect(getUserId(decoded)).toBe("u_1");
  });
});

describe("decodeJwtToken", () => {
  it("returns the header and payload without verifying the signature", async () => {
    const decoded = await decodeJwtToken(dashboardToken());
    expect(decoded.isValid).toBe(true);
    expect(decoded.header?.alg).toBe("HS256");
    expect(getUserId(decoded)).toBe("u_1");
  });

  it("returns { isValid: false } for a malformed token and never throws", async () => {
    expect((await decodeJwtToken("not-a-token")).isValid).toBe(false);
    expect(getTenantId(await decodeJwtToken("not-a-token"))).toBeUndefined();
  });
});

describe("resolveSafeDestination — open-redirect guard", () => {
  const origin = "https://app.test";

  it("allows a same-origin absolute path with query", () => {
    expect(resolveSafeDestination("/dashboard?tab=1", origin, "/login")).toBe("/dashboard?tab=1");
  });

  it("rejects an absolute off-origin URL", () => {
    expect(resolveSafeDestination("https://evil.test/steal", origin, "/login")).toBe("/login");
  });

  it("rejects a protocol-relative URL", () => {
    expect(resolveSafeDestination("//evil.test", origin, "/login")).toBe("/login");
  });

  it("rejects a backslash-tricked target and an absent target", () => {
    expect(resolveSafeDestination("/\\evil.test", origin, "/login")).toBe("/login");
    expect(resolveSafeDestination(null, origin, "/login")).toBe("/login");
  });
});

describe("server-only enforcement", () => {
  it("the WASM-backed jwt module imports 'server-only' so a Client Component import fails the build", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, "..", "src", "nextjs", "jwt.ts"), "utf8");
    expect(source).toMatch(/import\s+["']server-only["'];/);
  });
});

describe("createAuthProxy — fail-closed verification (S1) and token-type assertion (S2)", () => {
  it("admits a validly-signed access token when a non-empty secret is configured", async () => {
    // The happy path: an authoritative HS256 verification with the matching secret admits the
    // request and forwards the user id header; no sign-in redirect is issued.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(protectedRequest(dashboardToken()));

    expect(redirectedToLogin(response)).toBe(false);
    expect(admittedUserId(response)).toBe("u_1");
  });

  it("rejects a forged token when no secret is configured (S1 fail-closed)", async () => {
    // Without a secret the proxy must NEVER fall back to decode-only acceptance: a forged
    // (tampered) token is treated as unauthenticated and redirected to sign-in, not admitted.
    const { proxy } = createAuthProxy({});
    const response = await proxy(protectedRequest(tamperSignature(dashboardToken())));

    expect(redirectedToLogin(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });

  it("rejects even a structurally-valid token when no secret is configured (S1 fail-closed)", async () => {
    // A genuinely-signed token must also be rejected when there is no secret to verify it —
    // the proxy cannot prove it genuine, so it fails closed rather than admitting it.
    const { proxy } = createAuthProxy({});
    const response = await proxy(protectedRequest(dashboardToken()));

    expect(redirectedToLogin(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });

  it("rejects a verified MFA-challenge token (S2 token-type confusion)", async () => {
    // An MFA-temp token verifies under the secret but is NOT an access token; admitting it
    // would let a half-authenticated (pre-second-factor) session reach a protected route.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(protectedRequest(mfaTempToken()));

    expect(redirectedToLogin(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });
});

describe("createAuthProxy — client-supplied x-user-* headers never survive", () => {
  /** A protected request that forges every advisory identity header. */
  function forged(token: string): NextRequest {
    return new NextRequest("https://app.test/dashboard", {
      headers: {
        cookie: `access_token=${token}`,
        "x-user-id": "victim",
        "x-user-role": "ADMIN",
        "x-user-tenant-id": "victim-tenant",
        "x-user-status": "ACTIVE",
      },
    });
  }

  it("overwrites every forged header from the verified token", async () => {
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(forged(dashboardToken()));

    expect(response.headers.get("x-middleware-request-x-user-id")).toBe("u_1");
    expect(response.headers.get("x-middleware-request-x-user-role")).not.toBe("ADMIN");
  });

  it("strips them on a public path, where there is no token at all", async () => {
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET, publicPaths: ["/public"] });
    const response = await proxy(
      new NextRequest("https://app.test/public", {
        headers: { "x-user-id": "victim", "x-user-role": "ADMIN" },
      }),
    );

    const injected = response.headers.get("x-middleware-override-headers");
    expect(injected).not.toBeNull();
    expect(injected).not.toContain("x-user-id");
    expect(response.headers.get("x-middleware-request-x-user-id")).not.toBe("victim");
  });

  it("does not exempt a protected path that merely starts with a public prefix", async () => {
    // `/login` must not make `/loginhistory` public. The direction of that mistake is
    // fail-open: a route the operator meant to protect becomes reachable unauthenticated.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET, publicPaths: ["/login"] });
    const response = await proxy(new NextRequest("https://app.test/loginhistory"));

    expect(redirectedToLogin(response)).toBe(true);
  });
});

describe("createAuthProxy — forged background headers are not an auth bypass (RC10)", () => {
  /**
   * Whether a response is the bare, uncacheable 401 the proxy owes an unauthenticated
   * background request — the nest-auth parity shape (`no-store, no-cache`).
   */
  function isBackgroundRefusal(response: NextResponse): boolean {
    return (
      response.status === 401 && response.headers.get("cache-control") === "no-store, no-cache"
    );
  }

  it("answers a forged `RSC: 1` probe on a protected route with 401, never a pass-through", async () => {
    // The core bypass: `RSC` is a plain request header, so an attacker can set it on a normal
    // navigation. If the proxy answered `NextResponse.next()` the protected page's server
    // components would render for a caller holding no session at all. It must refuse instead.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(backgroundRequest({ RSC: "1" }));

    expect(isBackgroundRefusal(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
    // Not a redirect either: a redirected RSC fetch would poison the router cache with the
    // login document, which is why the refusal is a status code rather than a `Location`.
    expect(redirectedToLogin(response)).toBe(false);
  });

  it("answers a forged `Next-Router-Prefetch: 1` probe with the same 401", async () => {
    // The prefetch signal is equally forgeable, so it must reach the same refusal — closing
    // `RSC` alone would leave an identical bypass one header name away.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(backgroundRequest({ "Next-Router-Prefetch": "1" }));

    expect(isBackgroundRefusal(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });

  it("answers a forged `Next-Router-State-Tree` probe with the same 401", async () => {
    // The partial-render signal carries a serialised tree rather than a flag, so detection
    // keys off any non-empty value. Without it this variant would miss the background branch.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(backgroundRequest({ "Next-Router-State-Tree": '["",{}]' }));

    expect(isBackgroundRefusal(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });

  it("refuses a forged background probe even when a `has_session` cookie is present", async () => {
    // `has_session` is a non-HttpOnly UI hint and is likewise forgeable. It routes a normal
    // navigation into the silent-refresh redirect, but it must not turn a background request
    // into a pass-through — the caller still holds no verifiable access token.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const request = new NextRequest("https://app.test/dashboard", {
      headers: { RSC: "1", cookie: "has_session=1" },
    });
    const response = await proxy(request);

    expect(isBackgroundRefusal(response)).toBe(true);
    expect(admittedUserId(response)).toBeNull();
  });

  it("refuses a blocked account on a background request instead of passing it through", async () => {
    // The account-status gate must not be escapable by adding a header: a SUSPENDED user who
    // holds a genuinely-signed token would otherwise render the guarded page by sending
    // `RSC: 1`. The blocked refusal is returned whatever the request shape.
    const { proxy } = createAuthProxy({
      accessTokenSecret: SECRET,
      blockedStatuses: ["SUSPENDED"],
    });
    const response = await proxy(
      backgroundRequest({ RSC: "1" }, dashboardToken({ status: "SUSPENDED" })),
    );

    expect(response.status).not.toBe(200);
    expect(admittedUserId(response)).toBeNull();
    expect(response.headers.get("location")).toContain("reason=blocked");
  });

  it("refuses an RBAC-forbidden role on a background request instead of passing it through", async () => {
    // Same bypass one branch further along: a `member` token on an admin-only prefix must be
    // refused even when the request claims to be a background fetch. Passing it through would
    // hand a role-gated page to a user the rule denies.
    const { proxy } = createAuthProxy({
      accessTokenSecret: SECRET,
      roleRules: [{ pathPrefix: "/dashboard", roles: ["admin"] }],
    });
    const response = await proxy(backgroundRequest({ RSC: "1" }, dashboardToken()));

    expect(response.status).not.toBe(200);
    expect(admittedUserId(response)).toBeNull();
    expect(response.headers.get("location")).toContain("reason=forbidden");
  });

  it("still admits a genuine background request that carries a valid session", async () => {
    // The regression guard for the fix: hardening the background branch must not break real
    // prefetching. An authenticated RSC fetch is admitted with its user headers as before.
    const { proxy } = createAuthProxy({ accessTokenSecret: SECRET });
    const response = await proxy(backgroundRequest({ RSC: "1" }, dashboardToken()));

    expect(response.status).toBe(200);
    expect(admittedUserId(response)).toBe("u_1");
  });
});

describe("isBackgroundRequest — signal coverage", () => {
  it("detects the RSC, prefetch, state-tree, and Sec-Purpose signals", () => {
    // Each header the Next router uses for a non-navigational fetch must be recognised, so
    // the proxy answers every one of them with a 401 rather than a cache-poisoning redirect.
    expect(isBackgroundRequest(backgroundRequest({ RSC: "1" }))).toBe(true);
    expect(isBackgroundRequest(backgroundRequest({ "Next-Router-Prefetch": "1" }))).toBe(true);
    expect(isBackgroundRequest(backgroundRequest({ "Next-Router-State-Tree": '["",{}]' }))).toBe(
      true,
    );
    expect(isBackgroundRequest(backgroundRequest({ Purpose: "prefetch" }))).toBe(true);
    expect(isBackgroundRequest(backgroundRequest({ "Sec-Purpose": "prefetch;prerender" }))).toBe(
      true,
    );
  });

  it("treats an empty state-tree header and a plain navigation as foreground", () => {
    // An empty header value is not a state tree, so it must not flip the branch; a request
    // with no signal at all is a top-level navigation that still deserves a redirect.
    expect(isBackgroundRequest(backgroundRequest({ "Next-Router-State-Tree": "" }))).toBe(false);
    expect(isBackgroundRequest(backgroundRequest({}))).toBe(false);
  });
});
