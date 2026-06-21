import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  decodeJwtToken,
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken,
} from "../src/nextjs/jwt";
import { resolveSafeDestination } from "../src/nextjs/proxy";

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

/** Flip the final signature character so the signature is wrong but the framing intact. */
function tamperSignature(token: string): string {
  const last = token.slice(-1);
  return `${token.slice(0, -1)}${last === "A" ? "B" : "A"}`;
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
  it("returns the header and payload without verifying the signature", () => {
    const decoded = decodeJwtToken(dashboardToken());
    expect(decoded.isValid).toBe(true);
    expect(decoded.header?.alg).toBe("HS256");
    expect(getUserId(decoded)).toBe("u_1");
  });

  it("returns { isValid: false } for a malformed token and never throws", () => {
    expect(decodeJwtToken("not-a-token").isValid).toBe(false);
    expect(getTenantId(decodeJwtToken("not-a-token"))).toBeUndefined();
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
    const source = readFileSync(join(import.meta.dirname, "..", "src", "nextjs", "jwt.ts"), "utf8");
    expect(source).toMatch(/import\s+["']server-only["'];/);
  });
});
