import { createAuthProxy } from "@bymax-one/rust-auth/nextjs";

// The edge auth proxy. It verifies the backend-signed HS256 access token at the edge
// via WASM (no network call), gates protected routes, runs coarse role-based access
// control, attempts a silent refresh when a session signal is present, and forwards
// UI-only `x-user-*` headers. With no `accessTokenSecret` it FAILS CLOSED — every
// request is treated as unauthenticated — so the secret must be supplied.
const { proxy, config: proxyConfig } = createAuthProxy({
  accessTokenSecret: process.env.AUTH_ACCESS_TOKEN_SECRET ?? null,
  loginPath: "/login",
  // `/auth` is the same-origin forwarding route to the backend (login, register, …);
  // `/api/auth` are the refresh/logout handlers. Both must be reachable while
  // unauthenticated.
  publicPaths: ["/login", "/auth", "/api/auth"],
  roleRules: [{ pathPrefix: "/admin", roles: ["ADMIN"] }],
});

export const middleware = proxy;

// Run the proxy on everything except Next internals and static assets.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

// Re-exported for visibility; the resolved config is also available for diagnostics.
export { proxyConfig };
