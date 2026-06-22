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
  // `/api/auth` are the client-refresh/logout handlers. Both must be reachable while
  // unauthenticated.
  publicPaths: ["/login", "/auth", "/api/auth"],
  // The silent-refresh handler lives UNDER `/auth` so the path-scoped refresh cookie
  // (path `/auth`) is sent to it; a handler under `/api/auth` would never receive that
  // cookie and so could not refresh.
  silentRefreshPath: "/auth/silent-refresh",
  roleRules: [{ pathPrefix: "/admin", roles: ["ADMIN"] }],
});

export const middleware = proxy;

// Run the proxy on everything except Next internals and static assets. The WASM edge
// verifier is loaded through the Node.js runtime (`runtime: "nodejs"`): the
// bundler-target `wasm-bindgen` glue initializes via `__wbindgen_start`, which the
// Node runtime supports but the lighter Edge runtime does not. Verification is still
// purely local (no network call) — "edge" here means "in the middleware", not "on the
// Edge runtime".
export const config = {
  runtime: "nodejs",
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

// Re-exported for visibility; the resolved config is also available for diagnostics.
export { proxyConfig };
