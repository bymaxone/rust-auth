# nextjs

A Next.js 16 app using `@bymax-one/rust-auth/nextjs`:

- **`middleware.ts`** — `createAuthProxy` verifies the backend-signed HS256 access
  token **at the edge via WASM** (no network call), gates protected routes, runs
  coarse role-based access control, attempts a silent refresh, and forwards UX-only
  `x-user-*` headers. It **fails closed** without `AUTH_ACCESS_TOKEN_SECRET`.
- **`app/api/auth/*`** — the client-refresh and logout route handlers.
- **`app/auth/silent-refresh`** — the silent-refresh handler, mounted **under
  `/auth`** so the path-scoped refresh cookie (path `/auth`) is sent to it.
- **`app/auth/[...path]`** — a same-origin forwarding route to the Rust backend so
  the HttpOnly cookies land on this origin.
- **`app/dashboard`** — a protected server page that reads the forwarded identity
  headers (a UX convenience; the backend remains the source of truth).

## Run

```bash
# 1. start the backend (in another terminal)
cargo run -p axum-minimal

# 2. build the package, then install + run the app
cd ../../packages/rust-auth && npm run build:wasm && npm run build && cd -
npm install
AUTH_ACCESS_TOKEN_SECRET=<the backend JWT secret> \
AUTH_BACKEND_URL=http://127.0.0.1:8080 \
npm run dev      # http://localhost:3000
```

`AUTH_ACCESS_TOKEN_SECRET` must equal the backend's `JWT_SECRET` so the edge can
verify tokens the backend signed (server/edge parity).

`npm run build` type-checks and builds; CI runs it so a breaking contract change in
the package fails the example build.
