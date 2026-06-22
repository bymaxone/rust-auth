# react-vite

A React 19 + Vite SPA wiring `@bymax-one/rust-auth/react`
(`AuthProvider` + `useAuth` / `useSession` / `useAuthStatus`) and
`@bymax-one/rust-auth/client` (`createAuthClient`) against a running backend.

The Vite dev server proxies `/auth` and `/api` to the backend
(`http://127.0.0.1:8080` — start [`../axum-minimal`](../axum-minimal) first), so the
same-origin HttpOnly-cookie flow works in development.

## Run

```bash
# 1. start a backend (in another terminal)
cargo run -p axum-minimal

# 2. install and start the SPA
npm install
npm run dev      # http://localhost:5173
```

`npm run build` type-checks and produces a production bundle; CI runs it so a
breaking contract change in the package fails the example build.

The package is consumed via `file:../../packages/rust-auth`; build the package first
(`cd ../../packages/rust-auth && npm run build:wasm && npm run build`) so the
`dist/` + `wasm/` artefacts exist.
