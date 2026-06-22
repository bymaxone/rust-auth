# e2e — Playwright browser end-to-end

A real-DOM end-to-end test of the full stack. It drives Chromium (Playwright manages
its own headless browser — no system browser needed) through:

**login → protected request → silent refresh → logout**

and asserts the Next.js middleware **edge-verifies (via WASM) a token the Rust backend
signed** — server/edge JWT parity proven in a real browser.

## What it wires together

- A real **Redis** (`testcontainers`, `redis:8`) and the Rust **`e2e-backend`** binary
  in front of it (cookie delivery, sessions on) — started in `global-setup.ts`.
- The **Next.js example** served by Playwright's `webServer`, pointed at the backend
  and sharing its `JWT_SECRET` as `AUTH_ACCESS_TOKEN_SECRET` (the edge verification
  key).
- The browser drives the same-origin cookie flow; the middleware runs the WASM
  verifier on the Node.js runtime (`runtime: "nodejs"` — the bundler-target
  `wasm-bindgen` glue initializes there).

## Run (needs Docker + a built package and Next example)

```bash
# 1. Build the package and the Next.js example.
( cd ../../packages/rust-auth && npm run build:wasm && npm run build )
( cd ../nextjs && npm install && AUTH_ACCESS_TOKEN_SECRET=an-e2e-edge-hs256-secret-key-0123456789ab \
    AUTH_BACKEND_URL=http://127.0.0.1:8090 npm run build )

# 2. Install Playwright's chromium and run the suite.
npm install
npx playwright install chromium
npm test
```

The backend, Redis, and the Next.js server are started and stopped by the harness.
