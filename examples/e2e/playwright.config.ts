import { defineConfig, devices } from "@playwright/test";
import { JWT_SECRET, BACKEND_URL } from "./harness";

// The Next.js example is served in front of the Rust backend. It shares the backend's
// HS256 secret as `AUTH_ACCESS_TOKEN_SECRET`, so the edge middleware (WASM) verifies a
// token the backend signed — the parity the suite asserts. The backend itself is
// started in globalSetup (Redis via testcontainers + the e2e-backend binary).
const NEXT_DIR = "../nextjs";
const APP_PORT = 3000;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  reporter: process.env.CI ? "list" : "html",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  use: {
    baseURL: `http://127.0.0.1:${APP_PORT}`,
    trace: "on-first-retry",
    headless: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Build then start the Next.js example. `next build` is run by the CI step before
  // this config loads (so the package is present); `start` serves the production app.
  webServer: {
    command: "npm run start",
    cwd: NEXT_DIR,
    url: `http://127.0.0.1:${APP_PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      AUTH_ACCESS_TOKEN_SECRET: JWT_SECRET,
      AUTH_BACKEND_URL: BACKEND_URL,
      PORT: String(APP_PORT),
    },
  },
});
