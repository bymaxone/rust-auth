/**
 * E2E harness: start a real Redis (testcontainers) and the Rust `e2e-backend` binary
 * in front of it, and tear them down afterwards. The backend signs HS256 tokens that
 * the Next.js middleware edge-verifies via WASM; sharing the same `JWT_SECRET` /
 * `AUTH_ACCESS_TOKEN_SECRET` is what proves server/edge parity end to end.
 *
 * State is written to `.e2e-state.json` so Playwright's `globalSetup`,
 * `globalTeardown`, and the `webServer` env all see the same backend URL and secret.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { GenericContainer, type StartedTestContainer } from "testcontainers";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const examplesDir = join(repoRoot, "examples");
const STATE_FILE = join(here, ".e2e-state.json");

/** The HS256 secret shared by the backend (signing) and the edge (verifying). */
export const JWT_SECRET = "an-e2e-edge-hs256-secret-key-0123456789ab";
const BACKEND_PORT = 8090;
export const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

type State = { backendUrl: string };

let redis: StartedTestContainer | undefined;
let backend: ChildProcess | undefined;

/** Poll a URL until it answers (any HTTP status) or the timeout elapses. */
async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(url);
      return;
    } catch {
      await delay(250);
    }
  }
  throw new Error(`timed out waiting for ${url}`);
}

/** Start Redis + the backend and record the state for the rest of the run. */
export async function startBackend(): Promise<void> {
  redis = await new GenericContainer("redis:8").withExposedPorts(6379).start();
  const redisUrl = `redis://${redis.getHost()}:${redis.getMappedPort(6379)}`;

  backend = spawn("cargo", ["run", "--quiet", "-p", "e2e-backend"], {
    cwd: examplesDir,
    env: {
      ...process.env,
      REDIS_URL: redisUrl,
      JWT_SECRET,
      BIND_ADDR: `127.0.0.1:${BACKEND_PORT}`,
      RUST_LOG: "warn",
    },
    stdio: "inherit",
  });

  // The backend reaching /auth/me (401 without a cookie) means it is serving.
  await waitForHttp(`${BACKEND_URL}/auth/me`, 120_000);

  const state: State = { backendUrl: BACKEND_URL };
  writeFileSync(STATE_FILE, JSON.stringify(state), "utf8");
}

/** Read the recorded backend URL (used by tests). */
export function backendUrl(): string {
  if (!existsSync(STATE_FILE)) throw new Error("e2e state missing — globalSetup did not run");
  return (JSON.parse(readFileSync(STATE_FILE, "utf8")) as State).backendUrl;
}

/** Stop the backend and Redis, and remove the state file. */
export async function stopBackend(): Promise<void> {
  if (backend && !backend.killed) backend.kill("SIGTERM");
  if (redis) await redis.stop();
  if (existsSync(STATE_FILE)) rmSync(STATE_FILE);
}
