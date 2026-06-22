import { startBackend } from "./harness";

// Start Redis + the Rust backend before Playwright launches the Next.js webServer and
// the browser. The Next webServer (configured in playwright.config.ts) is pointed at
// this backend and shares its JWT secret for edge verification.
export default async function globalSetup(): Promise<void> {
  await startBackend();
}
