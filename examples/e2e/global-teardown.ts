import { stopBackend } from "./harness";

// Stop the Rust backend and the Redis container after the suite finishes.
export default async function globalTeardown(): Promise<void> {
  await stopBackend();
}
