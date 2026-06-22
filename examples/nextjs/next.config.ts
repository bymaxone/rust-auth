import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { NextConfig } from "next";

// This example lives inside the monorepo (multiple lockfiles above it). Point the
// output file-tracing root at the repository root so Next does not guess it — without
// constraining module resolution (which `turbopack.root` would, breaking the `file:`
// package symlink).
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const nextConfig: NextConfig = {
  // The edge JWT verifier is WebAssembly bundled inside @bymax-one/rust-auth. It is
  // server/edge-only and is never pulled into a client bundle (the HS256 secret must
  // not reach the browser).
  serverExternalPackages: ["@bymax-one/rust-auth"],
  outputFileTracingRoot: repoRoot,
};

export default nextConfig;
