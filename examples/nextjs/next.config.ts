import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The edge JWT verifier is WebAssembly bundled inside @bymax-one/rust-auth. It is
  // server/edge-only and is never pulled into a client bundle (the HS256 secret must
  // not reach the browser).
  serverExternalPackages: ["@bymax-one/rust-auth"],
};

export default nextConfig;
