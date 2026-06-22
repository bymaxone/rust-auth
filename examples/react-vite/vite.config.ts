import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// A standard React SPA build. The dev server proxies /auth and /api to the running
// backend so the same-origin cookie flow works during development.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/auth": "http://127.0.0.1:8080",
      "/api": "http://127.0.0.1:8080",
    },
  },
});
