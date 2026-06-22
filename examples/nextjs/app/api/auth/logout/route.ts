import { createLogoutHandler } from "@bymax-one/rust-auth/nextjs";

// Best-effort backend logout, then clears the three session cookies and returns
// `{ ok: true }`.
const backendUrl = process.env.AUTH_BACKEND_URL ?? "http://127.0.0.1:8080";

export const POST = createLogoutHandler({ backendUrl });
