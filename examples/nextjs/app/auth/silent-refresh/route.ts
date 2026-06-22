import { createSilentRefreshHandler } from "@bymax-one/rust-auth/nextjs";

// Cookie-to-cookie refresh: the proxy redirects here when an access token is expired
// but a `has_session` signal is present; on success it relays the rotated cookies and
// redirects back to the original destination, else it clears cookies and sends the
// user to /login.
const backendUrl = process.env.AUTH_BACKEND_URL ?? "http://127.0.0.1:8080";

export const GET = createSilentRefreshHandler({ backendUrl, loginPath: "/login" });
