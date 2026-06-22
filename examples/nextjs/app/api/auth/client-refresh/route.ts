import { createClientRefreshHandler } from "@bymax-one/rust-auth/nextjs";

// The JSON endpoint the client fetch wrapper POSTs to on a 401. It relays the rotated
// cookies; on failure it returns 401 with the `auth.session_expired` envelope so the
// client can react. Its path matches the client's default `refreshEndpoint`.
const backendUrl = process.env.AUTH_BACKEND_URL ?? "http://127.0.0.1:8080";

export const POST = createClientRefreshHandler({ backendUrl });
