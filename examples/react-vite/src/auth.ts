import { createAuthClient } from "@bymax-one/rust-auth/client";

// One typed client for the whole app. `baseUrl` is empty so requests are same-origin
// (the Vite dev server proxies /auth and /api to the backend); set it to your API
// origin in a cross-origin deployment. `credentials: "include"` is the default, so
// the HttpOnly cookies the backend sets are sent automatically.
export const authClient = createAuthClient({ baseUrl: "" });
