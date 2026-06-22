# axum-oauth-google

The Google OAuth `authorize → callback` flow with a single-use `state` and PKCE
(S256). The redirect URLs are operator-configured at startup and are never
request-derived (no open redirect). The example builds and starts with placeholder
credentials and never contacts Google in CI.

## Run

```bash
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
GOOGLE_CALLBACK_URL=http://127.0.0.1:8082/auth/oauth/google/callback \
cargo run -p axum-oauth-google
# listens on 127.0.0.1:8082 (override with BIND_ADDR)
```

- `GET /auth/oauth/google?tenantId=default` → 302 to Google's consent screen.
- `GET /auth/oauth/google/callback?code=...&state=...` → consumes the `state`
  atomically, exchanges the code with the stored PKCE verifier, fetches the verified
  profile, and applies the `on_oauth_login` decision (link existing / create new).

## TLS note

The bundled `ReqwestHttpClient` ships with **no TLS backend** (the workspace bans
`ring`/OpenSSL), so it speaks plain HTTP only. To actually reach Google over HTTPS,
construct it from a TLS-capable `reqwest::Client` via
`ReqwestHttpClient::with_client(...)`, or provide your own `HttpClient`. This example
wires the plain client so it compiles and starts without pulling a banned TLS stack.
