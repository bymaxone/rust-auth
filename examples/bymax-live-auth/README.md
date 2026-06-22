# bymax-live-auth

The dogfood integration shape — the production consumer pattern. This is the auth
wiring a real application (Bymax Live) assembles: the full backend surface
(sessions, MFA, platform-admin, invitations) mounted on the **Redis-backed** stores,
exactly as a production deployment runs it. It is a runnable reference, not a
deployable service.

OAuth has its own dedicated reference in [`../axum-oauth-google`](../axum-oauth-google)
(where the provider, state store, and sign-in hook are wired); it is omitted here so
the dogfood stays self-contained without external provider credentials.

## Run

```bash
REDIS_URL=redis://127.0.0.1:6379 \
JWT_SECRET=0123456789abcdef0123456789abcdef \
cargo run -p bymax-live-auth
# listens on 127.0.0.1:8083 (override with BIND_ADDR)
```

With no `REDIS_URL`, startup fails with a clear message — the dogfood deliberately
exercises the **real** Redis store wiring rather than an in-memory stand-in. In a
real deployment you also replace `InMemoryUserRepository` /
`InMemoryPlatformUserRepository` with your database-backed repositories.
