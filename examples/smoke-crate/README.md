# smoke-crate

The crate-side pre-publish dogfood smoke. It boots `bymax-auth-axum`'s router over a
real `testcontainers` Redis and drives the full happy path —
register → login → `/me` → refresh → `/me` → logout — through the native
`bymax-auth-client`, asserting a real outcome at each step (a wrong-password login is
asserted to map to the typed `InvalidCredentials` error).

This validates the to-be-shipped backend surface before a release. It carries no
runtime code; the smoke is the integration test.

## Run

```bash
cargo test -p smoke-crate            # requires Docker (testcontainers redis:8)
```

The single legitimate skip is Docker being unavailable, in which case the test
returns early rather than failing.
