# axum-minimal

The smallest end-to-end `bymax-auth` service: mount the Axum adapter over the
in-memory `UserRepository` and store doubles (no database, no Redis), then exercise
register → login → `/me`.

## Run

```bash
cargo run -p axum-minimal
# listens on 127.0.0.1:8080 (override with BIND_ADDR)
```

```bash
curl -i -c jar -X POST localhost:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"a@b.test","password":"correct horse battery","name":"A","tenantId":"default"}'

curl -i -c jar -b jar -X POST localhost:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"a@b.test","password":"correct horse battery","tenantId":"default"}'

curl -i -b jar localhost:8080/auth/me
```

## Going to production

Replace `InMemoryUserRepository` with your own `UserRepository` (sqlx / SeaORM /
Diesel) and `InMemoryStores` with the Redis-backed `bymax-auth-redis` stores. The
rest of the wiring is unchanged. Load `JWT_SECRET` from a secret manager.
