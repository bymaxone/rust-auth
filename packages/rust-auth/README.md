# @bymax-one/rust-auth

Frontend half of [`bymax-auth`](https://github.com/bymaxone/rust-auth): the TypeScript client,
React bindings and Next.js helpers for a backend built on the `bymax-auth` Rust crates. Wire
types and constants are generated from the Rust source, and the edge JWT verifier is the same
HS256 implementation as the backend, compiled to WebAssembly and bundled in this package.

## Install

```bash
pnpm add @bymax-one/rust-auth
```

`react` (19) and `next` (16) are optional peer dependencies: install them only for the
subpaths that use them.

## Entry points

| Subpath                       | What it exports                                                                  | Peer deps  |
| ----------------------------- | -------------------------------------------------------------------------------- | ---------- |
| `@bymax-one/rust-auth/shared`  | Generated types, error codes, route and cookie constants, `AuthClientError`      | None       |
| `@bymax-one/rust-auth/client`  | `createAuthClient` and `createAuthFetch` (native `fetch`, single-flight refresh) | None       |
| `@bymax-one/rust-auth/react`   | `AuthProvider`, `useSession`, `useAuth`, `useAuthStatus`                         | React 19   |
| `@bymax-one/rust-auth/nextjs`  | `createAuthProxy`, the refresh and logout route handlers, `verifyJwtToken`       | Next.js 16 |

The `/nextjs` subpath is server-only: it loads the WebAssembly verifier and reads the HS256
secret, so never import it into a Client Component. The verifier runs on the Node.js runtime and
is a fast reject, not the authority: it cannot see revocations, so anything that must not
outlive one has to reach the backend.

## Documentation

Setup, configuration, the HTTP endpoint table and the full frontend API reference are in the
[repository README](https://github.com/bymaxone/rust-auth#readme).

## License

MIT
