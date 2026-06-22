# smoke-npm

The npm-side pre-publish dogfood smoke. It consumes the installed
`@bymax-one/rust-auth` (the real published layout, via `file:`) and proves the
to-be-shipped frontend surface works:

1. the `./client` and `./shared` subpaths import and expose their public symbols, and
   the `./nextjs` surface type-checks (it is server-only at runtime);
2. a token signed by the backend's HS256 (reproduced with Node `crypto`) verifies at
   the **edge** through the shipped WASM, and a wrong-secret / tampered / expired token
   is rejected — server/edge parity.

## Run

```bash
# Build the package first so dist/ + wasm/ exist.
cd ../../packages/rust-auth && npm run build:wasm && npm run build && cd -

npm install
npm run typecheck   # ./client/./shared/./nextjs types resolve
npm run smoke       # edge HS256 parity against the shipped wasm
```

A non-zero exit blocks the tag in the release pre-publish step.
