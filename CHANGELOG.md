# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire/contract surface (token shapes, cookie names, the error envelope) is
treated as the public API for SemVer purposes — a breaking wire change is a major
version bump.

## [Unreleased]

### Added

- Initial workspace scaffolding: the Cargo workspace, the facade and internal
  crate skeletons, the WASM edge binding, the npm package stub, the pinned
  toolchain and lint posture, the supply-chain policy (`cargo-deny` / `cargo-vet`),
  the CI workflow, and the repository governance files.
- `[package.metadata.docs.rs]` on every public crate so docs.rs renders the full
  feature surface with `--cfg docsrs`.
- TypeDoc and ESLint configuration for the `@bymax-one/rust-auth` npm package — the
  JavaScript-side API documentation and lint gate.
- The six official `examples/` apps (`axum-minimal`, `axum-mfa`,
  `axum-oauth-google`, `react-vite`, `nextjs`, `bymax-live-auth`), built and linted
  in CI and excluded from the 100 % coverage workspace.
- Extra CI quality and security gates: CodeQL, OpenSSF Scorecard, a scheduled
  RustSec `audit`, a `cargo public-api` + `cargo-semver-checks` public-surface gate,
  a dependency-budget gate, a time-boxed `cargo-fuzz` smoke, a scheduled
  `cargo-mutants` pre-release mutation gate, and a Security-Invariants (§24) check.
- Non-publishing dogfood smokes (a crate Axum app and an npm Next.js app) and a
  Playwright browser end-to-end suite driving login → request → refresh → logout
  with edge JWT verification.
- `docs/RELEASE.md` documenting the deferred publish pipeline and the one-time
  OIDC / protected-environment setup it requires.
- **Cross-site request refusal** — an `Origin` / `Sec-Fetch-Site` check on
  cookie-authenticated writes, as a tower layer. `SameSite` covers this for
  `Lax`/`Strict`; it does not for `None`, which the library allows and which sends
  the session cookie cross-site. On by default; `cookies.trusted_origins` is
  required as soon as `same_site` is `None`, and refused under any other posture.
- **Breached-password refusal** — the `PasswordBreachChecker` seam with a bundled
  `HibpBreachChecker` (feature `breach`) riding the crate's existing `HttpClient`,
  so a deployment supplies the transport it already has. Only a 5-character SHA-1
  prefix leaves the process, and the checker fails **open** by contract: an
  unreachable corpus must never stop someone changing their password. Off by
  default (`AllowAllBreachChecker`).
- **Absolute session lifetime** — `jwt.absolute_session_lifetime_days` caps how
  long one login can be extended by rotation. `refresh_expires_in_days` bounds a
  token, not a session. Off by default: switching it on ends sessions already
  older than the cap.
- **`email_verified` on the OAuth profile** — `create_with_oauth` was called with
  `Some(true)` unconditionally. No bug today (the bundled Google provider refuses
  an unverified profile before building one), but the first third-party provider
  written against the old contract would have created a verified account from an
  address nobody proved they owned.
- **Per-route rate limits pinned to the shared contract** — the adapter already
  enforced them; what was missing was the agreement, with 21 numbers duplicated
  across two repositories and nothing checking they matched.
- **Header sanitization matched to `nest-auth`, entry for entry** — the map handed
  to host-supplied hooks withheld three names against the sibling's fifteen, so a
  host wiring one audit sink behind both backends received `x-api-key`,
  `proxy-authorization` and every forwarded-identity header from this side and not
  the other. `nest-auth`'s
  `^x-.*-(token|secret|key|password|credential|auth|bearer|signature|hmac)$` is
  reproduced as a suffix test rather than a regex dependency, matching it exactly:
  the leading `x-` is stripped and the remainder must carry a dash of its own, so
  `x-request-token` is withheld and `x-token`, which the pattern also declines, is
  not.
- **Security logging across the core flows** — three events against the sibling's
  seventy. Login lockouts, invalid credentials, MFA lockouts and rejected codes,
  refresh-token reuse, a completed password reset, and every best-effort cleanup
  that failed now emit, with `mask_email` reproducing `nest-auth`'s masking so one
  log pipeline shows one spelling for one account. `SessionNotFound` on the logout
  path stays silent: it is the ordinary outcome for a session already rotated, and
  logging it would bury the outage it exists to surface.
- **`recordEncodings` and `accessTokenClaims` added to the conformance tier** — the
  two sections of the shared contract that decide whether a record written by one
  backend is readable by the other, including the deliberate split where the
  session detail's timestamps are numeric while the refresh session's are ISO-8601.
- **The WebSocket upgrade ticket entered the shared contract.** `wst`, the
  snapshot's field list, and the ticket's own credential format are now declared
  and asserted on both sides. The mechanism was already here and is unchanged;
  what was missing was the agreement, because nest-auth had no equivalent to
  agree with. It does now, so the prefix, the record shape and the tenant-scope
  omission are pinned rather than coincidental.
- **`responseBodies` added to the contract**, which is what caught the mismatch above. It
  declares the client-facing payloads — the login body per delivery mode, the platform body,
  the challenge, the ws-ticket — and both sides assert against what they actually serialize.
  The cookie-mode claim is the load-bearing one: the tokens are in `Set-Cookie` so script
  cannot read them, and a refresh token repeated in the JSON payload would make the HttpOnly
  flag decorative.
- **`credentialFormats` and `errorEnvelope` added too**, which closes the section
  list: every part of the shared contract is now asserted on both sides.
  `credentialFormats` is asserted against what the code actually mints rather
  than against the contract's own prose — the TOTP secret at rest is proven to be
  AES-GCM over the BASE32 *text* by decrypting it and decoding back to the HMAC
  key, which is precisely the regression a merge introduced here and which no
  conformance test could see at the time.
- **`InMemoryStores::fail_next_cleanup_writes`** — arms a finite number of store
  failures so the paths the library deliberately swallows can be asserted rather
  than assumed.

- **`jwt.previous_secrets`** — secrets retired by a rotation, accepted for verification only.
  Rotating the signing secret used to sign every user out at once *and* invalidate every stored
  recovery-code digest, which is keyed by an HMAC derived from that secret: users would lose the
  codes they printed and filed, and find out at the moment they most need them. Both are now
  readable while the old tokens drain. Signing always uses the current secret, so a rotation is
  one-way.
- **`mfa.previous_encryption_keys`** — AES-256 keys retired by a rotation of
  `mfa.encryption_key`. The stored ciphertext carries no key identifier, so changing that key
  made every enrolled user's TOTP secret undecryptable at once, with no way back: the
  authenticator they set up simply stops matching, and nothing in the library could tell them
  why. A secret that opens under a retired key is now re-encrypted under the current one on the
  next successful challenge — TOTP and recovery code alike — so the rotation drains instead of
  requiring the retired key to stay configured forever; a key that still opens every stored
  secret is not retired. `build()` holds each entry to the same bar as the current key (base64,
  exactly 32 bytes, never equal to the current key or to another entry), because a malformed one
  would otherwise surface at a user's first challenge. Same option on both sides.

- **Startup bounds on the parameters that carry a control's strength.** `mfa.totp_window`
  (`0..=10`, `TotpWindowRange`), `mfa.recovery_code_count` (`1..=50`,
  `RecoveryCodeCountRange`), `password.scrypt.block_size` (`>= 8`, `ScryptBlockSize`) and
  `password.scrypt.parallelization` (`>= 1`, `ScryptParallelization`) had no validation while
  every sibling parameter did. The window counts 30-second steps on *either* side of now, so
  `2n + 1` codes are valid at once: at 60 that is 121, and a six-digit code becomes a hundred
  times easier to guess while the configuration still reads as "MFA enabled". Zero recovery
  codes enrols an account with no way back if the authenticator is lost. And scrypt's memory
  cost is `128 * N * r`, so a block size below 8 divides the hardness the cost-factor floor
  exists to guarantee — invisibly, because the parameter that *is* bounded stays intact.
  `nest-auth` enforces the identical ranges.

- **`tenant_id_resolver` is now honoured by every tenant-scoped flow.** The resolver is
  documented as authoritative over the body's `tenant_id` when configured, which is the whole
  anti-spoofing promise — but only `login` and `register` called it. `initiate_reset`,
  `reset_password`, `verify_reset_otp`, `resend_reset_otp`, `verify_email` and
  `resend_verification_email` read the caller's value verbatim, so on a deployment that
  derives the tenant from the request a caller on one tenant could drive reset and
  verification mail at accounts in another, and a reset started under the resolved tenant
  could never be completed because the two steps derived different identifiers.
  **Breaking:** those six methods now take `&RequestContext` as their final argument; the
  axum routes supply it through the existing `RequestMeta` extractor. `nest-auth` takes the
  same change as the Express request.

- **`POST /auth/logout` no longer requires a live access token.** The route sat behind the
  `AuthUser` extractor, so a user returning after their access token expired got a 401 and the
  engine never ran — the refresh session stayed live for its full lifetime on a device the
  user had just told the system to sign out. The refresh token authorizes the operation now,
  and `AuthEngine::logout` reads the session's owner from the stored record rather than taking
  it from the caller. The access token is still verified (signature + pinned algorithm) before
  its `jti` is blacklisted, waiving only the expiry check — an unverified one would let a
  caller revoke a token they do not own by naming its id. **Breaking:** `logout` drops its
  `user_id` parameter. `nest-auth` takes the same change.

- **MFA enrolment re-authenticates against the account password.** `mfa_setup` was guarded by
  the access token alone, so a token lifted by XSS or from a shared machine could enrol an
  authenticator the attacker holds — and the enable then revokes every session and bumps the
  epoch, locking the real owner out of an account they still know the password to, with the
  recovery codes displayed only to the attacker. ASVS requires re-authentication before an
  authentication factor changes; `disable` already demanded a TOTP code. An account
  provisioned purely through OAuth has no local password and is exempt. **Breaking:**
  `MfaService::setup` and `AuthEngine::mfa_setup` take `Option<&str>` for the password, and
  the two setup routes accept a `password` body field. `nest-auth` takes the same change.
- **The OAuth `state` is bound to the browser that started the flow.** The `state` nonce was
  validated against the store alone, which proves only that *somebody* started a flow. An
  attacker could run their own authorization, complete consent at the provider, capture the
  resulting `?code=…&state=…` callback URL without visiting it, and lure the victim there: the
  victim's browser then received the attacker's session, and everything they did next — a
  payment method, an uploaded document, a linked account — landed in the attacker's hands.
  PKCE does not cover this, because the verifier is held server-side and replayed for whoever
  presents the state. `oauth_initiate` now returns an `OAuthRedirect { authorize_url, state }`
  and the Axum adapter plants the raw state as an HttpOnly `oauth_state` cookie; the callback
  refuses any request that does not carry it back, as RFC 6749 §10.12 requires. The cookie is
  `SameSite=Lax` — the provider's callback is a cross-site top-level GET, and `Strict` would
  withhold the cookie on exactly that hop — and the check runs *before* `take_state`, so a
  lured victim cannot burn a state the legitimate browser is still entitled to spend.
  **Breaking:** `AuthEngine::oauth_initiate` returns `OAuthRedirect` instead of `String`, and
  `AuthEngine::oauth_callback` takes the cookie as its fourth argument. `nest-auth` takes the
  same change.
- **`cookies.resolve_domains` is honoured.** The field was configurable and never read: a
  deployment that set it got host-only cookies anyway, with nothing to say so. The adapter now
  asks the resolver per request — handing it the request host with the port stripped — and
  stamps the answer on all three session cookies and on the logout clear, which must mirror it
  or the browser keeps the cookie it was asked to delete. Only the first domain is used: a
  browser rejects a `Set-Cookie` whose `Domain` is not a suffix of the responding host
  (RFC 6265 §5.3.6), so a second one on the same response is either a duplicate scope or a
  value that gets dropped. Unset — the default — still means no `Domain` attribute at all,
  which is what a session cookie should be; `nest-auth` now defaults the same way.
- **The provider's error callback reaches the OAuth error handling instead of the validator.**
  RFC 6749 §4.1.2.1 defines a callback carrying `error` and no `code` — the response a provider
  sends when the user declines consent. `OAuthCallbackQuery` required `code`, so a user who
  simply clicked "Cancel" got a validation envelope rather than the configured error redirect.
  `code` is now optional and the handler refuses a callback carrying neither it nor `error`.
  The provider's value is logged and never echoed: it is provider-chosen text that would
  otherwise land in a URL the browser follows, and `oauth_failed` already says everything the
  library is willing to vouch for. `nest-auth` takes the same change.
- **`Set-Cookie` is marked sensitive on every response**
  (`SetSensitiveResponseHeadersLayer`). The request side was already redacted from traces; the
  response side is where the credential travels outward — every successful login, refresh and
  OAuth callback answers with `Set-Cookie: access_token=<a signed JWT>`. A deployment whose
  tracing records response headers, a reasonable thing to switch on while debugging, was
  writing live session tokens into its logs, where they outlive the session and are read by
  people it was never issued to.
- **`initiate_reset` shares the resend cooldown.** `resend_reset_otp` was throttled and
  `initiate_reset` was not, which made the throttle decorative — a caller just used the other
  door. It also made the OTP's 5-attempt ceiling per-issuance rather than per-account, because
  every issuance rewrites the record with `attempts: 0`: an attacker who knew an address could
  loop "initiate, guess five times" at a six-digit code indefinitely, mailing the victim once
  per lap. Both entry points now claim one budget under one key. `nest-auth` takes the same
  change.
- **The absolute session-lifetime cap is enforced on the grace-recovery path.** The check ran
  against the seed, and on that path the seed is the placeholder used when the live key is
  already gone — its `family_created_at` is `None`, so the check returned early and applied
  nothing. A lineage that had just passed its cap could still mint a fresh access token and a
  full-length refresh session by presenting a token inside its grace window: the cap ended
  normal rotation and left the one remaining door open. Both planes take the check.
- **`GET /auth/me` is pinned in the wire contract, and the TypeScript client reads the shape
  the server actually sends.** The route returns the bare user object; the client still
  unwrapped a `{ user }` envelope, so `getMe()` resolved to `undefined` while every other
  signal said authenticated — `AuthProvider` reported a session with no user, and a consumer
  reading `user.role` threw on a perfectly good login. The test that should have caught it
  mocked the old envelope. The contract had no `me` entry, which is why nothing else did.
- **`POST /auth/logout` and `POST /auth/ws-ticket` are rate-limited** (20/60s each, pinned in
  the contract). Logout is public by necessity and was unlimited; ws-ticket is authenticated
  but writes a fresh single-use key per call.
- **The Next.js proxy strips the caller's `x-user-*` headers on a public path** — that arm
  forwarded them verbatim, so the advisory identity headers were forgeable with no token at
  all — and `isPublicPath` now matches at a segment boundary, so `/login` no longer exempts
  `/loginhistory`.
- **The platform recovery-code challenge gates on winning the temp-token consume**, which the
  dashboard path already did. Found while chasing a coverage gap the enrolment change exposed:
  the two planes carry the same logic separately, and only one had been fixed.

### Changed

- **Family-lineage reuse detection replaces the previous sentinel.** A login opens
  a family; every rotation inherits it; a replay past the grace window revokes that
  lineage and only that lineage. `revoke_family` prunes the **prefixed** index
  member (`rt:{hash}`), not the bare hash — the index format changed underneath it,
  and pruning a bare hash would have left every revoked session listed until the
  index itself expired.
- **The rotation Lua scripts no longer decode stored records.** `nest-auth` drives
  its end-to-end tier against an in-memory Redis whose Lua VM has no `cjson`, so a
  script that decodes JSON is one the shared contract cannot be exercised against
  on that side. The grace record's family and the family owner's id are parsed by
  the caller instead, with a real parser.
- **Signing out other devices now advances the token epoch.** Deleting a refresh session stops
  that device rotating, but its already-issued access token is stateless and kept verifying for
  the rest of its lifetime — up to `jwt.access_expires_in` of continued access on a device the
  user had just revoked. Someone doing that because they believe a device is compromised means
  now. The caller's own access token is invalidated too, and the caller is the one party who
  recovers instantly: their refresh session is the one deliberately preserved. **Behavioural**
  for a client without silent refresh, which sees one 401 after the call.
- **The default scrypt cost is `N = 2^17`**, OWASP's recommended minimum, up from `2^15`. Both
  the config default and `ScryptParams::default()` moved — they are two declarations of one
  number and had to agree, since a mismatch makes every hash written by one immediately "stale"
  to the other and rehashes on every login. **Behavioural**: roughly 128 MiB and ~100 ms per
  hash. Lower it deliberately if the memory is not there.
- **A duplicate registration now spends the same derivation as a new one.** Skipping it was
  cheaper and leaked: a taken address answered in single-digit milliseconds against ~100 ms for
  a free one, which enumerates accounts by clock regardless of the status code.
- **The grace window is single-shot.** The pointer was served on every request
  inside the window, so one captured consumed token could mint a session
  repeatedly. It is consumed on use now, matching `nest-auth`.

### Removed

- **Every legacy-compatibility path in the credential surface.** Both libraries are new and
  unreleased into production, so a parsing allowance for a corpus that does not exist is a
  widened input for nothing — and each of these sat in the credential-verification core:
  - the `scrypt:{salt_hex}:{hash_hex}` nest-compat password reader, with its fixed
    `N = 2^15` assumption and its bounded-hex parser,
  - the UUID-v4 refresh-token shape,
  - and the corresponding `refreshTokenLegacy` / `recoveryCodeDigestLegacy` contract entries.

### Fixed

- **An auth-state change now revokes the outstanding access tokens too.** Enabling or
  disabling MFA, and the platform "log out everywhere" (`revoke_all_platform_sessions`),
  revoked the refresh sessions but left every access token working to expiry — the enable
  path even carried a comment claiming the current session would continue, which `revoke_all`
  had never made true. For MFA enable that is the worst possible window: every pre-enable
  token is stamped `mfa_enabled: false`, and the MFA gate refuses only
  `mfa_enabled && !mfa_verified` — so a stolen token kept clearing every MFA-gated route at
  the exact moment the user enabled a second factor because they suspected that theft. All
  three flows now bump the plane-scoped token epoch alongside the session sweep, the same
  rule the password-reset flow already applied. Verification has always enforced the epoch on
  both planes; what was missing was anything advancing it. Same change on both sides.
- **Every response of the axum router is stamped `Cache-Control: no-store`**
  (plus `Pragma: no-cache`), via `SetResponseHeaderLayer` in the middleware stack. RFC 6749
  §5.1 requires it on any response carrying a token, and a CDN or corporate proxy that caches
  a login response serves one user's tokens to the next caller. A router-wide layer rather
  than per handler, so a future route cannot forget it. `nest-auth` stamps the identical
  headers via a controller interceptor.
- **`mfa_enabled` is required on a stored session record.** `#[serde(default)]` made a missing
  value read as `false`, which turns a truncated or corrupt record into a silent second-factor
  bypass: the gate refuses only a token whose claims say `mfa_enabled && !mfa_verified`, so an
  absent field reads as "no second factor here" and the rotated token clears every MFA-gated
  route. A record that cannot be read is now no session at all — a login for the holder, and no
  bypass for anyone else. nest-auth made the same change.


- **`PlatformAuthResult`'s account field was named `user` while the wire says `admin`.** The
  adapter renamed it while building the response, so the TypeScript generated from the struct
  described a key the server never sends: a consumer reading `result.user` got `undefined` at
  runtime. The struct field is now `admin`, so the type, the struct and the body agree, and the
  adapter no longer remaps. **Breaking** for Rust callers reading `PlatformAuthResult::user` —
  none published, since the crate is unreleased. The wire is unchanged.
- **The error envelope omitted `details` instead of sending `null`.** The shared
  contract declares the key present with an `object|null` value, which is what
  nest-auth emits and what the one client library decoding both backends expects
  — `undefined` is not `null` to it, and a key that is sometimes absent makes
  every reader handle two shapes for one meaning. The field carried a
  `skip_serializing_if` and a doc comment asserting the omission was deliberate,
  while the test next to it said the body "must be exactly
  `{ error: { code, message, details } }`" and then asserted a body without it.
  Nothing caught the disagreement because `errorEnvelope` was the one contract
  section neither implementation asserted.
- **The in-memory store's grace window was weaker than the Redis one it stands in
  for.** It neither consumed the pointer nor checked the lineage was still alive,
  so a replay could recover repeatedly and a pointer left behind by an earlier
  rotation could remount a family reuse detection had just revoked. The conformance
  tier and `nest-auth`'s end-to-end tier both run against this store, so the gap hid
  exactly the divergence those tiers exist to catch.
- **A grace pointer could resurrect a revoked lineage.** Reuse detection only
  proves the *replayed* token's own pointer expired; a pointer planted by an
  earlier rotation of the same lineage can still be live, and recovering from it
  minted a session carrying the revoked family id. A recovery now requires its
  family index to still exist. Red-checked with a three-token lineage.
- **A consumed token replayed after a revoke-all reported `Invalid` rather than
  `Reused`.** The `cf:` marker deliberately outlives both the pointer and the
  revoke-all, so a replay stays a theft signal. It never minted a session either
  way.
- **`handlers.ts` in `packages/rust-auth` had no tests at all** — the one module
  that writes `Set-Cookie` back to a browser. It is at 100 % lines now, and the
  package runs under a coverage ratchet in CI so it can only go up.

### Internal

- **The mutation gate's configuration was never being read.** `cargo-mutants`
  loads `.cargo/mutants.toml` and nothing else; the file sat at the repository
  root, where it is ignored in silence — so `examine_globs` scoped nothing,
  `bindings/`, `examples/` and `fuzz/` were being mutated despite the excludes,
  and CI had been running the same way. Moved, with the path requirement written
  into its header and a one-line check (`cargo mutants --list` must print only
  `crates/` paths). With the file finally read, `additional_cargo_args` supplies
  `--all-features` and cargo refuses the flag twice, so the copy on CI's command
  line is gone.
- Every surviving mutant the sweep reported is closed — killed by a new test or
  recorded in `.cargo/mutants.toml` with the reason it cannot be. Re-running the
  sweep over the survivors is what caught four fixes that asserted the wrong
  thing, so each of those is red-checked by hand. The first full sweep under the
  corrected configuration confirmed it: **1,630 mutants, 1,242 caught, 95 detected
  by timeout, 293 unviable, zero survivors** (8 h wall clock).
- A second full sweep, after the parity work above: **1,652 mutants — 1,269
  caught, 89 detected by timeout, 293 unviable, 1 survivor** (9 h). The survivor
  was `!matches!(error, SessionNotFound)` on the logout path, which decides
  *which* cleanup failures an operator is told about and has no other observable
  effect — the logout returns `Ok` either way. It is closed, and the sweep before
  it had found nine more of the same character: a constant only ever read back
  through itself, an armed-failure counter never shown to run out, a log branch
  with no assertion surface, and a documented equivalent whose line anchor the new
  logging had pushed out from under it. Not one was a bug in the library.
- Recorded for whoever tunes the gate next: the timeouts sit almost entirely in
  the container-backed stores (`bymax-auth-redis`, plus a few in
  `bymax-auth-client`). A mutation there is detected by the suite *hanging* rather
  than asserting, and each one spends the full timeout window — roughly half the
  run's wall clock. Shortening the window would buy hours at the cost of gate
  integrity, since a legitimately slow test cut short is reported as detected and
  would hide a survivor; the sound fix is making those tests fail fast instead.
  For the same reason the two are reported apart rather than summed: 1,269 caught
  by assertion is the number that carries the stronger guarantee.

[Unreleased]: https://github.com/bymaxone/rust-auth/commits/main
