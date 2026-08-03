# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire/contract surface (token shapes, cookie names, the error envelope) is
treated as the public API for SemVer purposes — a breaking wire change is a major
version bump.

## [Unreleased]

### Added

- **`jwt.issuer` and `jwt.audience` — binding tokens to who minted them and who they are for.**
  Optional and `None` by default, so an existing deployment is unchanged. When set, the value
  is stamped on every token this backend mints — dashboard, platform and MFA challenge alike —
  and **required** on every token it verifies: one carrying a different value, or none at all,
  is rejected. Accepting an unstamped token would give an attacker a way to opt out of the
  check simply by omitting the claim.

  This matters because HS256 means the verifier can also sign: every service holding the secret
  to check a token can mint one, so audience binding is what stops a token minted for one
  service being replayed at another that trusts the same secret. The check sits at the single
  verification chokepoint, so a retired signing key does not waive it — a retired key buys a
  token signature acceptance and nothing else.

  Opt-in because both backends of a shared deployment must carry the same pair or they stop
  accepting each other's tokens, and because turning it on invalidates the access tokens
  already in flight. An empty string reads as unconfigured rather than as "require the empty
  issuer". `DashboardClaims`, `PlatformClaims` and `MfaTempClaims` gain `iss`/`aud` fields,
  both `Option<String>` and both skipped when absent, so the wire shape is unchanged for a
  deployment that configures neither.


- **Changing the address on an account** — `POST /auth/email/change` and
  `POST /auth/email/change/confirm`, opt-in behind `controllers.email_change`. The address is
  the account's recovery credential: whoever controls it can drive a password reset to a
  mailbox the owner does not read. Until now the library could mint one and never move it, so
  a user whose address died was locked out permanently.

  Two steps, and the split is the security property. The request re-proves the current password
  and mails a single-use token to the NEW address; nothing about the account changes. The
  confirmation consumes that token and is public, because the person holding it is proving
  control of a mailbox rather than of a session. The old address is then notified (NIST SP
  800-63B §4.6) — the last message the owner can receive somewhere they still control, and what
  turns a silent takeover into one they can see.

  No session is revoked: anyone who can complete the flow could already sign in, so ending the
  caller's devices would cost the user and buy nothing. The stored token is bound to the
  password in force when it was minted, so a planted request dies the moment the victim changes
  their password; uniqueness is re-checked at confirm time, because the two steps are separated
  by the whole TTL.

  BREAKING: `UserRepository` gains `update_email`, `PasswordResetStore` gains
  `put_email_change` / `consume_email_change`, and `EmailProvider` gains a **required**
  `send_email_change_verification`. That one is required rather than defaulted on purpose — a
  no-op default would swallow the token and leave the flow minting `ec:` keys nobody receives,
  a failure that looks like success from every side. The notice to the old address
  (`send_email_changed_notification`) is defaulted, like the other notices.


- **`AuthEngine::unlock_account(email, tenant_id)` — clearing a brute-force lockout.** A
  lockout is a denial of service the library imposes on its own users, and it could only be
  waited out: the counter is keyed by an HMAC of `{tenant_id}:{email}` under the library's own
  HMAC key, so a host facing "I am locked out and I need in now" had nothing to offer — and
  neither did an operator watching an attacker deliberately lock one account out of its own
  service. Undoing that is part of the defence, not a convenience (ASVS v5 §6.1.1). It grants
  no access: the password, the status gate, the verification gate and MFA all still apply. No
  adapter route ships with it, because who may unlock whom is a decision only the application
  can make.

- **`POST /auth/invitations/revoke` — withdrawing a pending invitation.** An invitation
  provisions an account, at a role, inside a tenant, to whoever holds the link — a credential
  in every sense — and once sent it stayed redeemable for its whole TTL with nothing an
  operator could do about it. ASVS v5 §6.1.1 expects an administrative path to invalidate a
  credential that should no longer work. Nothing on the issuing side could even *name* a
  pending invitation, since the record is keyed by the hash of a token only the invitee's
  mailbox ever held, so the withdrawal needs an index: `invidx:{tenantId}:{sha256(email)}`
  carries the invitation's TTL and points at its record, with the email hashed so a dump of
  the keyspace does not enumerate who a tenant has been inviting. Re-inviting an address now
  supersedes the previous invitation through that index rather than adding a second live
  token. The revoker is held to the same bar as the issuer (in the tenant, in good standing,
  out-ranking the granted role), and the route answers `204` whether or not anything was
  pending. Adds five `InvitationStore` methods (`put_invitation_index`,
  `read_invitation_index`, `take_invitation_index`, `read_invitation_by_hash`,
  `delete_invitation_by_hash`) — implementors of the trait must supply them.


- **Failure-side hooks: `on_login_failed`, `on_lockout`, `on_refresh_token_reuse_detected`**
  (`crates/bymax-auth-core/src/traits/hooks.rs`). Every existing hook fired on a success
  path, which left the failure side of authentication with no structured seam at all: a
  burst of wrong passwords, an account tripping its lockout, and a stolen refresh token
  being replayed existed only as English log lines whose wording is not a contract and whose
  change is not semver-visible. ASVS v5 §16.3.1 expects authentication operations to be
  logged with their outcome and §6.1.1 an *adaptive* response, which needs a signal to adapt
  to. `on_login_failed` carries a `LoginFailureReason` and — only when the address resolved —
  the user id, so a consumer can tell "someone is guessing at this account" from "someone is
  spraying addresses", a distinction the uniform `InvalidCredentials` response deliberately
  hides from the caller but not from the deployment. `on_lockout` fires on the attempt that
  **crosses** the threshold, not the next one: an attacker who trips the lock and walks away
  would otherwise never produce the event. All three are fire-and-forget — a hook that fails
  is logged and dropped, and the refusal the caller receives is unchanged.


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
- **Refresh re-reads the account and re-applies the status and email-verification gates.**
  Rotation worked entirely from the store record, so nothing on that path ever looked at the
  user again — and rotation is the door a signed-in caller actually uses. A banned account
  renewed its access token for the refresh token's whole lifetime (ASVS v5 §7.4.2 requires
  disabling an account to terminate its sessions), and an address that was never verified held
  a session indefinitely, because `register` issues one deliberately and only `login` ever
  checked. A blocked account that touches the system now has every session revoked and its
  epoch bumped in the same breath; an unverified one is refused without compensation, since an
  unproven address is an unfinished onboarding and revoking would kill the token rendering the
  "check your inbox" screen. **Breaking:** `AuthEngine::refresh` returns `RefreshedSession`
  (the rotated tokens plus the account), which also removes the adapter's second verify-and-look-up.
- **`AuthEngine::revoke_all_sessions(user_id)`** — the dashboard twin of `platform_revoke_all`,
  for the moment a host suspends, bans or deletes an account. `revoke_all_except_current` could
  not serve: it wants the hash of a session to keep, and an administrator banning somebody else
  has none.
- **`POST /auth/platform/logout` no longer requires a live access token.** It required
  `PlatformUser`, which refuses an expired one, so an operator who stepped away for longer than
  the access lifetime could not sign out and the refresh session of the highest-privilege
  identity in the system stayed live on a console they believed they had left. Same fix the
  dashboard plane took earlier in this cycle. **Breaking:** `AuthEngine::platform_logout` drops
  its `admin_id` parameter — the owner is read from the stored record — and returns it instead.
- **`DELETE /auth/sessions/all` accepts the refresh token from the body and refuses when it
  cannot identify the caller's session.** It read the cookie only, and a bearer-mode deployment
  plants none — so it could never identify one, and the engine treated that as "revoke nothing,
  successfully". A user with a compromised second device clicked "sign out my other devices",
  got 204, and nothing happened. `nest-auth` has always refused this case with
  `session_not_found`.
- **The in-memory `SessionStore` double clears grace pointers on `revoke_all`**, as the real
  Lua does. Keeping them made the double *weaker* than production: a token inside its grace
  window would still recover a session after "sign out everywhere", a password reset, or an MFA
  change — the exact property those flows exist to guarantee, asserted against a fake that
  could not break it.
- **`POST /auth/password/change` — authenticated password change.** ASVS v5 §6.2.2 and §6.2.3
  require it at **Level 1** — "users can change their password", and the change "requires the
  user's current and new password" — and it was the one credential operation this library did
  not own. Without it a host either sends users through the *unauthenticated* recovery flow to
  rotate a password they already know, or hand-rolls hashing against `bymax-auth-crypto` with
  duplicated parameters and no guarantee the sessions are revoked afterwards. The current
  password is what makes it safe: a session alone is not proof of identity, so a token lifted
  by XSS or from a shared machine could otherwise rotate the credential, lock the real owner
  out of an account they still know the password to, and keep the attacker in. Every other
  session ends on success and the epoch is bumped (§7.4.3); the caller's own survives when the
  request carries its refresh token. `nest-auth` takes the same change.
- **`CommonPasswordChecker` is the default password screen.** NIST SP 800-63B §3.1.1.2 states a
  verifier **SHALL** compare a prospective secret against a blocklist of commonly used values,
  and ASVS v5 §6.2.4 asks for it at **Level 1**. The previous default, `AllowAllBreachChecker`,
  approved everything: a deployment on defaults accepted `password1` and `12345678`, and the
  brute-force machinery never fired, because a spraying campaign that tries one password across
  ten thousand accounts never crosses any single account's threshold. The new default is
  offline, which is what lets it be a default where the HIBP checker could not — it refuses
  common base words, keyboard walks, repeats, sequential runs, fragments padded out with
  decoration, and any *decorated* form of those: `Password1`, `P@ssw0rd` and `PASSWORD123!`
  reduce to one base, which is why a few hundred entries stand in for a much longer list. It is
  a floor, not a corpus: `CommonPasswordChecker::with_extra_words` adds the context-specific
  words §6.2.11 asks for, and the HIBP checker remains the opt-in upgrade to a real breach
  corpus. `AllowAllBreachChecker` stays available for a deployment with a deliberate reason to
  screen nothing. **Breaking:** a deployment that relied on the approve-everything default must
  accept the screen or opt back out explicitly.
- **`EmailProvider::send_password_changed`** — fired after an authenticated change and after a
  completed reset. NIST SP 800-63B §4.6 requires the subscriber to be notified through a channel
  independent of the transaction that bound the new credential, and this was the one credential
  change the trait stayed silent about while announcing every MFA change unprompted. Defaulted
  to a no-op so an existing provider keeps compiling.
- **An invitation is re-validated against its inviter at redemption.** The inviter's authority
  was checked when the link was minted and never again, so for the token's whole life the
  invitation outlived the person behind it: an admin could send one, be banned and stripped of
  their role, and the invitee would still arrive as an admin of that tenant with a live session.
  That is a clean way to keep a foothold across the account kill switch, which makes the switch
  advisory. The inviter must now still exist, still be in good standing, still belong to the
  tenant, and still out-rank the role being granted — answered as an invalid token, because the
  redeemer is not the one who lost authority. `nest-auth` takes the same change.
- **A completed reset or password change invalidates the proofs issued beside it.**
  `ResetContext` gains `passwordFingerprint`, a digest of the password hash in force when the
  proof was minted; a proof is refused once that no longer matches. Several proofs can be alive
  at once — a 60-second send cooldown against a 600-second TTL allows up to ten — and completing
  one left the rest valid, which is the wrong end state exactly when it matters: a victim who
  resets *because* an attacker read a link from their mailbox had not closed the link the
  attacker read. The hash itself never leaves the repository, and an absent field is read as
  "no binding" so a rolling deploy does not break the resets already in flight. Pinned in
  `conformance/wire-contract.json`.
- **The platform recovery-code challenge gates on winning the temp-token consume**, which the
  dashboard path already did. Found while chasing a coverage gap the enrolment change exposed:
  the two planes carry the same logic separately, and only one had been fixed.

- **`VerifyOptions::expected_iss` / `expected_aud`, enforced inside `verify`.** The binding was
  checked by the engine after `bymax_auth_jwt::verify` returned, so the `wasm32` edge build — a
  Worker validating a session cookie, with no engine behind it — accepted a token minted for a
  different service. With HS256 the verifier can also sign, so "a different service that trusts
  the same secret" is the realistic attacker, not a hypothetical one. The check moves into the
  verifier, leaving one implementation of the rule; the engine passes its configured binding in
  and `verify_jwt_hs256` takes the pair too. A token carrying no such claim is refused as firmly
  as one carrying the wrong value. **Breaking:** `VerifyOptions` gains a lifetime, and the WASM
  entry point two optional arguments.
- **A concurrency limiter around the password KDF.** `spawn_blocking` bounds nothing useful:
  Tokio's blocking pool defaults to 512 threads and each derivation holds ~16–19 MiB for its
  whole run, so a few hundred concurrent logins reach gigabytes of resident memory — on a route
  an unauthenticated caller drives, because the derivation runs before the password is known to
  be right and the absent-user path runs one deliberately. A semaphore admits one per core,
  which is the useful ceiling for CPU- and memory-bound work; past it, requests queue, and the
  wait is identical for a real and an absent account. `nest-auth` reaches the same bound through
  libuv's four-thread pool.
- **`identifierPreimages`, `requestFieldBounds` and `errorCatalog` in the shared contract.** The
  preimages each backend HMACs, the length bounds every request DTO applies, and the full
  `auth.*` vocabulary with the codes that must never reach a client. Both conformance tiers
  assert against them by exercising the real derivations and the real validators. Writing the
  catalog down immediately found that this crate's own catalog test was missing three codes it
  does emit.

### Changed

- **A recovery code is claimed before it is accepted.** Consuming one is a read-modify-write
  against the consumer's user repository: the challenge reads the whole array, removes one
  entry, and writes the rest back. Two challenges landing together both read the array
  containing the code, both match it, and both write — one code minting two sessions, which is
  the one property a recovery code has. The per-token consume does not cover it, because two
  logins hold two temp tokens. The engine cannot make the consumer's repository atomic, so it
  claims the code in the store it owns: `MfaStore::claim_recovery_code` sets
  `rcu:{hmac(plane:userId:code)}` with `NX EX`, and the loser reads as an invalid code — which
  is what a code already spent is. Same construction as the TOTP anti-replay marker, for the
  same reasons. Implementors of `MfaStore` must supply the new method.


- **The session index is maintained by the rotation script, not after it**
  (`crates/bymax-auth-redis/src/lua/refresh_rotate.lua`). The script gained `KEYS[6]`
  (`sess:{userId}`) and two member prefixes, and does the index bookkeeping itself. Doing it in
  the store after the script left a window between the atomic consume and the `SADD` in which
  `revoke_all` could sweep the index without seeing the session the rotation had just minted:
  that session survived a revocation the user was told had happened, and went on rotating —
  re-stamping a fresh access token under every later epoch, so the token epoch did not contain
  it either. The window is attacker-aimable: a thief holding a stolen refresh token and
  refreshing in a loop is most likely to be mid-rotation exactly when a password reset is
  trying to evict them. Inside the script the two operations serialize. What stays outside is
  the per-session detail, which the revocation never reaches through, now issued as an atomic
  `MULTI`. Held byte-compatible with nest-auth, which rotates the same sessions.


- **`SessionStore::revoke_family` now returns the account the family belonged to**
  (`Result<Option<String>, AuthError>`). Reuse detection had no way to name its victim: the
  replayed token's own `rt:` key is deleted when it is rotated, so by the time the replay is
  caught the family index is the only surviving link between that token and an account — and
  the revocation already reads a member record to find the session index it prunes. Returning
  what it found there turns the strongest compromise signal the library produces from an
  anonymous log line into an attributable event. Implementors of the trait must widen the
  return type; returning `Ok(None)` preserves the previous behaviour.


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

- **Every OTP failure answers `auth.otp_invalid`, in the same time.** `forgot_password` answers
  the same whether or not the address exists — but it only writes an OTP record when it does, so
  `auth.otp_expired` for an absent record and `auth.otp_invalid` for a wrong code turned that
  uniform answer definitive after one extra request. `auth.otp_max_attempts` said the same thing
  more slowly, since only a record that exists can reach a ceiling. Both collapse through
  `to_wire`, the treatment the three token sentinels already get, and `AuthError::http_status`
  now reads the **wire** code — otherwise the oracle survived as 429-vs-401, which is also where
  the two libraries disagreed on the status for one failure.
- **The invitee index is keyed by an HMAC of the address.** It used a bare SHA-256, which an
  address carries far too little entropy to survive, and this key is the one handle anyone
  reading a keyspace dump has on who a tenant has been inviting. **Breaking:** the
  `InvitationStore` methods take the derived identifier rather than the raw address, and
  invitations pending across the upgrade stay redeemable but can no longer be superseded or
  withdrawn by address.
- **`revoke_invitation` answers an outranked revoker exactly as it answers an address with
  nothing pending.** The caller names an address and nothing else, so `InsufficientRole` said
  "there is a pending invitation here, at a role above yours" while `Ok(false)` said "there is
  none" — an oracle any member could walk an address list through, and precisely the disclosure
  hashing the address into the index exists to prevent. The revoker's own standing is a fact
  about the caller, so it still refuses out loud, and now does so before any lookup.
- **The new password is judged before any reset proof is spent.** Every proof is single-use and
  consumed atomically, so a screen rejection that arrived afterwards burned it: the caller was
  told their password was unacceptable and, in the same breath, that the credential they needed
  to fix it was gone.
- **Request bounds are held identical to `nest-auth`'s** and pinned by `requestFieldBounds`. The
  address, the tenant, the display name, the three reset proofs, the invitation token and five
  accepted-but-unused OAuth query fields were unbounded here; the email-verification OTP accepted
  4–8 digits when six is the only length either backend issues; and the login password gains the
  explicit floor of 1 that `ChangePasswordDto` already reasons for.
- **`cookies.trusted_origins` is accepted under `Lax`/`Strict` when a cookie-domain resolver is
  configured.** Those withhold the cookie cross-**site**, not cross-**origin**: a deployment
  serving `app.example.com` and `api.example.com` from one `.example.com` cookie is same-site, so
  the browser sends it on a POST between them — and `Sec-Fetch-Site: same-site` is not proof the
  request came from the app itself, so the guard falls through to the origin check. Refusing the
  list there left that deployment with no configuration at all: the cookie arrives, the request
  is refused 403, and the one setting that would have allowed it was rejected at startup.
- **`NoOpEmailProvider` masks the recipient.** A debug level is not a private one, and a provider
  that only runs when none is configured is the one likeliest to be running with verbose logging
  turned on.
- **A build without the `mfa` feature refuses an MFA challenge instead of signing one nobody can
  redeem.** `issue_mfa_temp_token` used to return the JWT anyway: an account whose stored
  `mfa_enabled` is true — a row left behind when a deployment turned the feature off — got a
  token with nowhere to spend it and a "challenge issued" line in the log. The user could not
  sign in and the log said the flow was working.

### Removed

- **Every legacy-compatibility path in the credential surface.** Both libraries are new and
  unreleased into production, so a parsing allowance for a corpus that does not exist is a
  widened input for nothing — and each of these sat in the credential-verification core:
  - the `scrypt:{salt_hex}:{hash_hex}` nest-compat password reader, with its fixed
    `N = 2^15` assumption and its bounded-hex parser,
  - the UUID-v4 refresh-token shape,
  - and the corresponding `refreshTokenLegacy` / `recoveryCodeDigestLegacy` contract entries.

- **Five error codes nothing could emit.** `SessionExpired` and `SessionLimitReached` describe
  behaviours neither library has — rotation answers `RefreshTokenInvalid`, and the session cap
  evicts rather than refuses. `RecoveryCodeInvalid` is unreachable on purpose: a wrong recovery
  code answers `MfaInvalidCode`, so a caller cannot learn which kind of credential they guessed
  wrong. `PasswordTooWeak` is the request DTO's job, and `PasswordResetTokenExpired` was already
  documented as unreachable by design. A code nothing can emit is a client branch that never
  fires. **Breaking** for a consumer matching on them; gone from both libraries.
- **`TokenManagerService::binding_holds`.** The rule it implemented now lives inside
  `bymax_auth_jwt::verify`, which is what lets the edge apply it too. Two implementations of one
  rule is how they drift.

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

- **Both login doors answered before proving the password.** The dashboard and platform logins
  ran the status and email-verification gates ahead of `passwords.verify`, so a caller who never
  held the credential learned an account's moderation state from the error code alone — and
  learned it in single-digit milliseconds, because the KDF was skipped. A wrong password now
  answers `InvalidCredentials` whatever the account's state is, and only the password holder is
  told why they still cannot sign in.
- **A tenant named `platform` shared the platform lockout counter.** The login path keyed its
  brute-force counter on `hashed_identifier`, whose preimage is `{tenantId}:{email}`, while the
  platform door builds `platform:{email}` — and the tenant comes from the request body whenever
  no resolver is configured, which is the default. Nothing stopped the two colliding, so five
  unauthenticated dashboard logins against an operator's address could lock that operator out of
  the console, repeatably, and a successful one cleared their lockout mid-attack. The login path
  derives through `lockout_identifier` now, which namespaces it with `dashboard:`;
  `hashed_identifier` is left alone because it also keys the OTP records, whose keyspace is
  shared byte-for-byte with `nest-auth`.
- **Platform rotation never re-read the admin.** `refresh` worked entirely from the session
  record, so blocking an administrator closed only the login door: they kept minting access
  tokens for the refresh token's whole lifetime, which ASVS v5 §7.4.2 asks a disable to end. A
  blocked or deleted admin now loses every platform session, including the one just minted.
- **Rotation froze the role and the tenant.** Claims were built from the session record written
  at login and inherited unchanged through every later rotation, so demoting an ADMIN to MEMBER,
  or moving a user between tenants, had no effect on a live session for the refresh token's whole
  lifetime — while every role check reads that claim. The dashboard refresh already re-read the
  account for the gates above; the authority was sitting there, unused. It is re-stamped now, and
  only when it differs.

### Security

- **`event-listener` advanced to 5.4.2 (RUSTSEC-2026-0221).** The crate reaches this
  workspace transitively, through `redis` → `async-lock`. Its `StackSlot` carried
  `unsafe impl<T> Send` and `Sync` with no bound on `T`, so a `!Send` value could be
  moved across a thread boundary — unsound for any listener holding one. 5.4.2 bounds
  both on `T: Send`. The rest of that release replaces the slab implementation with the
  intrusive one plus a spinlock fallback — both the removed module and its replacement
  sit behind `cfg(not(any(feature = "std", feature = "critical-section")))`, and this
  workspace enables `std` through `async-lock`, so neither is built here — and drops
  the `concurrent-queue` dependency. The delta is recorded
  as a `safe-to-deploy` audit in `supply-chain/audits.toml`: no import set covers
  5.4.2 yet, and its publisher differs from the one this project already trusts.

  The advisory was failing `cargo audit --deny warnings` on `main`, which blocked
  every open dependency pull request behind a finding none of them introduced.

### Fixed

- **`@bymax-one/rust-auth` resolved its types wrongly for every consumer that is not
  on a bundler.** The `exports` map declared one `types` condition per subpath, so
  `require()` landed on the ESM `.d.ts` while the matching `.d.cts` was being built
  and shipped all along, and the manifest carried no `typesVersions`, so a resolver
  that does not read the `exports` map found no declarations at all. `attw` reported
  `node10: Resolution failed` and `node16 (from CJS): Masquerading as ESM` on all four
  subpaths; it now reports `No problems found`. The package has never been published,
  so this is caught before the first release rather than after it — the same defect
  reached npm in `@bymax-one/nest-auth` 1.0.11.

  Each `typesVersions` entry lists the CommonJS declaration first and the ESM one as a
  fallback, so a resolver too old to load a `.d.cts` still finds declarations rather
  than none — the same shape `@types/react` uses for TypeScript 5.0 and below.

  `npm run check:exports` runs `attw --profile strict` against the packed tarball and
  is part of the npm package CI job. A `tsc --noEmit` compiles `src` and never resolves
  through the `exports` map, which is why nothing caught this.

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
