# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire/contract surface (token shapes, cookie names, the error envelope) is
treated as the public API for SemVer purposes — a breaking wire change is a major
version bump.

## [Unreleased]

> **Release rule.** The first breaking change below is on `main`, so the next release is the breaking batch: there is no interim release from `main`. A security fix needed before that batch ships from a release branch cut from the last tag.

### Changed

- **BREAKING (behaviour): the change-password and email-change failure counters are tenant-scoped (shared contract version 6).** In `conformance/wire-contract.json` (version 6), `userSubjectDerivedKeys` gains `changePasswordFailureCounter` and `emailChangeFailureCounter`, and the new `reproofCounterVectors` section pins both counters with known answers, which a test reads. The identifier behind each counter was `hmac_sha256("reauth:{flow}:{user_id}")` with a bare user id, so on a host that numbers users per tenant, failed passwords against `t1/u1` locked `t2/u1` out of the same flow with no credential. It is now `hmac_sha256("reauth:{flow}:{userSubject}")` with the tenant-scoped dashboard `userSubject`, the form the MFA counters already use. **Apply:** counters held under the old key are no longer read, so a count in progress restarts from zero at the upgrade (the crates are unpublished, so no deployed keyspace carries them).

- **The workspace cursor bound is 4096 characters, and an owner role outside a name rule is refused at startup (shared contract version 5).** `conformance/wire-contract.json` is copied byte-identical from `@bymax-one/nest-auth` (contract version 5, which both repositories must hold identical). `requestFieldBounds.pageLimit.cursor` is 1 to 4096 characters, up from 512: 512 was too small for the longest cursor an adapter can issue from ids, tenants and key parts of 128 code points and an owner role. `CURSOR_MAX_CHARS` is read against the contract by a test. A host's `MembershipRepository` must keep every `next_cursor` it issues within `CURSOR_MAX_CHARS`, because the HTTP edge refuses a longer one with `400` naming `cursor`. **BREAKING (behaviour):** `workspaces.roles.owner_role`, and no other role, must now be 1 to 32 code points of text with no control character (C0, C1 or DEL); an empty, longer or control-carrying owner role is refused at startup with `ConfigError::WorkspaceOwnerRole`, naming the option and the value. The bound is `OWNER_ROLE_MAX_CHARS`, read against the contract's `workspaceOwnerRole` by a test.

- **The shared contract moves to version 4, from `@bymax-one/nest-auth` 1.5.1, and the parts of it this repository has not built are tracked.** `conformance/wire-contract.json` and the four OpenAPI artefacts are copied byte-identical from the 1.5.1 release (the contract's sha256 pin is `1e4c38e1…2edd`, and each artefact's pin moves with its file). The contract gains the workspace sections (`workspaceMembershipCache`, `workspaceInvitations`, `workspaceScopedName`, `workspaceRealtime`, `workspaceAccountRemoval`) and workspace entries in its error codes, rate limits, key prefixes, request routes, operations and request schemas. Nothing is built from them in this change: every comparison against a table here keeps its both-ways assertion and carries a `PENDING` list of exactly the difference, and a pending entry that has been built, or a gap that is not listed, fails the build. `tests/contract_inventory.rs` adds the same check for whole sections and for the identifier preimages, request bounds and record encodings that no test read by name.

- **BREAKING (behaviour): a request that does not fit its DTO names each failing property.** A body that was JSON but missing a required property, carrying `null` or a value of the wrong type for one, or carrying a property the DTO does not have, answered one `auth.validation` entry naming the container (`body`, or `query` for a query string), so a client keying its form errors by property got a container name for every such failure. Every failing property is now named by its wire name. The properties come from the shared request schemas, the failing ones are replaced by a stand-in, and the rest of the request still goes through the DTO's own validation, so a request that fails one property by shape and another by bound names both (`{"email":"not-an-email","password":5}` names `email` and `password`). The status, the code and the top-level message are unchanged; the message of each entry is this crate's own and never repeats the client's value or type. An unknown property's name is echoed only when it is non-empty, at most 128 characters and free of control characters, and is otherwise reported once under `body`. The request-schemas artefact is now compiled in without the `openapi` feature, which only decides whether it is served. **Apply:** a client that matched `body` or `query` in `details[].field` for these failures must read the property names; the gate tests that asserted the container now assert the property.

- **BREAKING (behaviour): an OAuth error callback is not refused for an oversized `code`.** The callback query bounded `code` at 1 to 2048 characters whatever else it carried, so a provider's error callback (RFC 6749 section 4.1.2.1: `state` and `error`, the code never read) with a `code` past the bound was answered `400 auth.validation` naming `code` instead of the failed authorisation it is. The bound now applies only when there is no `error`; with one, the handler refuses the callback as `auth.oauth_failed` before it reads `code`, so an unbounded value still never reaches the token exchange or a store key. A callback with no `error` and a `code` that is empty or past the bound is refused as before. **Apply:** none unless a client or alert keyed on `400 auth.validation` for an error callback carrying an oversized `code`; it now sees `auth.oauth_failed` (or the configured error redirect).

- **BREAKING (behaviour): a refresh cookie past 2048 characters is refused, except on logout.** The refresh-token body was bounded at 1 to 2048 characters while the cookie carrying the same token was read without any bound, so an oversize cookie was hashed and looked up. The cookie is now held to the same bound: an empty cookie is still no token, exactly 2048 characters is still a token, and a longer value answers `400 auth.validation` with a detail on `refreshToken`, before anything is looked up. Logout alone treats an oversize cookie as no token: it answers `204`, clears the auth cookies, still revokes a presented access token and touches no refresh session, because a cookie planted by a sibling subdomain must not stop the user from signing out; a body value past the bound on logout is still `400`. Under `both`, an oversize cookie on logout is treated as an absent one, so a valid body token still applies. **Apply:** none for a client that sends the token the engine issued; a client or proxy that sends a longer cookie under the refresh cookie's name now gets the `400`, and can still log out.

- **BREAKING (behaviour): a validation error names a field the way the wire does.** `details[].field` of an `auth.validation` response carried the Rust field path (`current_password`, `tenant_id`, `new_password`), not the property the client sent (`currentPassword`, `tenantId`, `newPassword`); the engine's own validation errors already used the wire names. The adapter now converts each segment of the `garde` path to its wire name. Single-word fields (`email`, `password`, `name`, `code`) were never affected. The OAuth callback's `error_description` and `error_uri` are their own wire names and are reported as such. **Apply:** a client that matched the `snake_case` names must match the wire names; the status, the code and the messages are unchanged.

- **BREAKING (behaviour): request-field lengths are counted in characters, not bytes.** The request DTOs bounded every string with `garde`'s `length`, which counts the bytes of a `String`, while `@bymax-one/nest-auth` (class-validator) and JSON Schema's `minLength`/`maxLength` count characters. The same body was therefore accepted by one backend and refused by the other whenever a multibyte value sat near a bound. Every length rule is now `length(chars, ...)`: a passphrase of up to 128 characters in any script is accepted where a multibyte one used to be refused above 128 bytes, and in the other direction a value shorter than a minimum in characters is now refused where its byte count used to satisfy it, for example a one-character display name against a minimum of 2, or seven two-byte characters against the structural password minimum of 8. **Apply:** a front end or test that relied on a name shorter than the minimum in characters, or on a multibyte value being cut off at the byte bound, must adapt; ASCII values behave as before. The deployment's password floor (`password.min_length`) was already counted in characters.

- **BREAKING (behaviour): the OAuth callback reads `error_description` and `error_uri` under the provider's names, and logs them safely.** The callback query renamed every field to `camelCase`, so a provider's `error_description` and `error_uri` (RFC 6749 section 4.1.2.1) were never read, the bound the DTO declared for them never applied, and the log line its documentation promised never carried them. They are now read as sent, bounded at 512 characters, and logged with `error` when the provider refuses or sends no `code`. All three are provider-chosen text, so a value carrying a control character is logged as `<malformed>` (an absent one as `<absent>`) instead of raw. **Apply:** none for a host that does not read the log line; an alert keyed on its fields now finds `error_description` and `error_uri` beside `error`, and a callback whose `error_description` or `error_uri` exceeds 512 characters is now refused as a validation error.

- **BREAKING (host-implemented trait): `UserRepository::link_oauth` takes the tenant.** It was the one write keyed on the user id alone: on a host that numbers users per tenant, an OAuth `link` decision could land on another tenant's account, the same class as the writes made tenant-scoped earlier in this release. The signature is now `link_oauth(user_id, tenant_id, provider, provider_id)`, and an implementation MUST restrict the write to that tenant exactly as `find_by_id` restricts its read; the engine passes the tenant the identity was resolved in. **Apply:** add the `tenant_id: &str` parameter after the id and add the tenant to the `WHERE` clause of the update; a stale implementation fails to compile. The in-memory test double now restricts the write to the named tenant and records each call (`InMemoryUserRepository::link_calls`).

- **BREAKING (behaviour): the OAuth callback's error redirect carries the refusal's own code.** With `oauth.error_redirect_url` set, only `auth.oauth_failed` was redirected (as `?error=oauth_failed`); every other refusal (an email collision, a banned or suspended account, an unverified email) returned the JSON envelope. The adapter now redirects every refusal to the error URL with the suffix of its wire code (`?error=oauth_email_mismatch`, `?error=account_banned`), which is what `@bymax-one/nest-auth` does for any `AuthException`; a provider's own `error` response and a callback without a `code` stay `oauth_failed`, and an `Internal` failure stays a `500` envelope, never a redirect. **Apply:** a front end behind the error URL must handle the codes it can receive beyond `oauth_failed`, or treat any unknown value as a generic failure; a host with no `error_redirect_url` sees no change.

- **BREAKING (public API): `HookPlane` is `#[non_exhaustive]` and gains `ApiKey`.** `ApiKey` is the plane of the hook context a machine caller's request builds (no user, no tenant). **Apply:** add a wildcard arm to every exhaustive `match` on `HookPlane` outside this workspace; the compiler lists them.

- **BREAKING (public API): `AuthError` and `AuthErrorCode` are `#[non_exhaustive]`.** Each new error code was a source break for every host that matched either enum exhaustively. Marking them now means a future code is no longer a source break. **Apply:** add a wildcard arm (`_ =>`) to every `match` on `AuthError` or `AuthErrorCode` outside this workspace; the compiler lists them. Nothing on the wire changes.

- **BREAKING (source): `AuthConfig` gains `workspaces`, and `ControllerToggles` and `RouteGroups` gain `workspaces`.** A host that builds any of the three with a struct literal must add the field: `workspaces: WorkspacesConfig::default()` for `AuthConfig` (or start from a profile, which carries it), `workspaces: false` for the two toggles (or `..ControllerToggles::default()`). The layer is off by default and changes no behaviour. `RouteGroup` gains `Workspaces`; it is `#[non_exhaustive]`, so a match outside this workspace already has a wildcard arm.

- **BREAKING (source): `AuthConfig` gains the `api_keys` field.** A host that builds `AuthConfig` with a struct literal must add `api_keys: ApiKeysConfig::default()` (or start from `AuthConfig::nest_compat_defaults()` / `secure_defaults()`, which already carry it). The group is off by default and changes no behaviour.

- **BREAKING (source): `AuthConfig::redis_namespace` is removed; the namespace is the argument of `RedisStores::connect`.** The field was never read: the key prefix has always come from the `namespace` passed to `RedisStores::connect`, so setting the config field changed nothing, and a deployment that set it to anything but what it passed to `connect` believed it had isolated a keyspace it had not. The specification no longer lists it, and `connect` documents that its argument is the only place the namespace is set. **Apply:** delete the `redis_namespace` assignment (or struct-literal field) from your `AuthConfig`, and make sure the value you pass to `RedisStores::connect` is the one you meant. No key moves, since the field never affected one.

- **BREAKING (source): `PasswordConfig` is `#[non_exhaustive]`.** A field added to it later is no longer a source break for every host that spelled the struct out. It gains `blocklist` now, and a host outside this crate can no longer build it with a struct literal. **Apply:** start from `PasswordConfig::default()` (or a profile) and assign the fields: `let mut password = PasswordConfig::default(); password.rehash_on_verify = false;`.

- **BREAKING (behaviour): a failed invitation email is reported instead of swallowed.** `invite` logged a send failure and returned success, so `POST /auth/invitations` answered `204` and the inviter never learned the link had not been sent. It now returns `AuthError::Internal` with a fixed description, which the adapter answers as `500 auth.internal` with the generic body. Nothing the mail channel wrote reaches the error, its source chain or the log (one fixed line), because a relay can quote the body it rejected and that body carries the raw invitation token. The stored invitation is kept, since the email may have been delivered despite the error, and inviting the address again supersedes it. The shipped `DefaultAuthEmailProvider` applies `DeliveryErrorPolicy::Swallow` by default, so with it the provider reports success and `invite` sees no failure; the `500` appears with a custom provider or the `Rethrow` policy. **Apply:** a host that relied on the invite route succeeding while its mailer was down must handle the `500`; the invitation is stored and a retry supersedes it.

- **BREAKING (behaviour): the platform guard names a validly signed MFA-challenge token, and decides the kind of any other-kind token before it reads a store; `SelfOrAdmin` reads its id from a route with several captures.** A validly signed MFA-challenge token on a platform route is now `auth.platform_auth_required`, as a dashboard token is and as nest-auth answers, instead of `auth.token_invalid`. The kind of a dashboard or MFA-challenge token is now decided from its signature alone, so a revoked one is `auth.platform_auth_required` too and an outage of the revocation store changes nothing about it; a store failure while checking a *platform* token keeps surfacing as a `500 auth.internal`. `SelfOrAdmin` read exactly one path capture and refused every caller on a route with more than one, the owner included; it now reads the `user_id` capture, else `id`, whatever else the route captures, as one non-empty segment. A route that names a tenant (`tenant_id`, `tenantId` or `tenant`) is bound to the caller's tenant before either branch, so neither the owner check nor the admin override reaches into another tenant, several tenant captures must all agree, and anything it refuses answers `auth.insufficient_role`; this is the rule both libraries apply. `UserRepository::update_mfa` and `PlatformUserRepository::update_mfa` now document that the call must stay well under the 10 s MFA transition lock, because a stall past it lets two MFA writes reorder. **Apply:** a client that treated an MFA-challenge token on a platform route as `auth.token_invalid` should expect `auth.platform_auth_required`; a host whose `update_mfa` can take close to ten seconds must bound it.

- **BREAKING (behaviour): the platform guard and `SelfOrAdmin` answer with the error codes nest-auth's guards answer with.** A client that branches on `error.code` sees one answer per cause on either backend. `SelfOrAdmin` answered `auth.forbidden` when the caller was neither the owner nor an admin, and `auth.token_invalid` when the route had no `{user_id}` segment; both are now `auth.insufficient_role` (403 for both the old and new first case; the second was 401 and is now 403). `PlatformUser` and `RequirePlatformRole` answered `auth.platform_auth_required` for every refusal, a missing, unreadable, forged, expired or revoked token included; those are now `auth.token_invalid`, and `auth.platform_auth_required` is kept for a validly signed dashboard or MFA-challenge token, the cases that distinguish "the other context's token". Statuses are unchanged (401), and a store failure during the revocation check is still a 500. The shared wire contract pins the code vocabulary and statuses, not which guard answers which, so the mapping is recorded as a table in the specification (section 8.3.7). **Apply:** a client or test that expected `auth.platform_auth_required` or `auth.forbidden` from these guards for the causes above should expect `auth.token_invalid` or `auth.insufficient_role`. `AuthEngine::verify_platform_request_token` is new and gives any other transport the same answers.

- **BREAKING (behaviour): a refresh-token body is held to one rule, and a password change or revoke-all refuses a token that names no live session.** Refresh, logout, revoke-all and the platform refresh and logout read `refreshToken` from an optional JSON body. A missing field or `null` is no token and a string of 1 to 2048 characters is the token; every other value (an empty string, a longer one, a number, a boolean, an object, an array) now answers `400 auth.validation` with a detail on `refreshToken`, and a body that is not JSON or whose root is not an object answers `400` "Malformed request", all before the route does anything. Logout, revoke-all and platform logout used to ignore such a body and carry on, so a client could be told it had signed out while the session it named stayed alive. In dashboard `cookie` delivery the body value is ignored, but a body that is not a JSON object or array is still refused. `POST /auth/sessions/revoke-all` and `POST /auth/password/change` now check, before they change anything, that the presented refresh token is a live session of the caller's own account, or that it rotated away inside its grace window and its grace pointer names a live session of the same account (one hop, read once, never consumed or extended); that session is the one kept. Otherwise they answer `404 auth.session_not_found`. A password change used to write the new password and then end every session, the caller's own included, for a token naming nothing; and a refresh of the caller's own session that landed while the new password was being hashed made the change keep nothing. If the session cannot be resolved after the password is written, every session still ends and the epoch advances, and the change answers success. `SessionService::resolve_live_session` and `SessionStore::grace_successor` (default: no successor) are new; `SessionService::revoke_all_except_current` now answers `SessionNotFound` for a token that names no live session. **Migration:** a client that sends `refreshToken: ""` when it holds no token should omit the field or send `null`. A custom `SessionStore` that keeps grace pointers should implement `grace_successor`; without it a rotated token names no session. No wire-contract change.

- **BREAKING (startup): `secure_cookies = Some(false)` is refused in a production deployment.** `Environment` is `Production` unless the host declares otherwise, so `secure_cookies = Some(false)` without a declared `Development` or `Test` environment produced session cookies without the `Secure` attribute, sent over plain HTTP; a TLS-terminating proxy does not change that, because the browser still speaks HTTPS to the proxy and the attribute costs nothing there. `AuthConfig::validate` now returns the new `ConfigError::SecureCookiesRequiredInProduction` for that combination, after the `SameSite=None` check, so a deployment that breaks both is told about the one that explains why a browser would drop the cookie. Leaving `secure_cookies` unset, and `Some(true)`, are unchanged in every environment; `Some(false)` is accepted in `Development` and `Test`. **Migration:** a host that runs on plain HTTP declares `Environment::Development` or `Environment::Test`; one that sets `Some(false)` in production sets `Some(true)` or leaves it unset. The first sentence of the message is held identical with nest-auth's, with the field name in each library's spelling. No wire-contract change.

- **BREAKING (client crate): the tenant is optional.** `RegisterRequest::tenant_id`, `LoginRequest::tenant_id` and `ResetPasswordRequest::tenant_id` are `Option<String>`, and `AuthClient::forgot_password` takes `Option<&str>`, as in the TypeScript client. A backend that resolves the tenant itself (`tenant_id_resolver`) refuses a `tenantId` in the body, so a Rust caller could not reach such a deployment at all. `None` omits the key (never `null`); `Some(..)` sends it as before. Call sites wrap the value in `Some(..)`. The client has no counterpart of the TypeScript `authFetch` wrapper, on purpose: `reqwest` carries its own timeouts, set on the `reqwest::Client` passed to `with_http_client`, and `me()` already performs the single-flight refresh-and-retry.

- **BREAKING (adapter): `auth_router` and `AuthRouter::from_engine` return a `Result`, and `ClientIpSource::TrustedForwardedFor` requires `AxumAuthConfig::is_trusted_proxy`.** `TrustedForwardedFor` believed the rightmost `X-Forwarded-For` entry from any peer, so a caller that reached the service directly wrote its own address and chose its own rate-limit key, which is a limiter bypass. The builders now refuse that shape with `ConfigError::TrustedForwardedForRequiresPredicate` ("TrustedForwardedFor requires is_trusted_proxy"). `is_trusted_proxy` takes the TCP peer's address and answers `true` for the deployment's own proxies; the header is read only from such a peer, and the client is the rightmost entry that is not itself a trusted proxy (the rule Express applies, so a chain of several proxies resolves to the real client). A predicate that panics, a missing peer address and an entry that is not an address are all "not trusted". `PeerAddr` needs no predicate and stays the direct posture. Call sites add `?`.
- **Behind a trusted proxy the session address, the lockout key and the hooks record the real client.** The engine context used the peer socket address only, so with a proxy in front every session, lockout and `HookContext.ip` carried the proxy's address. It now uses the same resolved client address as the rate limiter, so the bucket a request is charged to and the address recorded for it cannot disagree. The IPv6 /64 bucketing stays in the limiter; the engine gets the full address. Directly exposed services (`PeerAddr`) see no change.

- **BREAKING (public API and host hooks): `HookContext` gains a required `plane` field, and the hooks a platform administrator reaches change.** A host that builds a `HookContext` by struct literal (a test double, a custom adapter) must set `plane: HookPlane::Dashboard` or `HookPlane::Platform`; `HookContext::from_request` now takes the plane as its first argument, and `HookContext::detached` takes `(plane, user_id, ip, user_agent)`. A hook implementation only reads the context, so it compiles unchanged, but it must now handle the platform plane: the three `after_mfa_*` hooks also fire for platform administrators, and `after_login` fires for those who complete an MFA challenge (a plain platform password login still fires none); their `SafeAuthUser` has an empty `tenant_id`. `after_logout` no longer fires for them, so a deployment that relied on it for administrators implements the new `after_platform_logout`. Branch on `ctx.plane`, not on the shape of `tenant_id`. The reasons are under Added and Fixed below.

- **A password change keeps the caller's own session whichever channel carries its refresh token, and the client's logout ends the server session.** `POST /auth/password/change` read the caller's current refresh token only from the body, so a cookie-delivery caller, whose token travels in the refresh cookie, revoked every session including their own. The handler now reads the cookie first and the body second. The Rust client's `logout` sent only the access token, which cleared the client's copy and left the refresh session redeemable; it now sends the stored refresh token in the body.

- **Re-inviting an address needs the rank to destroy the pending invitation, and the supersede is a compare-and-swap.** `invite` authorised only the role being requested, so any tenant member could post a `MEMBER` invitation for an address and delete a pending `ADMIN` one, a withdrawal the revoke route refuses them. Superseding now requires `has_role(inviter.role, pending.role)` (else `InsufficientRole`, 403), and the invitee index is claimed with a compare-and-set against the invitation that check approved: an invitation that appears between the check and the claim is never displaced by an outranked caller, a lost race is retried a bounded number of times, then refused with `InsufficientRole`, and the index is claimed before the record is written and re-claimed against its own hash after it (which also renews its TTL, so the record cannot outlive the entry that names it), so an invite whose address was changed underneath it withdraws its own record instead of leaving a redeemable token that nothing names. **BREAKING (host-implemented trait): `InvitationStore` gains `claim_invitation_index`.**

- **The per-route rate limit is counted in a shared store, so the allowance holds across instances.** The adapter's limit was an in-process token bucket per route, so N replicas gave a client N times the allowance. The engine now takes a `RateLimitStore` (`EngineBuilder::rate_limit_store`, and `redis_stores` wires it from the same handle; **the `redis_stores` bound gains `RateLimitStore`, so a host-implemented store bundle must implement it**). The counter is a fixed window that opens at the first request and is never extended, keyed `rl:{route}:{hmac(bucket)}` with the /64 bucketing for IPv6, with `Retry-After` equal to the full window, and a store failure is answered as an internal error rather than waved through. The in-process `tower_governor` layer remains the fallback only when no store is configured. The key family is outside the shared prefix contract: route naming is each implementation's own, so one client served by both libraries gets a budget from each.

- **`UserStatus` applies the verified-address rule, and the address change and invitation routes check the account's standing.** Registration mints a session before the address is verified, and the status gate checked only the blocked set, so that session reached every route behind that gate. `UserStatus` now also returns `EmailNotVerified` when `email_verification.required` and the address is unproven (a blocked status is still reported first). `POST /auth/email/change` and `POST /auth/invitations` (create and revoke) take `UserStatus` as well: minting or withdrawing an invitation uses the caller's authority. Hosts that run with verification required will see 403 `auth.email_not_verified` on these routes for unverified accounts.

- **`enforce_tenant_binding` (new, default `false`).** A valid token is otherwise trusted for the tenant baked into it, so a token minted for one tenant is accepted under another tenant's host. With the flag on, `AuthEngine::assert_tenant_binding` re-resolves the request's tenant with `tenant_id_resolver` and a mismatch is refused as `token_invalid`. The flag requires a resolver: `AuthConfig::validate` rejects the pair at startup (`ConfigError::TenantBindingWithoutResolver`), since a binding with nothing to compare against would enforce nothing. Both WebSocket handshake extractors (`WsAuthUser`, which redeems a ticket, and `WsAuthUserFromHeader`) apply the same binding as the HTTP extractors, so neither a token nor a ticket opens a socket under a tenant host it would be refused on over HTTP.

- **`on_lockout` reports the configured window, not `0`, when the store cannot say how long is left.** The hook fires on the attempt that crosses the threshold; if the read of the remaining lockout time failed, it was told `retry_after_seconds = 0`, which reads as "not locked". It now receives `brute_force.window`, an upper bound because the window is fixed from the first failure. The failure is logged.

- **BREAKING (host-implemented trait): every `AuthEmailCatalogue` renderer receives an `AuthEmailContext`.** The ten renderers were given only their own fields, so an override could not build a link under a tenant-specific host or address the recipient. They now take `&AuthEmailContext<'_>` first, carrying `tenant_id`, `email` and `locale`, filled by `DefaultAuthEmailProvider` from the tenant and address it already receives; the separate `locale` argument is gone because it lives in the context. `email` is the **delivery address**: the NEW address for `email_change_verification` (the one being proven) and the PREVIOUS one for `email_changed` (the notice goes where the owner still reads; `old_email` and `new_email` stay among its own arguments). New public type `AuthEmailContext`, exported from `bymax_auth_core::traits`. How an existing override adapts: add the context parameter first and read the locale from it. Before: `fn password_reset_token(&self, token: &str, locale: Option<&str>) -> AuthEmailMessage`. After: `fn password_reset_token(&self, ctx: &AuthEmailContext<'_>, token: &str) -> AuthEmailMessage`, with `ctx.locale` in place of `locale`. The ten renderers: `password_reset_token(ctx, token)`, `password_reset_otp(ctx, otp)`, `email_verification_otp(ctx, otp)`, `password_changed(ctx)`, `email_change_verification(ctx, token)`, `email_changed(ctx, old_email, new_email)`, `mfa_enabled(ctx)`, `mfa_disabled(ctx)`, `new_session_alert(ctx, session)`, `invitation(ctx, invite)`. The shape and the per-renderer address semantics are nest-auth's `AuthEmailContext`.

- **A WebSocket ticket no longer outlives the logout or the epoch bump that revoked the token it was minted from.** The ticket snapshot carried no revocation data, so a ticket minted before a logout, a password reset or a sign-out-everywhere still opened a socket for up to its 30 s TTL. The snapshot now carries the minting access token's `jti` and `epoch` (identifiers, not credentials), and redemption is refused, with the same `token_invalid` as an unknown or used ticket and a warning that names no identifier, when `rv:{jti}` is present or the account's stored epoch (`ep:`) is above the ticket's. A snapshot that names no tenant is refused (see the entry on redemption below). A ticket expires no later than the access token that minted it (its TTL is the lesser of 30 s and the token's remaining life less one second, because the clocks count whole seconds, and a token with none left mints nothing): a logout blacklists the `jti` only until the token expires, so a longer-lived ticket could be redeemed after that logout once the entry was gone. A record that is not a whole ticket (no `jti`, an `epoch` that is a string, negative or fractional) reads as an unknown ticket, including a ticket written by the previous version, which therefore stops working at upgrade. A ticket with an empty `jti` is refused at redemption. New public fields `WsTicketSnapshot::{jti, epoch}`, for a host that implements `WsTicketStore` or builds a snapshot by hand. The shared `conformance/wire-contract.json` documents both fields and is byte-identical with nest-auth's. Known limitation: a logout blacklists only the access token it was given and does not move the epoch, so a ticket minted from an access token that a refresh had already replaced is not refused after that logout, as a bearer token of that kind is not; it is refused only after a later epoch bump (a password reset or change, an MFA enable, disable or reset, revoking another session or all of them).

- **A refresh rotation keeps `mfa_verified`, on both planes.** Rotation minted `mfa_verified: false`, and no route lets an authenticated session re-acquire the claim, so once the first access token aged out every enrolled user was refused by every route behind the MFA gate (`MfaSatisfied`) until they signed in again. The refresh-session record (`rt:` / `prt:`) now carries `mfaVerified`, written only as `true` for a session established through the MFA challenge (a challenge login or a recovery code) and omitted otherwise, never written as `false`, so a record that never cleared the challenge is byte-identical to today's. It is read strictly: only the JSON boolean `true` counts, and an absent field, a legacy record or any other value reads as `false` without failing the record. Every primary rotation and every grace-window recovery copies it from the stored record to its successor and into the claims of the new access token; a placeholder seed carries nothing. A session inherits the assurance of the authentication event that created it (NIST SP 800-63B-4, Session Management). Enabling, disabling or resetting the factor through this library already revokes every session, so a stored `true` does not outlive the factor. Sessions that exist when this ships have no stored claim and stay unverified until the next challenge. New public field: `SessionRecord::mfa_verified: bool` (for hosts that construct a record by hand). `conformance/wire-contract.json` documents the field (`optionalFields`) and is byte-identical with nest-auth's.

- **BREAKING (host-implemented trait): `UserRepository`'s remaining writes take the tenant.** A write keyed on `id` alone cannot be correct under a schema that numbers users per tenant: it lands on another tenant's row. `update_password`, `update_last_login`, `update_status`, `update_email_verified`, `update_email` and `update_mfa` now take `tenant_id: &str` right after `id`, and an implementation MUST restrict the write to that tenant exactly as `find_by_id` restricts its read. Changed signatures:
  - `update_password(id, tenant_id, password_hash)`
  - `update_last_login(id, tenant_id)`
  - `update_status(id, tenant_id, status)`
  - `update_email_verified(id, tenant_id, verified)`
  - `update_email(id, tenant_id, email)`
  - `update_mfa(id, tenant_id, data)` (the tenant was `Option<&str>`, where `None` meant every tenant; there is no such scope any more, and a caller acting on another tenant's account passes that account's tenant)

  A stale implementation fails to compile rather than binding the wrong argument. The dashboard MFA write refuses to run without a tenant. `PlatformUserRepository` is unchanged: platform admins are not tenant-scoped. The in-memory test double now restricts every write to the named tenant, so a test that names the wrong tenant sees the account untouched.

- **BREAKING (public API): the last three unscoped account reads now carry the tenant.** `AuthEngine::issue_tokens_for_user_id(tenant_id, user_id, ip, user_agent)` takes the caller's `tenant_id` first and reads the account with it, so a workspace switch or impersonation that names another tenant's id no longer signs a session for that account. The session-cap resolver and the new-session hook read the account with the `SessionRecord`'s own tenant instead of by id alone.

- **BREAKING (public API): request-path account reads are scoped to the caller's tenant.** `UserRepository::find_by_id(id, None)` is the cross-tenant admin lookup, and request-path reads still used it, so on a host that numbers users per tenant a call naming another tenant's id read, and in some flows acted on, the wrong account. Each now reads with the tenant that is already at hand (the verified token's, or the stored reset, email-change or invitation record's): `request_email_change`, `confirm_email_change`, `invite`, `revoke_invitation`, the invitation's inviter re-check, `notify_password_changed` (the "your password changed" notice used to reach the other tenant's owner), the reset proof's password binding, the `after_password_reset` hook projection, and the transparent password rehash after login. Changed public signatures:
  - `AuthEngine::request_email_change(tenant_id, user_id, new_email, current_password)` takes the caller's `tenant_id` first (the axum route passes the token's).
  - `AuthEngine::assert_user_active` and `AuthEngine::assert_user_active_and_verified` take `tenant_id: &str` instead of `Option<&str>`.

  Behaviour: an inviter or revoker who lives in another tenant is now not found there, so `invite` and `revoke_invitation` answer `TokenInvalid` instead of `InsufficientRole`; the tenant comparison stays as a second lock for a repository that ignores the scope. The in-memory test double gained `InMemoryUserRepository::ignore_tenant_on_id()` to exercise that second lock.

- **BREAKING: bulk session revocation moved from `DELETE /auth/sessions/all` to
  `POST /auth/sessions/revoke-all`.** Guards, rate limit (5/60), `204` and error codes are
  unchanged; only the method and the last path segment moved. `AUTH_ROUTES.SESSIONS_REVOKE_ALL`
  in the npm client carries the new path.

  **The verb was the defect.** The handler needs the refresh token naming the caller's own
  session — the one session it must *not* revoke — and a bearer-mode deployment carries that
  token in the request body. RFC 7231 gives a payload on `DELETE` no defined semantics, so an
  OpenAPI generator drops it: the generated client sends no body, the handler cannot identify
  the current session, and every call answers `auth.session_not_found`. A `DELETE` that needs a
  body is a `DELETE` a generated client cannot call.

  Paired with nest-auth's `POST {prefix}/sessions/revoke-all`, so one generated client drives
  both servers instead of needing a per-implementation branch.

  `DELETE /auth/platform/sessions` is deliberately **not** moved: it revokes every platform
  session including the caller's, reads no body at all, and so carries none of the defect.

  **Apply:** change the method to `POST` and the path's last segment to `revoke-all`. A caller
  still on `DELETE /auth/sessions/all` now falls through to the `{id}` capture and gets
  `404 auth.session_not_found`, the same answer a malformed session hash has always produced.

### Added

- **The workspace read routes and the workspace guard, behind `controllers.workspaces`.** With `workspaces.enabled` and the new `controllers.workspaces` toggle (opt-in; not behind a Cargo feature), the router mounts `GET /auth/workspaces` (the caller's own active memberships of active workspaces, a page at a time, with the workspace it last switched to), `GET /auth/workspaces/{workspaceId}/access` (the workspace and the caller's role), `GET /auth/workspaces/{workspaceId}/members` (every member in every membership status, for the roles `workspaces.permissions.view_members` accepts) and `POST /auth/workspaces/{workspaceId}/switch` (records the last active workspace, 204), under the contract's `workspaceList`, `workspaceAccess`, `workspaceMembers` and `workspaceSwitch` limits. **The guard** is `bymax_auth_axum::RequireWorkspace<P: WorkspacePolicy>` (with `AnyWorkspaceMember`), which a host's own routes can use too; it applies `workspaceRealtime.rules.accessDecision` in its fixed order through `AuthEngine::authorize_workspace`: the identical `404 auth.workspace_not_found` (same status, same body bytes) for a stranger, a missing, suspended or deleted workspace, a suspended membership and every non-owner of a workspace pending deletion; `409 auth.workspace_pending_deletion` for its owner unless the policy sets `ALLOW_PENDING`, which then admits that owner alone; then `403 auth.insufficient_workspace_role` through the workspace hierarchy. A `workspaceId` over 128 code points, blank in JavaScript's whitespace set or carrying a control character is `400 auth.validation` naming it, after the credential and before any lookup, and before the handler reads any other path parameter. The membership is resolved through the versioned cache (`resolve_membership`), which fills and reads back only an active membership of an active workspace. **Lists:** `limit` is checked as text against `^(?:[1-9][0-9]?|100)$` and never clamped, `cursor` is 1 to 512 characters without a control character, and a query naming `tenantId`, `userId` or `workspaceId` is refused, so the tenant and the workspace of a list come only from the credential and the route. **Core:** `AuthConfig::workspaces` (`WorkspacesConfig`, `#[non_exhaustive]`, with `roles.hierarchy`, `roles.owner_role`, `permissions.view_members` and `membership_cache_ttl_seconds`, default 60, at most 3600, `0` disables the cache), `AuthEngineBuilder::workspace_repositories` and `membership_cache_store` (`RedisStores` implements the store), the access decision as pure functions (`workspace::access::{classify, decide}` over `AcceptedRoles`, `ResolvedAccess`, `WorkspaceRefusal`), and `AuthEngine::{authorize_workspace, list_my_workspaces, workspace_access, list_workspace_members, switch_workspace, workspaces_enabled, workspace_view_members_roles}`. A half-configured layer fails at startup (rule 26 of the specification). **Adapter:** `WorkspacePageQueryDto` and `MemberRouteParamsDto` answer their shared schemas and name each failing property; the operation table gains the four operations (`access`), `RouteGroup::Workspaces` mounts no request-body schema, and the dashboard security schemes are defined for a deployment that mounts only this group. The `PENDING` lists lose the four operations and the two schemas, and `workspaceRealtime` is read for `accessDecision` and `workspaceIdField`, its other statements staying pending for slice 13.9. Not built here: the mutations, the invitations, the workspace event hooks (`workspace.switched` is not reported yet), the host's `resolveRequestWorkspace`, and the realtime surfaces. **Apply to a derived backend:** a deployment that runs both libraries on one Redis needs nothing new here; the membership cache keys are the shared ones.

- **Behaviours the shared contract states are now compared with it.** `requestFieldBounds.opaqueToken`, `recordEncodings.emailChangeContext`, `passwordResetOrder` and `refreshTokenInput` were listed in `tests/contract_inventory.rs` as read by no test, and `RefreshTokenBodyDto` as a request schema no DTO was declared for. Each now has a test that reads it from `conformance/wire-contract.json` and drives the code: the refresh and reset-token DTO fields at the bound and either side of it; the address-change record's fields (set equality), its stored address and fingerprint, its `ec:` key at a real Redis, and a record without the fingerprint confirming; each reset step's answers against the codes the step names; and each clause of the refresh-token rule, by channel, against a scenario that drives it. `RefreshDto` is declared as the DTO answering `RefreshTokenBodyDto`, so the request-schema parity tests probe it, and a structural failure of `RefreshDto` names `refreshToken` as every other DTO names its properties. No behaviour of the routes changes: none showed a divergence from the contract.

- **The workspace-membership cache shared with `@bymax-one/nest-auth`.** `bymax_auth_core::traits::MembershipCacheStore` is the store seam of the versioned cache `workspaceMembershipCache` pins: a workspace counter (`wsv`), a membership counter (`wmv`) and an entry (`wm`) named by both versions. `read` reads `wsv`, then `wmv`, then the entry those two name, as single-key reads (an absent counter reads `0`, and a read never creates one); `fill` writes the entry only while both counters still hold the versions read and, in the same atomic step, extends every counter that exists to the 30-day retention, leaving an absent one absent; `bump_workspace` and `bump_membership` increment a counter and set its retention on every bump. `bymax_auth_core::services::membership_cache::resolve_membership` implements the read order over any store and the host's two repositories (`Repositories`): on a miss it reads both rows, answers an active member of an active workspace and refills under the versions it read first, and answers anything else as `NotMember` with the rows, without caching it. The cache is advisory (a store failure answers from the repositories and writes nothing), a blank tenant, workspace or user is refused before any key is derived, and `MembershipCacheTtl` carries `workspaces.membershipCacheTtlSeconds` (default 60, at most 3600, `0` disables the cache) as a parameter, since there is no workspace configuration group yet. `bump_workspace` and `bump_membership` in the same module derive the counter and bump it; a failed bump is an error. `bymax_auth_redis::RedisStores` implements the trait with two new scripts, `membership_cache_fill` and `membership_cache_bump`, which declare every key in `KEYS`, and `bymax_auth_core::testing::InMemoryMembershipCache` implements it with the same rules. The contract's scenarios run through one runner (`testing::membership_cache_scenarios`) against both, the in-memory store and a real Redis, so the two cannot drift. **Operational:** run the store with a no-eviction policy for the auth keyspace; an evicted counter restarts at `0` and can make an entry written under an earlier `0:0` readable again for up to its TTL.

- **The workspace domain and its repository contracts.** `bymax_auth_core::workspace` gains the workspace and membership records (`Workspace`, `Membership`, `Page`, `WorkspaceRef`, `MembershipRef`, `ActingMember`), the workspace status machine (`WorkspaceStatus::library_may_move_to`, `grants_access`, `blocks_account_removal`), the audit event (`WorkspaceAuditEvent`, `AuditKind`) and the role hierarchy (`RoleHierarchy`, which validates a hierarchy and its owner role). `bymax_auth_core::traits` gains `WorkspaceRepository` and `MembershipRepository`, which a host implements against its tables. Both state what a wrong implementation would get wrong silently: every method restricts its read and write to the tenant, reads the library decides on come from the primary, the last-owner rule and the transfer of ownership are one atomic operation in the repository, a role change and a removal are conditional on the roles the actor read, and a refused write persists no audit event. `MembershipRepository::remove_all_for_user` removes every membership of an account for a host about to delete or anonymise the user, and is refused while the account is the only active owner of an active or suspended workspace. `bymax_auth_core::testing::InMemoryWorkspaces` implements both traits with the same rules, so a host's implementation can be held to them. Nothing calls them yet.

- **The workspace derivations, bounds and limits, as data.** `bymax_auth_core::workspace` holds the subjects and Redis key identifiers of the workspace keyspaces, the request bounds of the workspace routes, the invitation and membership-cache limits, and `workspace_scoped_name`, the name a host builds for storage, cache, socket rooms and queues. Subjects length-prefix the tenant and workspace in UTF-8 bytes so a field's content cannot move the boundary between them, and a blank part derives no key. Every vector is read from `conformance/wire-contract.json` and derived by a test. **BREAKING (API):** `bymax_auth_redis::Prefix` is not `#[non_exhaustive]` and gains `Wsv`, `Wmv`, `Wm`, `Winv`, `Winvidx`, `Winvset` and `Winvrl`, and `RateLimitConfig` gains one field per workspace route, so an exhaustive match on the first and a struct literal of the second without `..Default::default()` stop compiling. The encoding policy matches a `:name` segment against any one non-empty segment, which lets it refuse an encoded body on the workspace routes that take an optional one only when the request carries one. The OAuth state record accepts an optional `workspaceInvitation`, the lowercase hex SHA-256 of an invitation token; a record that carries it as anything else is refused like any corrupt record.
- **Nine workspace error codes.** `AuthErrorCode` and `AuthError` gain `WorkspaceRequired` (`auth.workspace_required`, 400), `WorkspaceNotFound` (`auth.workspace_not_found`, 404), `InsufficientWorkspaceRole` (`auth.insufficient_workspace_role`, 403), `LastOwner` (`auth.last_owner`, 409), `AlreadyMember` (`auth.already_member`, 409), `InvitationEmailMismatch` (`auth.invitation_email_mismatch`, 403), `RegistrationClosed` (`auth.registration_closed`, 403), `WorkspaceLimitReached` (`auth.workspace_limit_reached`, 403) and `WorkspacePendingDeletion` (`auth.workspace_pending_deletion`, 409), with the messages and statuses `errorCatalog` in the shared contract pins; none is internal-only. No route raises them yet. The enums are `#[non_exhaustive]`, so a host's exhaustive match keeps compiling, and the generated `./shared` TypeScript types gain the same codes.
- **The `openapi` feature: the auth routes' request-body schemas, as data.** Behind a new `openapi` Cargo feature of `bymax-auth-axum` (off by default, in `full`, forwarded by the `bymax-auth` facade, no new dependency), `bymax_auth_axum::openapi` exposes `nest-auth`'s OpenAPI 3.0 request-body schemas as `serde_json` values: `request_schema_names()`, `request_schema(name)`, `request_schemas()`, `request_schemas_for(groups)` (the schemas of the route groups a router mounts), `request_body_routes()` (each route that takes a JSON body and the schema of that body, so a host can build its `paths` from the same table), `openapi_version()` and the raw `REQUEST_SCHEMAS_JSON`, keyed by `nest-auth`'s DTO names so a client generated from either backend sees the same names and bounds. It builds no document and serves no route: a host puts the schemas it wants under `components.schemas` of its own document. The data is the shared `conformance/openapi-request-schemas.json`, shipped as a copy inside the crate (a tarball holds only the crate's own files), held byte-identical by a test, and CI builds the packaged crates with the feature on. The same feature declares the security schemes: `security_schemes(&engine, groups)` returns the `components.securitySchemes` a deployment can satisfy, naming the cookies the adapter actually sets and defining a scheme only where the delivery mode and the mounted groups make a credential readable; `document_security(guard, delivery)` returns the document-level `security` default for a host's own routes, so it cannot name a scheme the document no longer declares after a change of delivery mode. The same feature lists the credential each operation requires: `operation_security()` (each operation of the auth router with its `OperationKind`, from the shared `conformance/openapi-operation-security.json`, held byte-identical with a digest pin) and `describe_operation(kind, delivery)`, which turns a kind into the operation's `security` list and, where a credential can arrive in a body, its request body. A test presents every operation in each delivery mode with combinations of credential and transport and requires the router to admit or refuse each the way its kind says. The same feature carries what the server does to a request value that a schema cannot say: `request_descriptions()` and `request_description(dto, property)` serve `nest-auth`'s hand-written `conformance/openapi-request-descriptions.json`, held byte-identical with a digest pin. Each entry carries a probe that a test runs through the real deserialisation and validation of the DTO it names. The same feature serves the contracts a schema cannot state: `declared_request_structures()` and `declared_operation_semantics()` return `nest-auth`'s hand-written `conformance/openapi-declared-structures.json`, held byte-identical with a digest pin. Every probe of every entry is run against the real router under the deployment it names. **Apply:** none; nothing changes unless the feature is enabled.

- **Service API keys: scoped keys for machine callers, off by default.** Behind the `api-keys` Cargo feature (in `full`, and forwarded by the `bymax-auth` facade to the adapter) and `api_keys.enabled`. A key is `{prefix}_{keyId}_{secret}` (default prefix `bak`, a lowercase UUID, 43 base64url characters, split on the first two separators only); only the hex HMAC-SHA-256 of the secret under `api_keys.pepper` is stored. **Core.** `AuthConfig::api_keys` (`ApiKeysConfig`, `#[non_exhaustive]`, with a `Default`) holds `enabled`, `pepper`, `scopes`, `header`, `prefix`, `last_used_flush` and `audit_mode`, validated only while enabled: the pepper clears the signing secret's bar and equals no other key the deployment holds, the scope vocabulary is non-empty, well-formed and distinct, the header is not a reserved one, the prefix fits the key grammar, and the flush interval is 1 to 3600 whole seconds. The host implements `ApiKeyRepository`; `limit_expiry` is an atomic minimum and `touch_last_used` is monotonic, so concurrent rotations and several flushing instances cannot push a deadline back. Enabling the group without the feature or a repository, or supplying a repository without enabling it, fails the build with a `ConfigError` that never names the pepper or a scope. `AuthEngine` gains `issue_api_key`, `revoke_api_key` and `rotate_api_key` (label, scopes from the vocabulary and a future expiry are validated; the plaintext key exists only in the returned `IssuedApiKey`, whose `Debug` redacts it; a rotation keeps the label and scopes and retires the old key at once or after an overlap of up to 30 days, never extending an earlier expiry), `flush_api_key_last_used` (the core runs no timer: the host calls it every `api_keys.last_used_flush` and at shutdown, and a failed write stays queued) and `authorize_api_key`, the one access decision every transport makes: a route that declares no scopes is `403 auth.forbidden` before any key work; every verification reads one row and compares two 32-byte digests whatever the reason, with a key valid strictly before its expiry; any bad credential is `401 auth.api_key_invalid`, a valid key missing any declared scope is `403 auth.api_key_scope_insufficient` (a key must hold ALL of them), and a store failure is `500 auth.internal`. `AuthHooks::on_api_key_request` receives a typed `ApiKeyAccessEvent` for every guarded request, refusals included, with the reason and key id for the operator and never the key; its outcome and reason names are held to the shared contract's `apiKeys.auditEvent` in both directions. `api_keys.audit_mode = Required` awaits the hook under the detached-task ceiling and refuses an admitted request whose audit failed or timed out, and the build fails with `ConfigError::ApiKeysAuditRequiresHooks` when it is set without any `AuthEngineBuilder::hooks`. `ApiKeyClock` makes expiry and rotation testable without waiting; `InMemoryApiKeyRepository` and `ManualApiKeyClock` are under the `testing` feature. **Adapter.** `require_api_key_scopes(&state, &["reports:read", ..])` builds a tower layer for `Router::route_layer`: it reads the configured header only (never the query string; a header that appears twice, or whose value is not visible ASCII, is a malformed key; every value is marked sensitive), asks the engine for the decision with the route PATTERN for the audit, and either answers with the library's error envelope (an identical `401` body whichever credential was bad) or passes the request on carrying a `CurrentApiKey` (id, label and scopes, never the digest). A layer built with an empty scope list refuses every request. `spawn_api_key_flush(engine)` starts the task that writes the coalesced last-used instants every `api_keys.last_used_flush` and once more on `ApiKeyFlushTask::shutdown`; the host owns it and calls `shutdown` before the process exits. Building the layer or the task over an engine whose `api_keys` group is off is `ConfigError::ApiKeyGuardWithoutApiKeys`. Building the layer with a scope that is not in `api_keys.scopes` is `ConfigError::ApiKeyGuardUndeclaredScope` (the position of the entry, never its value): no key could hold it, so the route would otherwise refuse every request at runtime. There are no HTTP routes to manage keys: who may mint one is the host's decision.

- **The shared wire contract gains the `apiKeys` section, the API-key error codes and the password-reset response bodies.** The `apiKeys` section pins the key grammar, the digest with a known-answer vector, the verification steps, the refusals and the audit event; `credentialFormats.apiKey` and `responseBodies.passwordResetRequest` are new. `bymax_auth_crypto::api_key` implements the grammar and the digest and is asserted against the contract's numbers and vector, including that the digest is taken over the secret string as presented, so two base64url spellings of the same bytes are two different keys. `AuthErrorCode` and `AuthError` gain `ApiKeyInvalid` (`auth.api_key_invalid`, 401), `ApiKeyScopeInsufficient` (`auth.api_key_scope_insufficient`, 403) and `ApiKeyNotFound` (`auth.api_key_not_found`, 404); the generated `./shared` TypeScript types gain the same codes. A router test reads `responseBodies.passwordResetRequest` from the file and asserts that `forgot-password` and `resend-otp` answer its status and body, with identical raw bytes, for a known and an unknown account.

- **`AuthEngine::login_lockout(tenant_id, email)`: a read-only view of the dashboard login lockout (Rust-side addition).** It returns `LoginLockout { locked, retry_after_secs }` from the same counter and the same identifier `login` and `unlock_account` use (the address normalized the same way), so a host can show a lockout, or decide what to offer, without guessing from a failed login. It writes nothing and has no write counterpart, because a way to raise or clear the counter outside the login flow is a bypass; clearing stays `unlock_account`. The state follows recorded failures and not the existence of an account, so an unknown address answers as a known one. The adapter ships no route for it.

- **`password.blocklist`: the deployment's own words for the default password screen.** `PasswordConfig::blocklist` (default empty) extends the engine's default screen with words such as the product or company name, reduced the way a candidate is, so `Acme` also refuses `Acme2024!` and `@cme123`. A screen supplied with `AuthEngineBuilder::breach_checker` owns the decision and the list is ignored. nest-auth has the same option; rust-auth additionally bounds it at startup: at most 10 000 entries, each at most 128 characters and not reducing to nothing, otherwise `ConfigError::PasswordBlocklistSize` or `ConfigError::PasswordBlocklistEntry { index, .. }` (the entry is never echoed).

- **A cookie name carrying a `__Secure-` or `__Host-` prefix is checked at startup.** A browser enforces a prefix by silently dropping a `Set-Cookie` whose attributes do not match, so a deployment that renamed `access_token` to `__Secure-access_token` with `secure_cookies` off got no error and no cookie. `__Secure-` now requires the resolved `secure_cookies` to be `true`; `__Host-` also requires `Path=/` (the refresh cookie is held to `cookies.refresh_cookie_path`) and no `cookies.resolve_domains`. A violation is `ConfigError::CookiePrefixUnsatisfied`, naming the option, the name and the requirement. The default names are unchanged and unprefixed, so nothing breaks until a deployment opts in. nest-auth validates the same contract.

- **`HookContext.plane` and `AuthHooks::after_platform_logout`.** The tenant cannot tell the planes apart (a platform administrator has none, and the credential-free user a hook receives carries an empty one), so a consumer matching a hook against a live connection by tenant skipped every administrator. Every context the library builds now carries `plane: HookPlane` (`Dashboard` or `Platform`). A platform logout now reports through its own hook, `after_platform_logout`, instead of reusing `after_logout`, which a consumer wrote for tenant users and may answer with a tenant lookup an administrator cannot satisfy. The breaking parts are listed first, under Changed. Mirrors nest-auth `HookContext.plane` and `afterPlatformLogout` (`interfaces/auth-hooks.interface.ts`).

- **The account-status cache `user_status_cache_ttl` always promised, mirroring nest-auth 1.4.8's `AccountStatusService`.** The option existed and nothing read it, so every authenticated request that needed the account's status read the user repository. The gate now answers from a shared cache, `{ns}:us:{subject}` for the status and `{ns}:uev:{subject}` for the verified-address flag (written and read only where `email_verification.required`), where `subject = hmac_sha256(hmacKey, userSubject)` is the same tenant-scoped account subject the session index and the token epoch already use, so no account identifier sits in a key. The keys, the value forms, the TTL and the invalidation order are pinned in `conformance/wire-contract.json` (`userStatusCache`, plus `userStatus`/`userEmailVerified` in `redisKeyPrefixes` and `userSubjectDerivedKeys`), the same bytes nest-auth carries, so one Redis can serve both libraries. A miss on a fact the gate needs is answered by one tenant-scoped repository read that refills both; an account that no longer exists is `token_invalid` and is not cached. A status change now reaches requests within `user_status_cache_ttl` (default 60 s), or at once after the new `AuthEngine::invalidate_account_status(user_id, tenant_id)`, which drops the verified flag first and then the status, as nest does; `verify_email` calls it best-effort once the flag is committed. `user_status_cache_ttl = 0` turns the cache off. New `UserStatusCacheStore` trait, `EngineBuilder::user_status_cache` setter, Redis and in-memory implementations. The platform plane is not cached. **BREAKING:** `EngineBuilder::redis_stores` gains a `UserStatusCacheStore` bound, so a host-implemented store bundle must implement it; the Redis bundle and the in-memory test stores already do. **Behaviour change to know about:** a host that changes an account's status or verified flag directly in its repository and relied on the very next request seeing it must now call `invalidate_account_status` there, or accept up to one TTL of staleness. **Deployment note:** the entries are TTL'd cache values, so nothing needs migrating, but a deployment that runs this library beside a backend that keys them differently (for example by the percent-encoded tenant and user id) names other keys than that backend does: an invalidation issued by one side deletes a key the other never reads, so a changed status can be served stale for up to one TTL. Drain the other shape before this one serves to avoid even that.

- **`AuthEngine::verify_access`: one call that runs the whole access-token chain for any transport.** The extractors compose the building blocks themselves; a consumer outside them (a WebSocket upgrade, an SSE stream, a background consumer) had `verify_access_token`, `verify_platform_token` and `assert_user_active*` and had to re-assemble the order, which is how a revocation read or a status re-check gets dropped. `verify_access(token, &VerifyAccessOptions::new(AuthPlane::Dashboard | Platform))` checks signature and expiry, the named plane's token type, both revocation channels, claim shape (`jti` a UUID v4, `sub` and tenant 1..256), the tenant binding (when `.request(&ctx)` is supplied; with `enforce_tenant_binding` on and no request, that is logged once), the account's current status, then the second factor, in that order, and returns `VerifiedAccessToken::{Dashboard, Platform}`. `require_mfa` and `check_status` default to on. A dashboard token presented on the platform plane answers `platform_auth_required`; every other token refusal, and every tenant-resolver failure, answers `token_invalid`. Mirrors nest-auth 1.4.8's `AuthTokenVerifierService.verifyAccessToken`.

- **`AuthEngine::assert_platform_active`: the platform administrator's status gate.** The dashboard plane had a tenant-scoped status gate and the platform plane had none outside login and refresh, so a suspended administrator's still-valid access token kept verifying for its whole lifetime. The check refuses an unknown administrator and a deployment with no platform repository (a token reaching it cannot have been issued here) with `token_invalid`, and a blocked status with its `Account*` code. Mirrors nest-auth's `assertPlatformAccountUsable`.

- **`AuthConfig::identifier_key`: rotating `jwt.secret` no longer has to rename every identifier.** The Redis names that identify an account (session index, token epoch, MFA keys, recent-authentication marker, OTP and rate-limit identifiers) and the stored MFA recovery-code digests are HMACs under a key derived from `jwt.secret`. Rotating it alone renamed all of them: every token epoch read zero, so a token that a password reset or a revoke-all had refused was accepted again until it expired. With `identifier_key` set to the value `jwt.secret` has today, the derivation does not move and a later rotation leaves them where they are. Unset, the key derives from `jwt.secret` exactly as before, so nothing changes on upgrade. The value is held to the same length and entropy bar as `jwt.secret` (`ConfigError::IdentifierKeyTooShort`, `ConfigError::IdentifierKeyLowEntropy`), and it never signs or verifies a token. The README has the rotation guide with both paths: routine rotation, and rotation after a compromise. The shared `conformance/wire-contract.json` documents the option. New public field: `AuthConfig::identifier_key: Option<SecretString>`.

- **An unaccompanied change to the shared wire contract now fails the build.**
  `conformance/wire-contract.json` is held byte-identical by nest-auth, and the suites only ever
  read *values* out of it (a preimage template, a status, a record shape) — so a change to a part
  nothing happened to read yet, or a reformat that rewrites every line while changing no value,
  passed. `crates/bymax-auth-core/tests/wire_contract_identity.rs` pins its SHA-256,
  so every byte change here has to be declared in the same commit by someone who looked at it.

  **It does not gate cross-implementation divergence, and calling it that would be false.** Walk
  it through: nest-auth changes the contract and its own constant in one commit — its suite is
  green; nothing moved here, so this suite is green; bytes divergent. Two independent local hashes
  cannot enforce agreement between two repositories, because neither reads the other. Closing that
  needs a comparison that crosses the boundary — one side fetching the other's committed blob in
  CI, or both consuming one immutable versioned artifact — which is proposed, unbuilt, and a
  maintainer call on both ends. Until then the identity rests where it already rested: on both
  maintainers changing the file deliberately and together. This narrows the accident, not the
  divergence.

  The working tree is hashed rather than `git show HEAD:`, which is the authoritative form: `git`
  is not reachable from every place these tests run (a mutation run executes against a copied tree
  with no repository in it), and a check that skipped itself there would pass on a broken state in
  the very place the gate measuring the tests runs.

### Fixed

- **A `bymax-auth` flow feature now reaches the adapters that gate the same flow.** The facade's `sessions`, `mfa`, `oauth`, `platform` and `invitations` features enabled only `bymax-auth-core`, so a consumer who selected `axum` or `redis` through the facade compiled the adapter without its half of the flow: with `axum` and `platform`, the platform extractors and the route groups behind each flow did not exist through `bymax_auth::axum`; with `redis` and `mfa`, the Redis stores lacked their MFA implementation. Each flow feature now forwards as a weak dependency feature (`bymax-auth-axum?/mfa`, `bymax-auth-redis?/mfa`, ...), which enables nothing when the adapter is not selected; `bymax-auth-redis` has only `mfa`, `oauth` and `platform`. A test reads the manifests and fails if a feature the facade shares with an adapter is not forwarded to it.

- **A failed password-reset request releases its resend cooldown and logs what it cannot tell the caller.** `forgot-password` and `resend-otp` share one cooldown, and a request that failed still held it, so the retry a failure invites was answered with a silent `200` that sent nothing, for up to a minute. The cooldown a request took is now released when the request itself observes the failure (the account lookup, storing the code or the reset token, the reset-link send); a failure of the detached code send, which the request never sees, leaves it in place, because a release from a detached task could delete the cooldown of a later request. A failure before the account is known (the cooldown gate, the account lookup) answers `500 auth.internal` after the 300 ms floor, as before. A failure after it is known (storing the code or the reset token, sending it) is logged with its cause and no account detail, and the `200` stands; `resend-otp` used to drop that failure without a log line, and an undeliverable reset link or code is now reported the same way on both routes. A cooldown hit waits the same floor as every other exit. The reset-link send, which is awaited inside the request, is now bounded by the 5 s detached-task ceiling, so a mail provider that never answers delays the response by at most that long instead of indefinitely. `OtpStore` gains `release_resend`, whose default releases nothing, so an existing implementation keeps compiling and its cooldowns run out as they did. `conformance/wire-contract.json` is adopted from nest-auth `a42af48` (sha256 `e5f59075…629f7`): `responseBodies.passwordResetRequest` gains `failures`, and the identity pin moves with it.

- **`useAuth().logout()` revalidates the session after a logout the route refused with a `4xx`.** The provider used to revalidate only after a successful logout, so it kept showing the old user after a `4xx` until the next interval. It now revalidates at once and then rejects with the same error. A `429`, a `5xx` or a transport failure rejects and keeps the state, because nothing was revoked. The failure is read by its `status`, since the `./react` and `./client` bundles each carry their own copy of the error class.

- **The Next.js logout route no longer reports a sign-out the backend did not complete.** It cleared the session cookies and answered `200` whatever the backend did, so a backend that answered `5xx`, or could not be reached, left the session alive while the browser dropped the only cookies that could end it. The route now clears the cookies and answers `200` only when the backend answered below `500` and did not throttle the call; a `5xx` is answered with that same status, a throttled call (`429`) with that status and its `Retry-After`, and an unreachable backend with `502`, all with the error envelope (`auth.internal`, or `auth.too_many_requests` for the throttled call), `cache-control: no-store` and no `Set-Cookie`. A deployment that relied on the route always answering `200` now sees `5xx`/`502` while its backend is failing.

- **A logout that completes on a retry announces itself, once.** A logout attempt that fails one of its writes (the access-token blacklist, the refresh-session delete, the grace-pointer delete) still deletes the refresh session, so the retry that completes the logout found no session, named no owner and never delivered `after_logout` / `after_platform_logout` for it: a deployment that closes its own sessions from that hook lost the signal exactly when a store was unhealthy. The failing attempt now records its owner under `lp:{sha256(refresh_token)}` (`plp:` on the platform plane) as `{ userId, tenantId }`, best effort and before the failure is raised, with a TTL of the access-token lifetime rounded up and never less than 300 seconds. A retry that finds no session reads the owner from the marker, and the logout that completes removes it; when the owner came from the marker the hook fires only if that removal removed the key, so racing retries announce once. The guarantee is exactly-once for sequential retries and at-least-once when attempts of one logout run concurrently. A marker that cannot be read ends the retry before any write; one that cannot be claimed answers an error, so the client retries. `SessionStore` gains `put_logout_pending`, `read_logout_pending` and `claim_logout_pending` (defaults: store nothing, read `None`, claim `false`) and the `LogoutOwner` record type. **Contract:** `conformance/wire-contract.json` is updated from nest-auth (`redisKeyPrefixes` gains `dashboardLogoutPending` / `platformLogoutPending`, `recordEncodings` gains `logoutPending`) and its identity pin moves with it. **Apply to a custom `SessionStore`:** implement the three methods to get the retry announcement; without them a retry names no owner, as before.

- **A platform MFA challenge rewrites a secret that opened under a retired key.** The dashboard challenge already re-encrypted a TOTP secret that only a key retired by a rotation could open, so the rotation drained and the retired key could be dropped. The platform challenge decrypted it and moved on: platform administrators' secrets stayed under the retired key for good, and a leaked retired key kept opening every one of them. A TOTP challenge now writes the secret back under the current key, and the recovery-code path carries the re-encrypted secret in the write that spends the code. The TOTP-path write carries the record's recovery codes as they are. On both planes, the write that rewrites the secret or spends a recovery code is abandoned when the stored secret is no longer the one the challenge opened: a holder who re-enrolled in between keeps the new secret, and the challenge still completes with the code spent.

- **A refresh of a dashboard session whose record names no tenant is refused before anything is rotated.** The stored record is what a refresh builds the next session from, and a record with no tenant (written by an older or foreign writer) used to consume the presented token and store a successor under a tenant-less subject that no client held, then answer `401` from a later step. It now answers `401 auth.refresh_token_invalid` first and leaves the presented token and its record as they were. A grace-window recovery whose recovered record names no tenant is refused the same way and writes nothing; the rotation script has already spent the single-shot grace pointer.

- **A password-reset code that could not be stored is logged.** `POST /auth/password/forgot-password` answers the same success whether or not the account exists, so a failure after the account was found (storing the code, or the reset token) is swallowed on purpose. It was swallowed without a trace. The failure is now logged once with its cause by `Display` and nothing that identifies the account. The response is unchanged.

- **A body that declares a `Content-Encoding` other than `identity` is refused before authentication and rate limiting, on the routes the shared contract names.** The adapter refused such a body (`415`) only after the route's own authentication and rate limit had run, so an unauthenticated request got `401` where nest-auth answers `415`, and a refused request spent a rate-limit slot. The check now runs as a layer outside every route layer, scoped by the contract's `requestEncoding` section: every route is checked except the contract's `unchecked` list, the `whenBody` routes refuse only a request that carries a body, and `GET`, `HEAD`, `OPTIONS` and `DELETE` are never checked. A conformance test drives every route of that section from the contract file. **Contract:** `conformance/wire-contract.json` is updated from nest-auth (new `requestEncoding` section; `transportErrors` gains the wording for the encoding refusal and a `400` row for a body parser's typeless `400`), and its identity pin moves with it.

- **A failed logout write and a failed over-cap eviction now log the cause, not just "internal error".** Both warnings printed the error's own `Display`, and `AuthError::Internal` displays as `internal error` with the real cause held as its `source()`, so the log line for a refused blacklist write, session delete or grace-pointer delete during logout, and for a store that refuses to evict a session over the concurrent-session cap, said nothing an operator could act on. They now render the error and each of its causes by `Display`, joined with `: ` (the same rendering the session-cap listing warning uses), still never `Debug`, which a store may derive over the session details it was holding. What the client receives is unchanged: logout still answers a generic internal error after attempting every write, and an eviction failure still never fails the operation that scheduled it.

- **A request the adapter cannot read answers the shared `transportErrors` envelope, and no rejection repeats the request.** `ValidatedJson` and `ValidatedQuery` put serde's own text in the `body` and `query` detail, so `POST /auth/login` with `"abc"` as its body answered `invalid type: string "abc", expected struct LoginDto at line 1 column 5`, an unknown key came back as ``unknown field `...` ``, and the internal type name rode along: every value, key and type a client chose was echoed. A body over the limit answered `400` with axum's text (or, with a declared `Content-Length`, a plain-text `413` from the limit layer), a `Content-Type: application/json; charset=nope` was accepted, and an invalid-UTF-8 path parameter answered axum's plain `Invalid URL: ...`. Now, as `conformance/wire-contract.json` (replaced by the updated shared file, SHA-256 `59f246ced4bf0ee935ec075b85e33b898c5d4e83f7aa6fa7202de6547e0e94b8`, which adds `transportErrors`) pins: a body that is not JSON, or whose root is not an object or array answers `400` `Malformed request` (a bare string or number included), and a body that cannot be read, other than for size, answers the failure's own `4xx` with the same message; a body over the limit answers `413` `Request entity too large`, whether it declares its length or not; a charset other than UTF-8 or a `Content-Encoding` other than `identity` answers `415` `Unsupported media type`; an undecodable path parameter answers `400` `Malformed request`. Each is `auth.validation` with a fixed message and `details: null`. A body that parses as JSON but does not fit the route answers `400` `Validation failed` with one `body` detail and a fixed message, and a query string that does not fit answers a fixed `query` detail. `Content-Type: text/plain` or none is unchanged (`400`, `content-type` detail). The refresh, logout and revoke-all routes keep their lenient body handling (no `Content-Type` check), and refresh answers the envelopes for a body that is not JSON, while logout and revoke-all still ignore one; all three answer the envelope for a body over the limit or one that cannot be read; the raw-body routes use a crate extractor, so their over-limit answer is the envelope and not axum's text. **Behaviour change:** the status of an oversized body (`400` to `413`), the acceptance of a non-UTF-8 charset (now `415`), the message and shape of every body and query rejection, and the `Rejection` type of `ValidatedJson` (now `BodyRejection`, a type that renders the two envelopes) all change; an empty body for a JSON route is now `Malformed request`.

- **A login no longer fails, after its session was stored, because the session-cap listing could not be read.** The concurrent-session cap lists the user's sessions once the new one is committed, and an error from that read was returned to the caller: password login, registration, invitation accept, OAuth sign-in and the MFA challenge answered `500 auth.internal` with the session already live in the store, so the client never received the tokens for a session that stayed alive until it expired, and a retry created another. The listing error is now handled where the cap is enforced: it is logged once (the error and each of its causes, by `Display`, and the user id; never `Debug`, which a store may derive over the session details it was holding), **nobody is evicted** (a partial list would evict the wrong sessions) and the new-session hook still fires; the login succeeds and the user may stay over the cap until a later login lists normally. A missing or unparseable session detail is unchanged (that session is the oldest and is evicted first). **Behaviour change:** `SessionService::after_session_created` no longer returns a store error for a failed listing.

- **The expiry of the OAuth `state` cookie and of the MFA-temp cookie carries the attributes the cookie was planted with.** `clear_oauth_state_cookie` and `clear_mfa_temp_cookie` removed their cookie with the name and path alone, so the `Set-Cookie` expiry had no `HttpOnly`, no `Secure` and no `SameSite`, while the plant sets all three. The OAuth `state` expiry is now `HttpOnly`, `Secure` as configured and `SameSite=Lax` (the plant is always `Lax`, whatever the deployment configures), and the MFA-temp expiry is `HttpOnly`, `Secure` as configured and the configured `SameSite`. The path is unchanged, so a browser still matches the deletion to the cookie it planted. nest-auth sets the same three attributes on both (`oauth.controller.ts` and `mfa.controller.ts`, `clearCookie`).

- **One damaged session-detail record no longer fails the listing, and a dead index member is removed.** `list_sessions` on the Redis store parsed each `sd:`/`psd:` record with `?`, so a single value that was not a whole detail (written by another version, truncated, or foreign) failed `GET /auth/sessions` for the whole account, and the session-cap enforcement that lists too. A record that is absent or not a whole detail now leaves its session out of the result and the rest are listed. The index member of such a session is removed only when its `rt:`/`prt:` key is gone as well, because the detail alone does not say the session is dead: a live session whose detail was damaged stays in the index, where a sign-out-everywhere still reaches it. Before, a member whose `rt:` key had expired and whose detail was gone stayed in the index for as long as the account was in use. What acts on sessions does not read the display listing: `SessionStore` gains `list_session_entries`, which names every live session whether or not its detail can be read (`detail: None` when it cannot), and "sign out other devices" and the concurrent-session cap work from it, so a session with a damaged detail is revoked and counted like any other and, having no creation time to order by, is evicted first. `list_sessions` stays the display view and omits it. The new trait method has a default built on `list_sessions`, so a host-implemented store keeps compiling; a store that can hold a live session without a readable detail overrides it, as the Redis store does. The existence check and the removal are one script, so a member whose key is written between the two is never dropped while live. A failed read of a detail key is an error: the listing fails with it rather than answering a partial list that silently omits a live session, and nothing is pruned on it, so a Redis outage cannot empty an index.

- **A logout answers an error, and keeps the auth cookies, when a revocation write failed; it no longer answers `204` over a live access token or refresh session.** The dashboard and the platform logout discarded the result of the write that blacklists the access token (`rv:{jti}`), and the routes discarded the engine's result, so a store that refused that write while still serving reads produced a `204`, cleared the cookies, and left the access token authenticating until it expired, with nothing logged. Both logouts now attempt every revocation write whatever an earlier one did, and answer the first failure as `AuthError::Internal` (HTTP 500, `auth.internal`); `204` means every write succeeded. A retry is idempotent and finishes whatever was left. `POST /auth/logout` and `POST /auth/platform/logout` no longer discard the result, and the dashboard route clears the cookies only on success so the client still holds what the retry needs. The refresh-session lookup that names the owner now fails closed before any write, instead of being treated as "no session"; the retry then starts from the same state. The `after_logout` and `after_platform_logout` hooks fire only for a logout that succeeded, and name the owner the session record gives. When the first attempt deleted the session but the blacklist write failed, the completing retry finds no session, names no owner, and delivers no hook for that logout. **Behaviour change:** "a logout is never blocked by a store failure" no longer holds; `AuthEngine::logout` and `platform_logout` return `Err` where they returned `Ok`. Reads keep failing closed as before.

- **The engine refuses a WebSocket ticket for an MFA-enrolled session that has not cleared its challenge, and refuses to redeem a snapshot that names no tenant.** `POST /auth/ws-ticket` gated on `MfaSatisfied`, but `AuthEngine::issue_ws_ticket` did not, so a host that mints through the engine without that extractor handed a socket to a session that skipped its second factor; the ticket then outlives the challenge for the socket's whole life. The engine now answers `AuthError::MfaRequired` first, before any read (nest-auth's `issue` asks the same question first). At redemption a snapshot with no tenant, or an empty one, was rebuilt into `DashboardClaims` whose `tenant_id` was the empty string; it is now refused with the same `TokenInvalid` an unknown ticket gets. This engine mints only dashboard tickets, so such a record was not written by it, and the platform-plane revocation branch that served it is gone. The shared record shape still allows a record without a tenant (nest-auth's interface calls it a platform ticket), but neither library mints one: nest-auth's `issue` takes a dashboard payload and always sets the account's tenant. Behaviour change: a ticket whose snapshot lacks a tenant, which this library never wrote, no longer redeems.

- **A logout whose body carries extra keys revokes the refresh session it names, and a body that carries only a refresh token ignores keys it does not read.** `RefreshDto` denied unknown fields, so `{"refreshToken": "...", "client": "web"}` was a `400` on refresh where nest-auth, which has no DTO on these routes and reads only `refreshToken`, serves it. On logout the effect was a security defect, not an error: the body was swallowed as unreadable, so the call answered `204` while the refresh session it named stayed alive and kept rotating. This covers dashboard and platform refresh and logout and `POST /auth/sessions/revoke-all`; every other body, including login, stays strict about unknown keys, pinned by a test so the loosening cannot spread. One difference remains and is unchanged: on the two refresh routes a non-string `refreshToken` or a body that is not a JSON object is a `400` here, where nest-auth reads it as no token and answers `401 auth.refresh_token_invalid`. On logout and `revoke-all` both backends already treat such a body as no token.

- **An email address is trimmed and lowercased before it is validated, and a whitespace-only platform password is refused.** Every email field was checked as written, so `" a@e.com"` was a `400` where nest-auth accepts it: its DTOs trim and lowercase first. The twelve email-carrying bodies (register, login, forgot and reset password, verify and resend OTP, verify and resend email, platform login, change email, create and revoke invitation) now do the same, so a padded or upper-case address reaches the same account the canonical one does. The engine already canonicalized the address for the lookup and the lockout key, so this changes only what is accepted at the edge. The whitespace set is JavaScript's, which differs from Rust's at U+FEFF (trimmed here, as in nest-auth) and U+0085 (not trimmed here, as in nest-auth). Lowercasing needed no special mapping: Rust's agrees with JavaScript's on the contextual cases, measured in Node and pinned in the tests (the final sigma, which depends on the characters around it, U+0130, the Kelvin sign and full-width capitals). A platform login password made only of whitespace is a `400 auth.validation`, as in nest-auth (`/\S/`).

- **A second-factor code of the wrong shape is a `400` and is never counted as a failed attempt.** The TOTP-only bodies (`verify-enable`, `disable`, `recovery-codes`) checked only that the code was six characters long, and the challenge accepted any string of up to 128 characters, so `abcdef` or `12345a` reached the engine, answered `401 auth.mfa_invalid_code` and counted against the account's lockout. A TOTP code must now be exactly six ASCII digits, and the challenge takes that or a recovery code (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, hexadecimal digits of either case, at most 29 characters), as nest-auth's validators do. Anything else answers `400 auth.validation` before the engine is touched. The challenge's length ceiling drops from 128 to 29.

- **`POST /auth/ws-ticket` answers `{ ticket, expiresIn }`, the body the shared wire contract pins.** The response carried `ticket` only, so a client that read `expiresIn` (as nest-auth's does) got `undefined` and had to hard-code the lifetime, which is not fixed: a ticket lives for the smaller of 30 seconds and what the minting access token has left. `expiresIn` is that lifetime in whole seconds, the same value the ticket was stored under. `AuthEngine::issue_ws_ticket` now returns an `IssuedWsTicket { ticket, expires_in }` instead of the bare string. The lifetime is now measured from the clock rounded **up** to the next whole second, with one second held back, as nest-auth does: with the clock rounded down, a ticket whose store write landed late in the second could end up to a second after the access token that minted it, which is the one thing the lifetime exists to prevent.

- **An MFA temp token presented at the other plane's challenge route no longer completes a login that is then thrown away.** `POST /auth/platform/mfa/challenge` ran the whole challenge for a dashboard temp token (consumed the token, verified the code, created a dashboard session, fired the login hooks) and only then refused the result, and `POST /auth/mfa/challenge` did the same for a platform token (completing the platform login and stamping its last-login time). Each answered `401 auth.mfa_temp_token_invalid`, so the account was left with a session whose tokens nobody received (it counts against the per-user session limit and can evict a real one), the hooks had fired for a request that failed, and the user had to log in again because the token was spent. The plane is now read from the token's own `context` claim before anything is consumed. The platform route refuses a dashboard token with `401 auth.platform_auth_required` and spends nothing; the dashboard route serves a platform token with the platform session in the body (no cookies), as nest-auth's does. `AuthEngine::dashboard_mfa_challenge` is removed and `MfaService::challenge_platform_only(...)` is added.

- **A refused cross-site caller of the Next.js silent-refresh route is redirected to sign in instead of getting a bare `403`.** A person who follows a link into the app from another site after the access token expired reaches the route on a navigation the browser marks cross-site on every hop, so the refusal left them on a blank `403`. The route now answers `307` to `loginPath?reason=expired`, the target a failed refresh already uses. What the refusal exists for is kept: no refresh is attempted, no backend call is made and no `Set-Cookie` is written. The client-refresh and logout routes are unchanged. A page that treated a `403` from the silent-refresh route as a signal now sees a redirect. Mirrors nest-auth 1.4.12.
- **The refresh cookie's expiry carries the `SameSite` the cookie was issued with.** The refresh cookie is `Strict` unless the deployment is configured `None`; its expiry on logout named no `SameSite` at all. It now names the same one, so a browser that matches the two sees one cookie being replaced. Mirrors nest-auth 1.4.12.

- **A delivery mode reads the refresh token from its own channel only.** Refresh, logout, password change and the session routes took the cookie and then the body in every mode, so a `cookie`-mode deployment accepted a token a script put in a request body, and a `bearer`-mode one accepted a stray cookie, neither of which that deployment issues. `cookie` mode now reads the refresh cookie only, `bearer` the body only, and `both` the cookie first and then the body, as the specification and nest-auth do. A client that sends the token on the wrong channel (a body token to a `cookie`-mode backend, or a cookie to a `bearer`-mode one) now gets `401 auth.refresh_token_invalid` from refresh and its logout does not revoke the refresh session; it must use the channel its mode delivers on. The reading also closes a confusion vector: a body-supplied token can no longer be redeemed in place of the cookie in `cookie` mode. The Rust client speaks `bearer` and is unaffected.

- **A resolver that names several cookie domains gets a session on, and a logout from, every one of them.** The adapter used `domains.first()` only, so the session was planted on the first domain and a logout cleared only that one: the session cookie a browser kept for the second domain stayed signed in. Each resolved domain now receives the full set of three cookies, and the logout clears each one. The logout's expiry cookies also carry `Secure` whenever the planted ones do, so an expiry is never weaker than the cookie it removes. With no resolver the cookies are still host-only. nest-auth does the same.
- **The refresh cookie follows a cross-site `SameSite=None` deployment, and the MFA-temp cookie follows the configured `SameSite`.** Both were hard-coded to `Strict`, so neither could follow a cross-site deployment (`same_site = None`): a browser does not send a `Strict` cookie on a cross-site request. The refresh cookie is still `Strict` under `Lax` and `Strict` (the long-lived credential keeps its tightest posture by default) and becomes `None` only when the deployment is configured `None`; the MFA-temp cookie takes the configured value, as the specification states.
- **The `Host` handed to the cookie-domain resolver is a plain hostname or empty.** The header was cut at its first colon, so `[::1]:8080` reached the resolver as `[`, and a value such as `evil.com; Path=/` reached it verbatim. The port is now cut the way Express does it and the result must be letters, digits, dots and hyphens, as in nest-auth; anything else is the empty string, which a resolver answers with no domain.

- **`after_mfa_enabled` and `after_mfa_disabled` report the account as the transition left it.** Both hooks fire after the second factor is written, but the account they were handed was projected from the record read before the write, so "after MFA enabled" reported `mfa_enabled = false` and "after MFA disabled" reported `true`, on both planes and for the administrative `reset_mfa` as well. They now report `true` and `false` respectively. A handler that branched on the old, inverted value (for example to decide whether to send an alert) now sees the real one. Only the flag changes: the payload is still credential-free and the stored record is not touched. `after_mfa_recovery_codes_regenerated` does not change the flag and is unchanged. Mirrors nest-auth's fix of the same defect.

- **Five notification hooks no longer run on the response path.** `on_login_failed`, `on_lockout`, `on_new_session`, `on_session_evicted` and `on_refresh_token_reuse_detected` were awaited inline with no time bound, so a slow or hung consumer hook delayed the refusal of a failed login (a latency signal about which branch the attempt took) and could hold a request open for as long as it hung. They now run detached under the same five-second ceiling as the `after_*` hooks, errors and panics logged and dropped, which is what the hook discipline in the specification already promised and what nest-auth does (it never awaits them). A hook that finishes after the response is still delivered; a test or a consumer that read a hook's effect immediately after the call must now wait for it.

- **`on_session_evicted` receives the evicted session's stored hash, not its first eight characters.** The trait documents "the stored hash, never the raw token" and nest-auth passes it (`session.service.ts`, `enforceSessionLimit`), but the hook got an eight-character prefix, which could not be matched with a stored or listed session. The full hash is the SHA-256 of the refresh token, so it cannot be used to act as the session. **Behaviour change:** a handler that compared the eight-character form must compare the full 64-hex hash; `on_new_session` still receives the short form, as in nest-auth.

- **`after_logout` names the tenant of the session that ended.** Its context carried no tenant although the session record the logout reads names one, so a consumer closing live connections could only match the user id, and a repository id is unique only within a tenant. The tenant is now set when the record carries one.

- **Completing an MFA challenge now stamps the last-login time, and on the platform plane fires `after_login`.** The password step stops at the MFA temp token for an account with MFA, so neither the last-login time nor `after_login` could run there; the challenge is the only place they can. The dashboard challenge fired `after_login` but never `update_last_login`, so an MFA account's `last_login_at` never moved. The platform challenge did neither (and its comment said no hook fires). Both planes now update the account's own repository and the platform plane fires `after_login`, as nest-auth does (`mfa.service.ts`, the `challenge` completions).

- **Platform administrators' MFA hooks now fire.** `after_mfa_enabled`, `after_mfa_disabled` and `after_mfa_recovery_codes_regenerated` ran only for dashboard users, so a deployment alerting on MFA changes never heard about an administrator's. They now fire for both planes. An administrator is passed as a `SafeAuthUser` with an empty `tenant_id` and `email_verified = true` (provisioned, not self-registered), with `HookContext.plane` set to `Platform`.

- **The refresh-token reuse hook now says which plane and where the replay came from.** Its `HookContext` carried an empty IP and user agent although the rotation holds both; it now carries the replaying request's IP and user agent and the plane (dashboard or platform).

- **An invite whose last store call fails no longer leaves a redeemable record, and a failing cleanup no longer masks the refusal.** After the record is written, `invite` confirms the invitee index still names it. When that confirmation returned a store error the `?` propagated it without removing the record, leaving a live invitation behind a call that reported failure; the record is now withdrawn best-effort and the original error returned. When the index had moved, the withdrawal's own failure replaced `InsufficientRole`; it is now logged at `warn` and the refusal stands. No email is sent in either case.

- **A blocked, unverified or deleted account with a pending second factor is now told that, not `mfa_required`.** `MfaSatisfied` demanded the challenge before it looked at the account, so the answer depended on whether the handler also listed `UserStatus` first. With an MFA challenge pending the extractor now runs the status gate (`assert_user_active_and_verified`) before refusing: a blocked account answers its `account_*` code, an unverified address `email_not_verified` where verification is required, and a deleted account `token_invalid`. Accounts with no pending challenge pay no extra lookup. This is the same order as nest-auth's access-token verifier.

- **The contract test read a hand-written subset of the section it was checking, and that is how
  the session keyspace below stayed unfixed with a green gate.** `userSubjectDerivedKeys` holds
  eight entries; the assertion listed six, naming them "the six keys that were in the blind spot"
  — true when it was written. `sessionIndex` and `tokenEpoch` entered this repo's copy of the
  contract in the length-prefix change below, which adopted nest-auth's file byte for byte; the
  test's literal list was not extended in that same commit. From that moment the two keys the
  contract itself calls mandatory were pinned by nobody, and rust-auth kept the pre-relocation
  shape with the gate reporting agreement.

  The assertion is now exact set equality against the section, in both directions: a key added to
  the contract fails the build until rust-auth derives it, and a key removed fails until the
  removal is understood. Each entry is additionally checked to be an HMAC rather than a bare
  digest, the two that moved are pinned by shape, and the session subject is asserted to be the
  same derivation as the MFA subject — an MFA state change revokes sessions and bumps the epoch,
  so a second spelling of the subject would have those two writes name different accounts.

  This is the same failure mode as the error-catalog entry below, one contract section over: a
  parity test that reads only what it happens to list is not a parity test.

- **BREAKING: a request naming `tenantId` is now refused when the deployment configures a
  `TenantIdResolver`**, instead of being accepted and silently discarded. A security audit of a
  derived backend found `POST /register` answering `201` for
  `{"tenantId": "attacker-chosen-tenant", ...}` while creating the account under the resolved
  tenant — the caller's belief about which tenant it registered into diverging from server state,
  on the boundary the resolver exists to defend, with nothing in the response saying so. No
  privilege crossed, and that is why it survived: accept-and-ignore is the worst of the three
  available answers precisely because it looks like success.

  The refusal is **conditional, and the asymmetry is the point**. Without a resolver the field is
  the only thing that can name a tenant — `resolve_tenant` already answers `400` when it is
  absent — so refusing it outright would break every deployment that relies on it. With a
  resolver configured it does not participate at all, and `deny_unknown_fields` already refuses a
  property that does not exist on exactly that principle. This makes the principle config-aware
  rather than carving an exception out of it.

  `null` and an omitted field are not refused: both deserialize to `None`, the caller asserted
  nothing, and there is nothing to contradict. The refusal is placed **before** the resolver runs,
  so a caller cannot tell a refusal apart from a deployment whose resolver would have failed.

  **Apply to a derived backend:** if you configure a `TenantIdResolver`, stop sending `tenantId`
  on the nine endpoints that accept it. Eight read it from the **request body** — `register`,
  `login`, `verify-email`, `resend-verification`, `forgot-password`, `reset-password`,
  `verify-otp`, `resend-otp` — and one reads it from the **query string**:
  `GET /oauth/{provider}?tenantId=…`, so dropping a body field is not the change to make there.
  All nine answered `200`/`201` while discarding the value and now answer `400 auth.validation`
  with `field: "tenantId"`. Deployments without a resolver are unaffected — the field remains
  required there.

  Paired with nest-auth's own refusal (its `resolveTenantId`, released in 1.4.2), down to the
  message bytes: `tenantId is decided by this deployment and must not be sent`. Held in one
  `BODY_TENANT_REFUSAL` constant so the string the two backends share has one place to drift from.

- **BREAKING (npm client): `tenantId` is optional, and `useAuth()` no longer invents `'default'`
  for a caller that named no tenant.** `LoginInput`, `RegisterInput` and `ResetPasswordInput`
  declared it required, and the React `login` / `forgotPassword` hooks substituted `'default'`
  when the caller passed nothing — so against a resolver-configured backend every call through
  those hooks now names a tenant the deployment refuses, and against a backend without a resolver
  it silently signed people into a tenant they never chose. The field is now omitted when absent
  (`JSON.stringify` drops it), which lets one client serve both deployment shapes and lets the
  backend's own `400 auth.validation` say which one this is. A caller that relied on the implicit
  `'default'` must now pass `tenantId: 'default'` explicitly.

- **The error-catalog parity test now reads the shared contract's status table instead of one
  written down beside it.** `conformance/wire-contract.json` pinned the code vocabulary but never
  the HTTP status per code, and what is not in the shared artifact has no gate: thirteen codes
  answered a different status on each implementation, with nest-auth the outlier in all thirteen
  and both suites green throughout — each side was self-consistent, and neither read the other.
  `tests/error_catalog.rs` carried a hand-written `(variant, string, status)` table under a doc
  comment claiming that "a code whose serialization or status drifts from nest-auth breaks parity
  and fails here"; it checked rust-auth against itself. A parity test that reads only its own side
  is not a parity test.

  The contract gains `errorCatalog.statuses` (and a `$statusesComment` recording the incident),
  copied byte-identical from nest-auth. The status column is gone from the test, which now asserts
  `code.to_wire().http_status()` against the contract's value for every code, plus exact set
  equality between the contract's statuses, the contract's codes, and the enum's variants — a code
  with no status and a status with no code both fail. An exhaustive match anchors the table to the
  enum, so a variant added without a row stops the build.

  **No status rust-auth answers changed**, and none needed to: rust-auth's table was the
  semantically correct side in all thirteen, and nest-auth moved to it. The contract pins **wire**
  statuses, so `auth.otp_max_attempts` is 401 there — the status of the `auth.otp_invalid` it
  collapses onto — while the variant keeps 429 pre-remap for logs. `AuthError::http_status()`
  already resolved the wire code before reading the status, which is why answering the 429 was
  never reachable: only a record that exists can reach an attempt ceiling, so a 429 would say
  through the status line exactly what the collapse withholds from the body.

- **Three documents describing that collapse were wrong about it.** §8.6 of the technical
  specification carried a second, stale copy of the status map — naming five variants the engine
  does not have — and claimed to be authoritative; it now points at §15.3 and the contract. §8.6
  and the `error_response` rustdoc both said the OTP cap emits a `Retry-After` header. The code
  never did, and must not: on a response that reads `auth.otp_invalid`, that header hands back
  through the headers exactly what the code collapse withholds. §15.5 listed three internal-only
  codes when there are five, and `error.rs` said the same in its module doc.

### Security

- **The session index and the token epoch are keyed on the tenant-scoped user subject, not on the
  bare user id.** `sess:`/`psess:` and `ep:`/`pep:` were built from the repository id alone, and
  `UserRepository::find_by_id` takes a tenant precisely because an id may not be unique across
  them. On a host that numbers users per tenant, suspending `t1/u1` swept the sessions and bumped
  the token epoch of `t2/u1` — a credential-free cross-tenant revocation, reachable by anyone who
  could get an account suspended in their own tenant. The same root cause as the account-status
  gate below, in the keyspace rather than in a lookup. The bare id was also an account identifier
  in the clear in a store both libraries read, which is the second reason every key here is an
  HMAC and not a bare digest: a user id carries too little entropy for a plain hash to hide it.

  All four now derive `hmac_sha256(hmac_key, user_subject)` in lower-case hex — the same
  derivation the MFA keyspace already used, reached through the new `SessionKind::plane`. The
  platform arm carries no tenant segment, because its admins are cross-tenant and have none; it
  still moves off the bare id, and that pair is the one that matters most: a `pep:` left behind
  revalidates admin access tokens a revocation had already killed.

  The store seam moved with it. Every `SessionStore` method that names an ACCOUNT now takes a
  `subject_hash` the engine derives, never a user id — the same shape `mark_recent_auth` and the
  MFA store already had, and the reason `bymax-auth-redis` still holds no hashing key.
  `revoke_family` discovered its owner inside the store, so it splits: `find_family_owner` reads
  the record (which carries the `tenant_id` the subject needs) and the revocation takes the
  resulting subject, keeping the deletes and the index prune one atomic step. Index MEMBERS are
  unchanged (`rt:{sha}`, `rp:{sha}` and the platform twins), as is every token-keyed record — only
  the keys that name an account moved.

  Threading the subject made the tenant a parameter on the public surface: `AuthEngine`'s
  `list_user_sessions`, `revoke_user_session`, `revoke_other_user_sessions`,
  `revoke_all_sessions` and `change_password`, and `SessionService`'s `list_sessions`,
  `revoke_session` and `revoke_all_except_current`. The axum routes pass the verified token's own
  `tenant_id`. `TokenManagerService` and `SessionService` now take the identifier key as a
  constructor argument rather than an optional wither: it was optional while it fed only the
  recent-authentication marker, where an absent key fails closed, and a session subject has no
  such fallback.

  **This has no compatibility path, and `@bymax-one/nest-auth` 1.4.4 (2026-08-19) already shipped
  its half.** A backend on the old shape writes `sess:{userId}` while one on the new shape reads
  `sess:{hmac}`: sessions stay alive and unswept, a revoke-all misses them, and an epoch bump on
  one side is invisible to the other. Neither library carries a fallback for the previous
  preimage — deliberately, because a fallback is compatibility weight for a deployment that a
  cutover removes the need for.

  So this is a **cutover, not a rolling upgrade**, in both directions: the two libraries deploy
  together, and neither may run two versions of itself at once. The MFA keyspace is where the
  second half bites hardest rather than the session one — the transition lock that serializes the
  read-modify-write on the recovery-code list is keyed by this same subject, so two pods that
  disagree about the subject take different locks and do not exclude each other at all, and the
  `rcu:` claim can then be spent twice. Drain the old pods before the new ones serve.

  **A live keyspace must be migrated, not dropped**, and nothing here performs it — the
  obligations are the consumer's:

  - The dashboard session index **fans out**: one old `sess:{userId}` becomes N new keys, one per
    tenant that id appears in. Partition its members by reading each member's own `rt:`/`rp:`
    record for that record's `tenantId` — the old index MIXES tenants, so emptying it into a
    single derived index hands one tenant another's live sessions, which is the defect again with
    the migration as its delivery mechanism.
  - **Epochs are copied forward and never backwards**, carrying at least the old value and the
    remaining TTL. An epoch that moves down revalidates every access token the bump it replaces
    had already killed.

  `AuthEngine::session_subject` is public for exactly this: it names the new key, so a migration
  need not re-derive it by hand. The executable spec is `conformance/wire-contract.json` —
  `hmacKeyDerivation` (it carries a test vector), `userSubjectPreimages`,
  `userSubjectDerivedKeys`, `sessionIndexMembers` and `recordEncodings.refreshSession`.

- **The tenant is length-prefixed in the shared user subject.** `dashboard:{tenantId}:{userId}`
  is not injective. Both components may legitimately contain `:` — a tenant id is validated for
  length and control characters only, and a user id is whatever the host's repository assigns — so
  tenant `acme:prod` + user `u1` and tenant `acme` + user `prod:u1` built one preimage. Everything
  derived from it collided, `rcu:` included: the marker that stops one recovery code being spent
  twice, which means one tenant could spend another tenant's code.

  The tenant's UTF-8 **byte** length now precedes it (`dashboard:9:acme:prod:u1` against
  `dashboard:4:acme:prod:u1`). Bytes, not characters: `str::len()` already counts bytes, and the
  symmetric mistake on the TypeScript side is `String.length`, which counts UTF-16 units — the two
  agree on ASCII and derive different keys for the first accented tenant id, a split that surfaces
  only in production and only in some locales. The platform arm takes no prefix and no tenant:
  one component after the plane, nothing to disambiguate.

  `conformance/wire-contract.json` was adopted from nest-auth byte for byte for this (verified
  with `cmp` against their tree, not retyped from a description); `mfaSubject*` became
  `userSubject*` there. The preimage test now asserts the PROPERTY — that the two formerly
  colliding pairs differ, and that a 4-character 6-byte tenant id derives the 6 — rather than the
  literal shape, which a port counting characters would have passed.

  **Breaking, with no compatibility path**, on the same terms as the session-keyspace entry
  above: every key derived from the subject moves, and both libraries must ship it together.

- **The account-status gate is scoped to the token's tenant.** `AuthEngine::assert_user_active`
  resolved the account with `find_by_id(sub, None)` — and `UserRepository` says in as many words
  that `None` is for "internal admin flows where cross-tenant access is intentional". A status
  gate on a request path is not one of those. A repository id is unique only *within* a tenant,
  so with a host whose ids are per-tenant serials the gate could resolve a **different tenant's**
  account and decide on that account's status: admitting a caller whose own account is banned, or
  refusing one who is fine. The verified token carries `tenant_id`, so there was nothing to guess.
  `assert_user_active` now takes the tenant and the `UserStatus` extractor passes it.

- **MFA management now requires a verified address, not just a live token.** `POST /auth/mfa/setup`,
  `/verify-enable`, `/disable` and `/recovery-codes` took `AuthUser` — a valid token and nothing
  else — so an account whose address nobody had proven could enrol, remove or re-roll a second
  factor. Binding a factor to an unproven address binds it, and the recovery path that runs back
  through that same address, to a mailbox that may not be the holder's. They now take a new
  `VerifiedUser` extractor: account status **and** address verification.

  `POST /auth/mfa/challenge` is deliberately **not** gated — it is part of signing in, not of
  managing the factor. `GET /auth/me` is deliberately left on `AuthUser` alone: a pending,
  suspended or unverified client still has to read its own profile to render the "verify your
  email" or "suspended" screen, and `SafeAuthUser` carries `status` and `emailVerified` for
  exactly that. Gating it would leave that client a 403 and nothing to render.

  The verification half is conditional on `email_verification.required`, exactly as the login
  path is: a deployment that does not ask for verification never marks anyone verified, so an
  unconditional gate would make these routes permanently unreachable there.

  `UserStatus` is unchanged and still gates status alone — ws-ticket, password change and the
  session routes keep their current behaviour rather than silently acquiring a second gate.

- **A delivery failure no longer logs the catalogue's subject.** `DefaultAuthEmailProvider`
  reported a failed send with the rendered subject line, and the subject comes from
  `AuthEmailCatalogue` — which is the host's. Putting the code in the subject is an ordinary
  product decision, not a misuse: `"123456 is your verification code"` is what shows in a phone's
  notification preview, and plenty of products write it exactly that way. A host doing something
  entirely reasonable would therefore have had this library copy their OTP or reset token into a
  log pipeline, on a path that is only reachable when something is already going wrong.

  That the email port's contract forbids logging codes did not help, because the code writing the
  line is the library's, not the adapter's — a rule nobody can see being broken is not a control.
  The failure now records a library-owned event name (`password_reset_token`,
  `email_verification_otp`, …) and a generic delivery error, and nothing the catalogue produced.
  The transport's underlying cause stays out too: it is a `Box<dyn Error>` the host's sink built,
  so its text is exactly as unconstrained as the subject was, and a sink formatting "could not
  send to user@example.com" would walk the recipient straight back in. A sink that wants its
  diagnostics recorded is the right place to record them.

  The constant is also the better field to read: it is stable across a reworded subject and
  across locales, so an alert keys off it once, where matching on product copy silently stops
  firing the day the wording changes. Pinned by a test that installs a subscriber, renders a
  catalogue whose subject carries the OTP, and asserts the code never reaches the event.

### Added

- **`DefaultAuthEmailProvider`, the overridable default that fills the email port** so a
  deployment does not hand-write ten methods to send a verification code. It sends through
  `AuthEmailSink`, a one-method delivery port narrow enough that the module depends on no
  concrete mailer, and it ships the security policy each of those hand-written providers would
  otherwise have to get right independently: HTML escaping on a body path that carries
  caller-chosen text (an inviter's display name, a tenant's name, the address an account moved
  to), CR/LF stripping on the subject so that text cannot inject an extra header, the NIST
  SP 800-63B §4.6 notification catalogue, and a swallow-and-log delivery-failure policy so a
  down channel never turns "enable MFA" into a failed request.

  The copy is entirely replaceable — implement `AuthEmailCatalogue` and override any subset of
  its ten renderers, returning `html` for real links and branding. A catalogue chooses words,
  never behaviour: the subject sanitization and the failure policy apply to an override exactly
  as to the default. **Escaping is the one exception, and it is a security boundary.** The
  provider escapes what it renders — a message that leaves `html` unset has its `text` turned
  into escaped paragraphs — but a renderer that RETURNS `html` has that value used verbatim and
  owns the escaping of every dynamic value it interpolates. That is what makes a real `<a>`
  link possible, and it means an override must not trust the provider to escape its markup.

  `DeliveryErrorPolicy::Rethrow` restores the error for the flows that react to one (the
  reset path deletes an undelivered token early rather than leaving it to its TTL; the
  email-change path refuses to record "verification sent"; the invitation path answers
  `500 auth.internal`). It does not turn an outage into a failed user operation elsewhere: the
  MFA and password-changed notices are detached through `spawn_guarded`.

  Mirrors nest-auth's provider of the same name, so the two libraries send the same messages
  from the same events.

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

- **Every `EmailProvider` method now takes the account's `tenant_id` first**, so a multi-tenant
  delivery channel can attribute and route each message rather than guessing from the
  recipient. A cross-tenant platform admin carries no tenant of its own, so MFA notices on that
  plane arrive under the reserved `PLATFORM_EMAIL_TENANT` (`"platform"`) — held byte-identical
  to nest-auth's constant, so one adapter behind both backends sees one name for the admin
  plane rather than two. A deployment that lets tenants choose their own id must keep that one
  out of the space, the same way `pep:`/`ep:` keep the two epoch namespaces apart in Redis.

  **Breaking for a hand-written `EmailProvider`.** Rust will not silently bind the new
  parameter the way a structurally-typed language would, so every implementation fails to
  compile until it is updated — which is the outcome to want here: a provider that kept
  compiling while passing the recipient where the tenant now goes would attribute every
  message to an address. Nothing is published on crates.io or npm yet, so this breaks no
  released consumer.

- **`tenantId` is optional wherever a `TenantIdResolver` can supply it.** A configured resolver
  is authoritative and ignores the body's value — that is the whole anti-spoofing promise — so
  a client under one may now omit the field entirely instead of sending a value the server
  discards. With no resolver configured the body is the only thing that can scope the request,
  and one naming no tenant is refused with `auth.validation` naming the field, rather than
  defaulted: inventing a tenant name would silently gather into one scope every account a
  misconfigured deployment created, and that scope keys the user lookup, the Redis records and
  the HMAC identifiers built from it.

  The engine inputs (`RegisterInput`, `LoginInput`, `ForgotPasswordInput`, `ResetPasswordInput`,
  `VerifyResetOtpInput`, `ResendResetOtpInput`) carry `Option<String>`, and `verify_email`,
  `resend_verification_email` and `oauth_initiate` take `Option<&str>`. The internal reset
  helpers now receive the RESOLVED tenant as an argument rather than reading it back off the
  input struct — with both values in scope, reading the wrong one is a one-character mistake
  that no test would notice, and it is exactly the mistake nest-auth had to fix on this flow.


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

- **The freshness of a re-issued access token is now tested, not just documented.** Both
  `reissue_access_with_authority` and its platform twin promise "a fresh `jti`, window, and
  epoch are issued", and every one of those fields could be dropped from the claim literal —
  inheriting the value from the token being replaced — with the whole suite still green. Only
  the re-stamped authority (`role`, `tenantId`, `mfaEnabled`) was covered, which is how four
  fields on each plane went unasserted at once.

  The three failures are not interchangeable. A re-used `jti` collapses two tokens into one
  revocation identity, so the `rv:{jti}` a logout writes for one silently revokes the other and
  a token minted after a logout is born already blacklisted. An inherited `exp` re-mints the
  session with the ORIGINAL sign-in's window, so a console that has been refreshing for hours
  hands out tokens that are already expired. An inherited `epoch` re-mints below the account's
  current generation, so the token a refresh just issued is refused by the very check the
  refresh exists to satisfy. On the platform plane all three land on the highest-privilege
  identity in the system.

  The tests drive the re-issue from deliberately stale hand-built claims rather than from a
  freshly issued token, because `iat` has one-second resolution: claims minted moments earlier
  in the same test carry the same second, and a window assertion against them holds whether the
  field was replaced or inherited. They also assert the re-issued token *verifies* before
  reading its fields — an inherited `exp` or `epoch` surfaces as an error rather than as a wrong
  value, and unwrapping with a `let-else` that returns would have called that a pass.

- **The logout path's expired-token allowance is now tested.** `verify_access_ignoring_expiry`
  and its platform twin exist for exactly one caller — logout — and the `validate_exp: false`
  that makes them work was unasserted: dropping the field falls back to the validating default
  and nothing went red. An access token that expired while the user was away is the *normal*
  case at logout, and refusing it leaves the refresh session — the long-lived credential logout
  exists to kill — alive for its whole remaining lifetime. The new tests pin both halves: an
  expired token passes this verifier and is refused by the ordinary one, and a tampered
  signature is still refused, so "ignoring expiry" has not quietly become "ignoring
  verification".

  Behaviour is unchanged; what changed is that a regression in any of it now fails the suite.
  Found by a `cargo-mutants` sweep: ten surviving mutants across the two claim literals and the
  two verifiers, all ten killed by these four tests.

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

### Added

- **A release pipeline for both halves of this library** (`.github/workflows/release.yml`).
  One `v*.*.*` tag publishes the eight crates to crates.io and `@bymax-one/rust-auth`
  to npm — they are one product, the npm package speaks the wire contract the crates
  implement, so they carry one version and ship together.

  Both registries authenticate by OIDC trusted publishing: crates.io through
  `rust-lang/crates-io-auth-action`, npm through `npm publish --provenance`. No
  long-lived registry token exists in this repository. Both, however, can only add a
  trusted publisher to something that already exists, so the **first** publish of each
  crate and of the npm package is a manual one from a maintainer's machine; every
  release after that runs here.

  The publish is ordered `verify → crates → npm → GitHub Release`. `verify` runs
  `cargo publish --workspace --dry-run`, which packages each crate and rebuilds it
  from the resulting tarball — the only check that sees what the registry will see,
  rather than what the working tree happens to contain. `--workspace` also settles the
  publish order from the dependency graph instead of a hand-maintained list.

- **`scripts/check-release-versions.sh`**, run by CI on every pull request and again
  at tag time. The workspace pins its own crates exactly (`=x.y.z`), so a single stale
  pin publishes a crate that cannot resolve its sibling — and the correction would
  have to be a new version, since crates.io and npm are both append-only. The script
  holds the workspace version, every publishable crate, every internal pin and the npm
  package to one number, and to the tag being cut.

### Changed

- **The crate version is declared once, in `[workspace.package]`**, and inherited by
  all eight crates. A release moves that line and the pins beside it, rather than
  eight manifests that could disagree.

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
