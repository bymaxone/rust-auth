# Phase 13 — Workspace parity with `nest-auth`: plan

> **Status**: 🔄 In progress · **Progress**: 0 / 12 slices · **Last updated**: 2026-11-11
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) (this phase is not in its dashboard)
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

This is the plan for the workspace feature set as the published contract states it. It contains no code; each slice is its own reviewed pull request.

---

## Entry gate

Met: `@bymax-one/nest-auth` has published the release that carries its workspace feature set, and the project owner has authorised the work. The files below are the ones this phase takes, in one pass, from that release (`conformance/` at the release tag, read through the contents API and base64-decoded, never the raw media type, which rewrites JSON escapes):

| File | sha256 |
|---|---|
| `wire-contract.json` (contract version 3) | `33f571f3e86ebcf14ee1dcdce4a6a50a6e430d9be968e883453a4d32d94f3a78` |
| `openapi-operation-security.json` | `41aa87e8ff48c9f417ce2839cdcf86da2cc5f025d3d18aba987437489e004d3a` |
| `openapi-request-schemas.json` | `90b2fd7ae9da0634881c193e0dd36ee31ff7b17aa5af83827b3da50b1b34741c` |
| `openapi-request-descriptions.json` | `81b6e5aaced9e463dbd61b928dca1b59dbe1b669d4402b3fc9b27e237f476c07` |
| `openapi-declared-structures.json` | `78218849b5d1aea392e54fc0b8722e76444d86db9600cb3d77848f0aa3296fd5` |

Nothing is copied before slice 13.0 lands. Until then the files under `conformance/` stay at the version the repository holds, and the tests that assert against them keep passing.

---

## Context

The shared files are the authority. `conformance/wire-contract.json` is held byte-identical with `nest-auth`, with the sha256 pinned in this repository, and so are the four OpenAPI artefacts. Workspaces add, to those files:

- sections of the wire contract: `workspaceMembershipCache`, `workspaceInvitations` (with key vectors), `workspaceScopedName` (with vectors), `workspaceRealtime` (the access decision on every surface, the live job check, `access.denied` and its vectors), `passwordResetOrder`, `refreshTokenInput`;
- changes to `errorCatalog` (nine codes), `errorEnvelope`, `identifierPreimages`, `userSubjectDerivedKeys`, `rateLimits` (nineteen limits), `redisKeyPrefixes` (nine prefixes), `requestEncoding` (eleven strict routes and three when-body routes), `requestFieldBounds` (`pageLimit`, `workspaceName`, `memberUserId`, `pathParameters`) and `recordEncodings` (the OAuth state record gains an optional `workspaceInvitation`);
- operations in the operation-security table (38 become 57), DTOs in the request schemas (22 become 35, and the OAuth initiate query gains `workspaceInvitation`), and descriptions of two more email-normalising DTOs.

Because every one of those lists is compared with this repository's own tables in **both directions**, copying the files makes the comparing tests fail until the matching code exists. That is the purpose of the tests, and it decides the shape of this plan: slice 13.0 makes the failure visible and tracked instead of blocking, and each later slice removes entries from the tracked list.

---

## Rules-of-phase

1. **One slice, one reviewed pull request,** merged on the fail-closed thread gate. No slice depends on the next one being merged.
2. **Red first.** Each behaviour is a test that fails against the previous main and passes after, and the failing output is recorded in the review context.
3. **The contract moves in both repositories or not at all.** Only slice 13.0 touches a shared file, and only to copy it. A difference found while implementing is reported as a contract change request and fixed in `nest-auth`, then copied.
4. **Tracked, not silent.** A thing the contract requires that this repository has not built yet is listed in a `PENDING` table of the test that compares it, with the reason. The test requires each pending entry to still be missing, so a slice that builds it must remove the entry, and a gap that is not listed fails the build.
5. **Gates per slice:** `cargo fmt`, `clippy -D warnings`, `rustdoc -D warnings`, `llvm-cov` at 100% lines and functions over the whole workspace, `cargo mutants --in-diff`, and the bounded Claude + Codex review.
6. **Wire behaviour is probed against a real router and a real Redis,** not read off the code. The probes the OpenAPI work built (operation matrix, declared structures, structural failure names, OTP answers) are reused and extended, not rewritten.
7. **No new direct dependency** without a vet entry and a justification in the slice's pull request.
8. **Everything is English,** timeless comments, no history in code.

---

## Reference docs

- `conformance/wire-contract.json`, `conformance/openapi-*.json` — the contract, read in full at the gate.
- [`docs/technical_specification.md`](../technical_specification.md) — § 6 (repositories), § 8.4.1–8.4.4 (validation, refresh body, OpenAPI), § 12 (Redis keyspace and scripts), § 8.6 (errors), § 19.6 (dependency policy).
- The F9 test modules this plan reuses: `tests/adapter/openapi_operation_security.rs`, `tests/adapter/openapi_declared_structures.rs`, `tests/adapter/structural_failure_names.rs`, `tests/adapter/otp_failure_answers.rs`, `src/structure_tests.rs`, `src/dto/description_parity_tests.rs`.

---

## Task index

| ID | Slice | Status | Depends on |
|---|---|---|---|
| 13.0 | Copy the contract; track what is not built | 📋 ToDo | entry gate |
| 13.1 | Error codes, statuses and wire envelope | 📋 ToDo | 13.0 |
| 13.2 | Keys, preimages, rate limits, encoding, bounds, scoped names (data only) | 📋 ToDo | 13.0 |
| 13.3 | Domain model and repository traits | 📋 ToDo | 13.1 |
| 13.4 | Membership cache store and its scripts | 📋 ToDo | 13.2, 13.3 |
| 13.5a | Workspace reads: list, access, members, switch, and the guard | 📋 ToDo | 13.1, 13.3, 13.4 |
| 13.5b | Workspace mutations: create, rename, deletion lifecycle, role, remove, leave, transfer | 📋 ToDo | 13.5a |
| 13.6 | Invitations core: invite, resend, revoke, list, preview | 📋 ToDo | 13.2, 13.3, 13.5a |
| 13.7 | Acceptance family and bootstrap invitations | 📋 ToDo | 13.5b, 13.6 |
| 13.8 | OAuth invitation, invitation-only registration, the OAuth MFA branch | 📋 ToDo | 13.7 |
| 13.9 | Realtime surfaces: verifier, sockets, job check, `access.denied` and its limiter | 📋 ToDo | 13.5a |
| 13.10 | OpenAPI surface, client, npm types and documentation | 📋 ToDo | 13.5b, 13.7, 13.8, 13.9 |

---

## Slice 13.0 — copy the contract and track what is not built

**Contract surface:** the five shared files, copied byte-identical, and their sha256 pins.

**Work.** Copy the files into `conformance/` and, for the OpenAPI ones, into `crates/bymax-auth-axum/openapi/`. Move each digest pin. Introduce the `PENDING` table in every test that compares a contract list with a table in this repository, listing exactly what the new files add and this repository lacks.

**Tests that fail on purpose at copy, each turned into a tracked entry:**

| Comparison | What fails | Where |
|---|---|---|
| Digest pins of the wire contract and each artefact | the bytes changed | the pin tests of each artefact |
| Rate-limit table against `rateLimits` | new named limits | the rate-limit contract test in `bymax-auth-axum/src/rate_limit.rs` |
| Error catalog and statuses against `errorCatalog` | new codes | `bymax-auth-types/tests/error_catalog.rs` |
| Redis key prefixes against `redisKeyPrefixes` | new prefixes | the key tests in `bymax-auth-redis/src/keys.rs` |
| Exempt lists against `requestEncoding` | new strict and when-body routes | `encoding_policy` tests |
| Operation table against `openapi-operation-security.json` | new operations | `openapi_operations_tests.rs` |
| Declared DTO table, request schemas, descriptions inventory | new DTOs | `structure_tests.rs`, `dto/description_parity_tests.rs`, `dto/openapi_parity_tests.rs` |
| Vectors of `workspaceMembershipCache`, `workspaceInvitations` | no test reads them yet | new, in slices 13.2 and 13.4 |

**Gate:** main stays green because the pending lists are exactly the difference. A pending entry that has been built, or a missing one that is not listed, fails.

---

## Slice 13.1 — error codes, statuses and the wire envelope

**Contract surface:** `errorCatalog` (codes, statuses, `internalOnly`), `errorEnvelope`.

**Work.** Add the nine workspace codes to `AuthErrorCode` and `AuthError` with the statuses the contract pins, fixed client messages, and the TypeScript export. The enums are `#[non_exhaustive]`, so this is not a source break. A code the contract marks internal-only goes through `to_wire` like the existing sentinels. The structural-failure naming already follows the envelope rule (the set of distinct fields is normative; message text and entry count are not).

**Probes reused:** `every_code_answers_the_wire_status_the_contract_pins`, `the_catalog_names_exactly_the_codes_the_shared_contract_does`, the wire-status assertion of every code.

**Open at the gate:** which of the new codes are reachable from a route that already exists. If any is, that route's behaviour changes in this slice.

---

## Slice 13.2 — keys, preimages, rate limits, encoding and bounds

**Contract surface:** `identifierPreimages` (`wsp:`, `wms:`, `wie:`, `wir:`, the length-prefixed preimages in UTF-8 bytes), `redisKeyPrefixes` (`wsv`, `wmv`, `wm`, `winv`, `winvidx`, `winvset`, `winvrl`), `rateLimits`, `requestEncoding`, `requestFieldBounds`.

**Work.** Pure derivations and tables, no I/O:

- the workspace and membership subjects and the invitation-email and inviter-rate subjects, each HMAC-ed with the identifier key of `hmacKeyDerivation`, and the key builders for every prefix;
- the named rate limits in the same `requests/windowSeconds` form, with defaults;
- the strict and when-body route lists, including the first `PATCH` route;
- the bound tables: workspace name (counted on the value as submitted, stored trimmed, blank after trim refused), member user id, page limit and cursor, path parameters;
- the `workspaceScopedName` builder and its vectors (length-prefixed in UTF-8 bytes, refusals for controls and unpaired surrogates), and the optional `workspaceInvitation` field of the OAuth state record.

**Probes and vectors reused:** the contract's vectors are read from the file, never restated: the membership vectors and the invitation key and inviter-rate vectors. They were recomputed independently with a second implementation during the contract reviews and all reproduced, including the multibyte and the delimiter-in-identifier cases. The test asserts **set equality** with each vector section, so a vector added later fails until it is derived.

**Parsing rules to implement exactly:**

- `limit` is received as a string and checked against the artefact pattern `^(?:[1-9][0-9]?|100)$`; an integer parse would accept `05` and `+5`. A value outside 1 to 100, a leading zero, or a present-but-empty `limit=` is refused as `auth.validation` naming `limit` and is never clamped. The default is 50 when absent.
- `cursor` is 1 to 512 code points with no control character (C0, DEL, C1) and carries no tenant or workspace.

---

## Slice 13.3 — domain model and repository traits

**Contract surface:** `workspaceMembershipCache` (what an active membership of an active workspace is), `workspaceInvitations` (`rules`), the operation semantics for ownership.

**Work.** The workspace and membership types, the role hierarchy, the workspace status machine (active, scheduled for deletion, restored, deleted), and the repository traits with in-memory doubles in `testing/`.

**Trait additions and their doc requirements.** The contract files carry rules but no trait shapes, so the shapes are taken from the published `nest-auth` ports at the gate. What must be stated in rustdoc, because a wrong implementation is silent:

- **Primary or read-your-writes.** The repository reads the cache is filled from must come from the primary or be read-your-writes. A lagging replica would cache a removed member as present under the new version.
- **Tenant scoping.** Every method takes the tenant, and an implementation must restrict the read and the write to it. A user id is unique only within a tenant.
- **Atomic ownership rules.** The last owner of a workspace cannot leave, be removed or be demoted, and the check and the change are one atomic operation in the repository, not a read followed by a write. The same holds for the transfer of ownership.
- **Compare-and-set on change.** A role change and a removal are conditional on the role the actor read (`expectedRole`) and on the actor's own standing, so two concurrent actors cannot both succeed against a stale view.
- **Owned-workspace counting** for the per-user workspace limit, and the pending-deletion state it must report.
- **Time bounds.** Calls the engine makes while holding a short lock must stay well under it, as `update_mfa` already documents.

**Tests:** the in-memory doubles honour the same rules (tenant restriction, atomicity, compare-and-set) and have their own tests, so a host's implementation is held to a stated contract.

---

## Slice 13.4 — membership cache store and its scripts

**Contract surface:** `workspaceMembershipCache` in full: the three keys, the read order, the fill and bump rules, the retention, the TTL option, the entry rule, and the scenarios (including counter loss and absent counters).

**Work.** A `MembershipCacheStore` trait with a Redis implementation and an in-memory one.

**Read.** Separate single-key commands in the order `wsv`, `wmv`, then the entry named by those two values; on a miss the repositories; the entry is written under the versions read first. No script is needed for the read, and a read never creates a counter.

**Scripts** (every key declared in `KEYS`, as the existing scripts do):

| Script | Keys | Rule |
|---|---|---|
| Fill | the two counters and the entry | write only if both counters still hold the versions read (an absent counter counts as 0), and in the same step extend every counter that exists to the retention; a counter that does not exist is left absent; a fill that finds a counter moved writes nothing |
| Bump | one counter | `INCR` then `EXPIRE` to the retention, atomically, on every bump; a failed bump is an error and the change is never reported as invalidated |

**Rules enforced in code:** the writer changes the repository first and bumps after; only an active membership of an active workspace is cached, and an entry whose status is not `active` reads as a miss; a TTL of 0 disables the cache; the cache is advisory, so an unreachable Redis answers from the repositories and writes nothing.

**Probes reused:** the contract's scenarios run against the in-memory store and against a real Redis, by the same table, so the two implementations cannot drift. The entry for an exhausted memory-pressure counter (a counter evicted restarts at 0) is documented as an operational requirement (no-eviction policy for the auth keyspace), not tested.

---

## Slice 13.5a — workspace reads and the guard

**Contract surface:** the read operations of the operation-security table (list, access, members, switch), their DTOs (`WorkspacePageQueryDto`, `MemberRouteParamsDto`), `workspaceRealtime.rules.accessDecision` and `workspaceIdField`, `requestEncoding`, `requestFieldBounds`, `rateLimits`, `errorCatalog`.

**Work.** The workspace guard and permission check, the access decision, the read services and their routes behind a new flag of `RouteGroups`.

**Behaviour the contract fixes and the slice must probe:**

- **The access decision, in one fixed order.** Not an active member of an active workspace, and any non-owner of a workspace pending deletion, answer the IDENTICAL `404 auth.workspace_not_found`, decided from the rows already read. The owner of a workspace pending deletion answers `409 auth.workspace_pending_deletion` unless the surface admits pending workspaces, in which case only that owner is admitted. Then the role is judged through the hierarchy (`403 auth.insufficient_workspace_role`). A surface never tells a non-owner more than the route does.
- **Path parameters.** A parameter over 128 code points, blank, or carrying a control character answers `400 auth.validation` naming the parameter, **ahead of authorization**; the workspace guard runs first, so when both `workspaceId` and another parameter are bad only `workspaceId` is reported. A well-formed id that names nothing answers the identical 404. "Blank" uses the JavaScript whitespace set, as `not_blank` does. A literal route such as `workspaces/invitations/preview` coexists with `workspaces/{workspaceId}/…` because static segments win; a workspace whose id is `invitations` is unreachable under that prefix, which the documentation states.
- **Membership status.** Every path that reads a membership decides its status explicitly, and only an ACTIVE membership of an ACTIVE workspace grants anything; the cache fills and reads back only an active membership.
- **List routes.** `limit` and `cursor` as in 13.2; the tenant and the workspace of a list always come from the credential and the route.
- **Structural failures.** The new DTOs are added to `dto::DECLARED` with their schema names, so a missing or wrong-typed property names the property.

**Probes reused:** the operation matrix (each operation × each delivery mode × nine credential and transport combinations, with an oracle written from what each kind means) extends to the new operations without a new oracle; the structural-failure table extends to the new DTOs by construction.

---

## Slice 13.5b — workspace mutations

**Contract surface:** the mutating operations (create, rename, schedule deletion, restore, change role, remove, leave, transfer ownership), their DTOs, `workspaceName`, `memberUserId`, `rules.membershipStatus`, `rules.bootstrapCreate` (the create path shared with bootstrap), the workspace hooks.

**Work.** The lifecycle services, the routes, and the hooks, including the workspace-create cap (`workspaces.maxWorkspacesPerUser`, counted as the workspaces the account owns with the owner role), the host's `beforeWorkspaceCreate`, and the self-serve switch `allowCreate`.

**Behaviour the contract fixes and the slice must probe:**

- **Workspace name.** The bound (1 to 120 code points) and the control-character rule apply to the value as submitted; the stored value is trimmed; blank after trimming is refused as `auth.validation` naming `name`.
- **Ownership.** The last owner cannot leave, be removed or be demoted, as one atomic repository operation. The receiver of an ownership hand-over must be ACTIVE (`400 auth.validation` naming `userId`), checked before the giver's password is looked at and again by the repository's write.
- **Role changes and removals** act only on an ACTIVE member; a suspended one answers `404 auth.workspace_not_found`. Both are conditional on the role the actor read.
- **Refusals** use the catalog codes: `auth.last_owner`, `auth.workspace_limit_reached`, `auth.insufficient_workspace_role`, and a `403 auth.forbidden` with a detail for a host-hook refusal.

---

## Slice 13.6 — invitations core

**Contract surface:** `workspaceInvitations` (`record`, `keys`, `fullKeyVectors`, `inviterRateVectors`, `rules`), the invite, resend, revoke, list and preview operations and their DTOs, `rateLimits`.

**Work.** The invitation store (record, index, pending set, inviter counter), the services and the routes.

**Scripts:**

| Script | Rule |
|---|---|
| Publish (invite, resend, or a second invitation of the same address) | ONE atomic step, with no separate claim: it takes the record key the writer read from the index (none for a first invitation) and writes only while the index still holds it, then writes the record, points the index at it, adds the record key to the set, deletes the record it replaces and that record's place in the set, and sets the TTLs. A writer that read a stale index writes nothing and answers `429 auth.too_many_requests` |
| Pending cap | in the same step: a first invitation at the cap writes nothing; replacing a LIVE record skips the cap because the set does not grow; an index naming a GONE record counts as a first invitation, with `resendCount` 0 and no cooldown, because the dead entry is dropped before the cap is counted |
| Revoke | removes the record, the index entry and the set member in one step; an address with no live invitation, or one the actor may not act on, answers 204 and changes nothing |
| Inviter counter | `INCR` with `EXPIRE` on the first increment only, one atomic step; 20 per inviter per hour |

**Behaviour to probe:** the role ceiling (the owner invites to any role; every other role invites only to a role strictly below its own); an address that has a membership in ANY status is refused with `409 auth.already_member`; invite, resend and revoke answer 204 with no body whether or not the address has an account, and the email provider is told `accountExists`; the 60 s cooldown and the limit of 5 resends apply to a second invitation as to a resend; the preview needs no credential, takes a token of exactly 64 characters, and answers a union on `kind` (`member` carries `inviterName`, `bootstrap` has none), with one `400 auth.invalid_invitation_token` for every failure cause and the same repository reads in each; a delivery failure is re-thrown without the failing text, which may quote the token.

**Probes reused:** the indistinguishability harness of the declared-structures test (registered against unknown address: identical status and payload) extends to the invitation answers.

---

## Slice 13.7 — acceptance family and bootstrap invitations

**Contract surface:** `rules.accept`, `acceptOrder`, `acceptSignup`, `bootstrap`, `bootstrapCreate`, `acceptLimits`, `afterAcceptedHook`, the accept and accept-signup operations and DTOs, the hook event.

**Work.** Accept (a signed-in caller), accept-signup (no credential), host-issued bootstrap invitations (a service call with no route, and a second call that withdraws one by workspace id), and the hooks.

**Behaviour the contract fixes and the slice must probe:**

- **Accept order, without spending the token:** the token names a record of a known role in the caller's tenant (else `400 auth.invalid_invitation_token`); the caller's address equals the record's, compared in lowercase (else `403 auth.invitation_email_mismatch`); that address is verified (else `403 auth.email_not_verified`); the workspace is active and the inviter exists; then the membership is written and the record spent. The answer is `200 {workspaceId, role}` where `role` is the role the caller ACTUALLY holds afterwards.
- **Spend semantics.** Spending deletes the token's own record key always, and the index and the set entry only while they still name that key; a revoke or a resend that lands between the write and the spend cannot undo the acceptance. A failure before the write leaves the invitation usable; a failure after it retries into `already_member`, which counts as success. The hook event carries `lostConsumeRace: true` only when the spend found the index no longer naming the record.
- **Accept-signup:** the record, the inviter and workspace checks, an existing account for the address (`409 auth.email_already_exists`), then the password policy and breach screen, then the account is created with a verified address, the membership is written, the record is spent, and the session is issued as a sign-in does. A refused password spends nothing.
- **Bootstrap:** accepting creates the workspace and the owner membership in one repository call, applying the owner cap and the create hook (never `allowCreate`), then spends the record; a retry that finds the workspace created with this caller as its active owner is success.
- **The after-accepted hook** runs only when an acceptance CREATED the account, is detached, and a failing hook is logged without its message.
- **Limits:** 10 per minute per IP for accept, 5 for accept-signup.

---

## Slice 13.8 — OAuth invitation and invitation-only registration

**Contract surface:** `rules.oauthAccept`, `oauthAcceptMfa`, `registration`, `recordEncodings.oauthState`, the OAuth initiate query with `workspaceInvitation`.

**Work.** `GET oauth/{provider}?workspaceInvitation=<token>` (the token is exactly 64 characters, `Referrer-Policy: no-referrer` on the start response, `400 auth.invalid_invitation_token` when workspaces are not enabled); the optional `workspaceInvitation` field of the state record, the SHA-256 of the token and never the token; the callback checks, before the host's `onOAuthLogin` hook runs; the MFA branch; and the `registration` option.

**Behaviour to probe:** an account with a second factor receives the MFA challenge exactly as any OAuth sign-in does, and the invitation is neither completed nor spent; `registration: 'invitation-only'` makes `POST register` answer `403 auth.registration_closed` before anything else is read, and the OAuth `create` action answers it unless the flow carries an invitation that passed the callback checks; sign-in, linking and every accept route are unaffected; startup refuses the mode when workspaces and invitations are both off, naming both. A state record carrying `workspaceInvitation` as anything but 64 lowercase hex characters is refused as corrupt.

---

## Slice 13.9 — realtime surfaces

**Contract surface:** `workspaceRealtime` in full (`accessDecision`, `workspaceIdField`, `verifierWorkspace`, `socketMessage`, `jobAuthorization`, `accessDeniedEvents`, `accessDeniedVectors`), `redisKeyPrefixes` (`wad`, `wads`), `userSubjectDerivedKeys`, the `workspaces.accessDeniedEvents` options.

**Work.**

- **The verifier.** An optional `workspace {workspaceId, roles, allowPending}` on the access verifier that, on the dashboard plane, returns the caller's membership beside the verified payload, resolved through the same versioned access cache as the routes and judged by the access decision after the identity checks. On the platform plane, or with workspaces disabled, the option is a programmer error and not an auth failure.
- **Sockets.** A message is admitted to the workspace it names, from its body only (never the URL, a header, the handshake or the ticket), judged again on every message, with the membership kept with the message and not on the connection. A message that is not an object answers `400 auth.validation` naming `workspaceId`; a handler declaring no roles is refused `403 auth.forbidden` before anything is looked up.
- **The live job check.** A queued job carries `{tenantId, workspaceId, actorUserId}`; before any side effect the check reads the account, the workspace and the membership from the repositories on the primary (never from the access or status cache), the account first, then the access decision. It does not emit `access.denied`.
- **`access.denied` and its limiter.** The event, its `surface` and `reason` mapping, and the per-account budget: a fixed-window counter `wad:{digest}` and a suppressed counter `wads:{digest}` (24 h), each incremented by one atomic script that sets the expiry on the creating increment, with the suppressed count read and deleted in one atomic step (`GETDEL`). The options `max` and `window_seconds` (defaults 10 and 60, bounds 1 to 10000 and 1 to 3600) with the startup errors the contract pins; when the counter store fails nothing is emitted, one warning per window per process says so, and the access decision is unchanged.

**Vectors:** the `accessDeniedVectors` and the `fullKeyVectors` are read from the pinned contract in the test and reproduced byte for byte, never typed into Rust.

---

## Slice 13.10 — OpenAPI surface, client, npm types and documentation

**Work.**

- `request_schemas`, `operation_security`, `describe_operation` and the descriptions and structures accessors serve the new files; the request-body schemas for the refresh and logout bodies carry the artefact's bounds; the declared-DTO table covers all 35 schemas.
- `workspaceScopedName` is exposed to hosts: a public helper that builds the length-prefixed name for rooms, keys and prefixes, with the contract's refusals (a C0 control or DEL, an unpaired surrogate, an empty tenant or workspace), and a test that reproduces the contract's vectors from the pinned file.
- The Rust client crate and the npm package types gain the workspace methods and types; the `ts-rs` export is regenerated.
- The specification (§ 6, § 8, § 12), the CHANGELOG (the breaking behaviour entries for every change to an existing route) and the migration notes (a shared Redis keyspace gains prefixes; a deployment running both libraries needs both on the same contract) are written.

---

## Definition of done for the phase

- Every `PENDING` table is empty and has been deleted from the tests, or each remaining entry names a published reason.
- The contract files in the repository are byte-identical with the published release, with pins that match.
- The probes of every slice pass against a real router and a real Redis.
- The CHANGELOG states every behaviour change, and each shared-contract change is recorded as made in both repositories.

---

## Risks and open questions

1. **Multi-key scripts and Redis Cluster.** The fill and invite scripts touch several keys, so whether they support Redis Cluster is decided in their slice and stated in the specification.
2. **Trait shapes are outside the contract files.** Slice 13.3 takes them from the published ports and must reconcile any difference with a contract change request.
3. **`type_name` keys the declared-DTO table.** A format change in the compiler would fail safe (the old container entry), and a test requires every DTO to be found; a new DTO must be added to the table in the slice that adds it.
4. **Character counting.** Lengths on text a user submits count code points everywhere; store-key and storage bounds may count bytes by design. New bounds follow the same rule and get an astral boundary test.
5. **Dependency budget.** No new crate is expected. If one is needed (a cursor encoding, for instance), it needs a vet entry, and the dependency-budget job is re-measured.
