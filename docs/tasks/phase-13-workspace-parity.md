# Phase 13 — Workspace parity with `nest-auth`: plan

> **Status**: ⛔ Blocked (entry gate below) · **Progress**: 0 / 9 slices · **Last updated**: 2026-11-09
> **Source roadmap**: [`docs/development_plan.md`](../development_plan.md) (this phase is not in its dashboard until the work is authorised)
> **Source spec**: [`docs/technical_specification.md`](../technical_specification.md)

This is a plan. It contains no code and authorises none. It exists so that, when the entry gate opens, the work starts from a measured list and not from memory.

---

## Entry gate

Implementation starts only when `@bymax-one/nest-auth` has published the release that carries its workspace feature set, and the project owner has authorised the work. Until then, `nest-auth` still adds to the shared contract, so code written now would chase a moving target. Every list below is therefore **re-derived from the published contract files at that point**; the lists here are what the contract reviews found in the files named in each slice, and they will have grown.

Nothing in this phase is copied into the repository before the gate: the files under `conformance/` stay at the version the repository holds, and the tests that assert against them keep passing.

---

## Context

The shared files are the authority. `conformance/wire-contract.json` is held byte-identical with `nest-auth`, with the sha256 pinned in this repository, and so are the OpenAPI artefacts (`openapi-request-schemas.json`, `openapi-operation-security.json`, `openapi-request-descriptions.json`, `openapi-declared-structures.json`). Workspaces add, to those files:

- sections of the wire contract: `workspaceMembershipCache` and `workspaceInvitations` (with key vectors), `passwordResetOrder`, `refreshTokenInput`; and additions to `errorCatalog`, `errorEnvelope`, `identifierPreimages`, `rateLimits`, `redisKeyPrefixes`, `requestEncoding` and `requestFieldBounds` (`pageLimit`, `workspaceName`, `memberUserId`, `pathParameters`);
- operations in the operation-security table, DTOs in the request schemas, and descriptions of two more email-normalising DTOs.

Because every one of those lists is compared with this repository's own tables in **both directions**, copying the files makes the comparing tests fail until the matching code exists. That is the purpose of the tests, and it decides the shape of this plan: slice 0 makes the failure visible and tracked instead of blocking, and each later slice removes entries from the tracked list.

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
| 13.2 | Keys, preimages, rate limits, encoding and bounds (data only) | 📋 ToDo | 13.0 |
| 13.3 | Domain model and repository traits | 📋 ToDo | 13.1 |
| 13.4 | Membership cache store and its scripts | 📋 ToDo | 13.2, 13.3 |
| 13.5 | Workspace services, guard and routes | 📋 ToDo | 13.1, 13.3, 13.4 |
| 13.6 | Invitations: store, scripts and routes | 📋 ToDo | 13.2, 13.3, 13.5 |
| 13.7 | Whatever the release adds after the lifecycle and invitations | 📋 ToDo | the published contract |
| 13.8 | OpenAPI surface, client, npm types and documentation | 📋 ToDo | 13.5, 13.6 |

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

**Work.** Add the workspace codes to `AuthErrorCode` and `AuthError` with the statuses the contract pins, fixed client messages, and the TypeScript export. The enums are `#[non_exhaustive]`, so this is not a source break. A code the contract marks internal-only goes through `to_wire` like the existing sentinels. The structural-failure naming already follows the envelope rule (the set of distinct fields is normative; message text and entry count are not).

**Probes reused:** `every_code_answers_the_wire_status_the_contract_pins`, `the_catalog_names_exactly_the_codes_the_shared_contract_does`, the wire-status assertion of every code.

**Open at the gate:** which of the new codes are reachable from a route that already exists. If any is, that route's behaviour changes in this slice.

---

## Slice 13.2 — keys, preimages, rate limits, encoding and bounds

**Contract surface:** `identifierPreimages` (`wsp:`, `wms:`, `wie:`, `wir:`, the length-prefixed preimages in UTF-8 bytes), `redisKeyPrefixes` (`wsv`, `wmv`, `wm`, `winv`, `winvidx`, `winvset`, `winvrl`), `rateLimits`, `requestEncoding`, `requestFieldBounds`.

**Work.** Pure derivations and tables, no I/O:

- the workspace and membership subjects and the invitation-email and inviter-rate subjects, each HMAC-ed with the identifier key of `hmacKeyDerivation`, and the key builders for every prefix;
- the named rate limits in the same `requests/windowSeconds` form, with defaults;
- the strict and when-body route lists, including the first `PATCH` route;
- the bound tables: workspace name (counted on the value as submitted, stored trimmed, blank after trim refused), member user id, page limit and cursor, path parameters.

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

## Slice 13.5 — workspace services, guard and routes

**Contract surface:** the workspace operations of the operation-security table, the request schemas and descriptions of their DTOs, `requestEncoding`, `requestFieldBounds`, `rateLimits`, `errorCatalog`.

**Work.** The lifecycle services (create, rename, schedule deletion, restore, list, access, members, switch, change role, remove, leave, transfer ownership), the workspace guard and permission check, the workspace hooks, and the routes in a new `RouteGroup`.

**Behaviour the contract fixes and the slice must probe:**

- **Path parameters.** A parameter over 128 code points, blank, or carrying a control character answers `400 auth.validation` naming the parameter, **ahead of authorization**. The workspace guard runs first, so when both `workspaceId` and another parameter are bad only `workspaceId` is reported. A well-formed parameter that names nothing, or a workspace the caller may not see, answers the identical `404 auth.workspace_not_found`, with the same repository reads in each case. "Blank" uses the JavaScript whitespace set, as `not_blank` does. A literal route such as `workspaces/invitations/preview` coexists with `workspaces/{workspaceId}/…` because static segments win; a workspace whose id is `invitations` is unreachable under that prefix, which the documentation states.
- **Workspace name.** Length and control characters are checked on the value as submitted; the stored value is trimmed; blank after trimming is refused as `auth.validation` naming `name`.
- **List routes.** `limit` and `cursor` as above; the tenant and the workspace of a list always come from the credential and the route.
- **Authorization.** Every operation is `access`; the role ceiling and the last-owner rules are enforced in the service through the repository's atomic operations.
- **Structural failures.** The new DTOs are added to `dto::DECLARED` with their schema names, so a missing or wrong-typed property names the property.

**Probes reused:** the operation matrix (each operation × each delivery mode × nine credential and transport combinations, with an oracle written from what each kind means) extends to the new operations without a new oracle; the structural-failure table extends to the new DTOs by construction (an empty body names exactly the required set).

**Set equality that moves here:** the operation table, the DTO table, the descriptions inventory (two more email-normalising DTOs), the encoding lists, the rate limits.

---

## Slice 13.6 — invitations

**Contract surface:** `workspaceInvitations` (`record`, `keys`, `fullKeyVectors`, `inviterRateVectors`, `rules`), the invitation operations and DTOs, `rateLimits`.

**Work.** The invitation store (record, index, pending set, inviter counter), the services and the routes.

**Scripts:**

| Script | Rule |
|---|---|
| Invite | in **one step**: list and prune the pending set (a member whose record is gone is dropped), refuse when the pending cap (`workspaces.maxPendingInvitationsPerWorkspace`) is reached, set the index by compare-and-set against the key the writer read, write the record, add it to the set, and set the TTLs. The index is claimed before the record is written, so a crash leaves an index naming nothing, which reads as no invitation. A lost compare-and-set is `429 auth.too_many_requests` |
| Replace (resend, or a second invitation of the same address) | mints a new token, takes the role of the new request, retires the old record, in one step; the cooldown (60 s) and the resend limit (5) apply to both |
| Revoke | removes the record, the index entry and the set member in one step; an address with no live invitation, or one the actor may not act on, answers 204 and changes nothing |
| Inviter counter | `INCR` with `EXPIRE` on the first increment only, so the hour runs from the first invitation; 20 per inviter per hour |

**Behaviour to probe:** the role ceiling (the owner invites to any role; every other role invites only to a role strictly below its own); an active member is refused with `409 auth.already_member`; invite, resend and revoke answer 204 with no body whether or not the address has an account, and the email provider is told `accountExists`; the preview needs no credential, takes a token of exactly 64 characters, and answers one `400 auth.invalid_invitation_token` for a token that never existed, expired, was withdrawn or consumed, or whose workspace is not active or whose inviter is gone, with the same repository reads in each case; a delivery failure is re-thrown without the failing text, which may quote the token.

**Probes reused:** the indistinguishability harness of the declared-structures test (registered against unknown address: identical status and payload) extends to the invitation answers; the preview uses the same comparison across its failure causes.

---

## Slice 13.7 — what the release adds after this

The accept route, the OAuth invitation path and invite-only registration (the codes `registration_closed` and `invitation_email_mismatch` are in the catalog) are planned only after the contract that carries them is published. This slice is a placeholder: its contract surface, probes and gates are written when its files exist, in the same format as the slices above.

---

## Slice 13.8 — OpenAPI surface, client, npm types and documentation

**Work.**

- `request_schemas`, `operation_security`, `describe_operation` and the descriptions and structures accessors serve the new files.
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

1. **The contract is still growing.** Any list above can gain entries before the gate; slice 13.0 absorbs that, because it copies whatever is published.
2. **Multi-key scripts and Redis Cluster.** The fill and invite scripts touch several keys, so whether they support Redis Cluster is decided in their slice and stated in the specification.
3. **Trait shapes are outside the contract files.** Slice 13.3 takes them from the published ports and must reconcile any difference with a contract change request.
4. **`type_name` keys the declared-DTO table.** A format change in the compiler would fail safe (the old container entry), and a test requires every DTO to be found; a new DTO must be added to the table in the slice that adds it.
5. **Character counting.** Lengths on text a user submits count code points everywhere; store-key and storage bounds may count bytes by design. New bounds follow the same rule and get an astral boundary test.
6. **Dependency budget.** No new crate is expected. If one is needed (a cursor encoding, for instance), it needs a vet entry, and the dependency-budget job is re-measured.
