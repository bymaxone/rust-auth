# AGENTS.md

`rust-auth` is a **published Rust authentication library**, not an application. It is one half of a
pair: `@bymax-one/nest-auth` is the TypeScript implementation of the same contract, and the two are
expected to run against **one shared Redis**. That is the fact most review findings here turn on —
a change that is locally correct and unilateral is still a defect.

There is no `CLAUDE.md` in this repository. The authority on behaviour is
`docs/technical_specification.md`, and the authority on anything crossing the two implementations is
`conformance/wire-contract.json`. What follows is the review layer.

## Code Review Rules

<!-- shared:begin -->
<!--
  CANONICAL COPY: bymaxone/.github → agents/code-review-rules.md
  Do not edit this block in a consuming repository. It is replaced wholesale by
  the `agents-sync` reusable workflow, so a local edit is reverted on the next
  run. Change it here, cut a release, and every repository is offered the update.

  Repository-specific rules go OUTSIDE this block, below the closing marker.
  Editing notes: AGENTS.md in bymaxone/.github.
-->

These rules hold in every Bymax repository. What is specific to this one is written after this
block, and the two are read together.

The pipeline already enforces formatting, linting, dependency policy, coverage and — where the
repository has one — the mutation gate. Do not spend a review on a **violation** of one of those: it
is a red check, not a comment. What follows is what CI cannot see.

A violation of a rule in this block is reported at **P1** at minimum. Codex surfaces only P0 and P1
on a pull request, so a rule whose violations land at P2 is a rule nobody sees.

**When a rule moves from here into a check, it leaves here.** A red check is proportionate to a
correctness failure that is invisible without it, and disproportionate to style enforced at an
inconvenient moment. Never carry both: a rule stated here _and_ enforced by CI spends a reviewer's
attention on what a gate already reports.

**A change to the enforcing configuration is the opposite case, and it is in scope.** Every gate runs
the configuration from the branch under review — that branch's lint config, its coverage thresholds,
its mutation thresholds. So a pull request that deletes a rule, lowers a threshold or widens an
ignore glob turns the check **green**, because a gate reports on the rules it was handed. For those
diffs the review is the only independent check there is, and a weakened gate needs the same
justification a suppression does.

### A finding names what it read

Every factual claim in a review — about a library's API, about this repository's history, about what
a file contains — has to come from something read in the tree under review, and the finding should
say which. A claim assembled from recollection is likely to describe a previous version of whatever
it is about.

**Safe path**, by the kind of claim:

| Claim about                             | Read this                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| A library's API **shape**               | `node_modules/<pkg>/dist/**/*.d.ts` in this tree                               |
| A library's **runtime behaviour**       | that version's changelog entry, its documentation, or a test that exercises it |
| A commit's author or committer identity | out of scope: it is not text a change introduces                               |
| What a file contains                    | the file at the revision under review, not an earlier one                      |

The first two rows are separate on purpose: a `.d.ts` settles what a signature accepts and nothing
about what the implementation does with it, so a behavioural claim resting on one is unfounded.

Weight the checking by what acting on the finding would cost. A comment that asks for a reworded
sentence is cheap to be wrong about; one that asks for history to be rewritten, a merge reverted, or
a release pulled is not — verify that class before raising it, and raise it at the severity the
evidence supports rather than the severity the consequence would deserve if true.

### A bug reproduces, and a finding is this change's

Unless a rule here says to report without one, raise a bug only with its trigger: the input or
repository state, the command, the wrong result. Letting through what should be refused is P1 at
least, as is a crash an untrusted caller can trigger; a refusal, or a crash no untrusted caller can
reach, on input the project does not claim to support is not. Behaviour already present at the merge
base belongs to another change. On new commits, review what changed since the last reviewed commit.
A thread is settled only when the reply cites evidence that disproves the finding (a command, a
test, a file:line) or the code it names changed; a resolved thread or a bare reason is not evidence,
so re-check the current code and raise the finding again only if its trigger still reproduces. One
comment per root cause, its siblings named in it.

### A dependency upgrade migrates every call site, not only the ones that fail to compile

When an upgrade tightens a contract, the compiler catches only the call sites whose **shape**
changed. A field that stays optional in the published type while becoming mandatory in behaviour
compiles, passes the unit suite, and fails in production.

A `@bymax-one/*` version number carries **no compatibility information** while the libraries are
pre-stable: breaking changes ship in minor and patch releases by explicit policy, so `^` and `~`
protect against nothing. The migration note under **Apply to a derived backend** in the library's own
changelog is the compatibility contract.

**Safe path:** read **every** changelog entry from the version being replaced up to the proposed
one, not only the proposed one's, and check every call site they name — not only the ones the
compiler rejected. Upgrades routinely skip releases, and the entry that matters is often not the
last one: adopting `@bymax-one/nest-cache` 1.1.0 → 1.2.1 skipped 1.2.0, whose entry holds a security
fix. Diff the `.d.ts` of the **previously adopted** version against the **proposed** one — `npm
pack` both, and name the two versions. Reaching for "the installed declarations" is the trap: in a
checkout of the branch under review the installed tree is already the new version, so that diff
compares a release with itself and shows nothing.

### Settled decisions are not review findings

Both are settled deliberately, and reopening either costs a round trip and changes nothing:

- **Do not propose a major version bump** for a breaking change in a `@bymax-one/*` library, and do
  not assert that this ecosystem follows strict SemVer. Until an API is declared stable, breaking
  changes ship in minor and patch releases; the migration note carries the compatibility information
  the number does not. If a document claims strict SemVer, the finding is that the claim is wrong —
  not that the version should be raised.
- **Do not propose pinning `bymaxone/.github` reusable workflows to a commit SHA.** They are
  referenced by the `@v1` alias on purpose: a fix has to land once and reach every repository, the
  tag is immutable and the alias moves only on a release, and pinning was measured to cost ~58
  dependency pull requests to propagate one change. Third-party actions are the opposite case and
  **are** pinned by SHA.

**Safe path:** if you believe a settled decision is now wrong, say so as a question in the pull
request rather than as a finding.

### Suppressions are refusals, not exceptions

`@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `eslint-disable` in any form,
`as unknown as` laundering a real type error, `istanbul ignore`, and in Rust `#[allow(...)]` over a
lint gate or `unsafe` without a `// SAFETY:` comment are blocking findings.

Anything a configured gate already reports belongs to the gate, not to a review: where a repository
lints `no-explicit-any` as an error — most do — an `as any` is a red check, and raising it here only
duplicates it. Check the repository's lint configuration before reporting a suppression rather than
assuming the list is exhaustive in either direction.

A failing gate means the code is wrong, the type is wrong, or the rule is wrong. **Safe path:** fix
whichever it is. Changing a rule's configuration with a stated reason is legitimate; scattering
per-call-site silencers is not.

### A key built from more than one field keeps its boundaries

A key or digest derived from **two or more variable fields** must not let a field's content move the
boundary between them. `${tenantId}:${recipient}` makes `('a:b','c')` and `('a','b:c')` one key,
which no digest strength repairs, and one tenant's lookup then resolves another's record. Rejecting
empty fields does not fix it, and neither does a caller that validates its input — the property has
to hold in the construction. A fixed prefix beside a single field is not this shape.

**Safe path:** encode each field so it cannot contain the delimiter, or hash each to a fixed width.
Any other composition needs an argument that every boundary is recoverable, and one bounded field
does not rescue two free ones beside it. Then assert it in a test: where the property holds only
because of the values in play, the next one added takes it away and nothing says so.

### Comments state constraints, never history

A comment must read as true for whoever opens the file next. Flag any comment that narrates what a
previous version did, names a phase, task, ticket or review round, or explains a change rather than
the code. **Safe path:** state the constraint that still holds, and let `git log` carry the history.

Evidence for a constraint is not history, and how the evidence was obtained does not decide which it
is. The test is whether the fact still binds the next reader. A measurement that predicts what they
will hit on the other path — what the alternative did, what it costs in numbers — belongs beside the
constraint it supports, however it was obtained. What ages is the part that cannot recur for them:
what a previous version of this code did, a version number, a registry state, a review round, a
failure that has since been fixed. Flag those; keep the measurement.

### Size and layering

Functions over **50 lines** and nesting deeper than four levels are findings **for what a change
introduces** — a new function, or a change that pushes an existing one past the limit — in the
repository's own source and test directories. A test-suite grouping construct (`describe`, `context`,
`mod tests`, a table of cases) is not a function; the unit under the limit is the body of a single
`it`/`test`/`#[test]`. On the same terms, every non-trivial source file a change introduces opens
with a header stating its purpose and its layer, and every exported symbol a change introduces
carries a doc comment.

**The 800-line file limit applies to what a change introduces, not to what it inherits.** A
repository that already carries a file past the line — a generator, a long end-to-end suite — would
otherwise produce a finding on every pull request touching three lines of it, which the author
cannot act on and did not cause. Raise it for a **new** file over the limit, or when a change pushes
a file past it or materially grows one already over.

Markdown, generated output and lockfiles are **out of scope**: none has layers, and reporting their
length fires on every dependency bump and release note.

**Safe path:** extract by responsibility rather than by line count — the limit is a symptom, and one
file doing two jobs is the defect.

### Language and attribution

Everything published is English — source, comments, tests, commit messages, pull request titles and
bodies, `README.md`, `CHANGELOG.md` and everything under `.github/`.

Each repository states its language policy for `docs/` below this block. Report a language finding in
`docs/` only against what the repository states; where it states nothing, `docs/` is English like
everything else. A `docs/` language other than English is a repository-owner decision recorded in the
narrowings, not a convention a contributor may introduce.

No commit, pull request, comment or code may attribute authorship to an AI assistant or coding tool,
in any form. **Only text the change introduces is in scope** — a trailer, a "generated with" line, a
signature in a comment or a description.

A commit's author and committer fields are not that: they come from the contributor's git
configuration rather than from the diff, and a review reading the diff cannot see them. Never report
an identity field, and never present a command's reconstructed output as evidence for one. Measured:
twenty-six such findings, every SHA resolving nowhere and every `git log` line unrun, each asking to
rewrite published history.

<!-- shared:end -->

### A key, index or fan-out built on a bare user id is a defect

`UserRepository::find_by_id` takes a tenant precisely because a repository id is unique only
*within* a tenant. A host that numbers users per tenant has a real `t1/u1` and a real `t2/u1`, and
they are unrelated accounts. So any Redis key, index, set membership or fan-out derived from the id
alone silently merges them, and the failure is a cross-tenant one: revoking, suspending or bumping
an epoch for one account reaches a stranger's.

This is worth stating because **the wrong version is the tidier-looking one**. `sess:{userId}` reads
as obviously correct next to `sess:{hmac_sha256(hmacKey, userSubject)}`, and a reviewer optimising
for simplicity approves it. The account-scoped derivation is `userSubject` (§12.4), and every key
that names an ACCOUNT rather than a token belongs to `userSubjectDerivedKeys` in the shared
contract.

The same reasoning covers lookups, not just keys: `find_by_id(id, None)` is documented as the
cross-tenant admin path, and reaching for it on a request path is the same defect one layer up.

**Safe path:** derive from the tenant-scoped subject, and add the key to `userSubjectDerivedKeys`
so the contract test enforces it.

### A parity test must read the shared artefact, not a restatement of it

`conformance/wire-contract.json` is only a drift detector if something asserts against it. A test
that copies a table out of the contract, or that lists a hand-written subset of a section it reads,
detects drift only in what it happens to name — and reports agreement for everything else.

A hand-written table checks rust-auth against itself, and a partial key list passes with the gate
green while the omitted keys go unimplemented.

**Safe path:** assert **set equality** against the section, in both directions. A key added to the
contract must fail the build until it is derived; a key removed must fail until the removal is
understood. Flag any new test that names a subset of an artefact it has already loaded.

### The shared contract is a two-repository change

`conformance/wire-contract.json` is held **byte-identical** with nest-auth, and **nothing in CI
compares the two copies** — each repository can only detect an unaccompanied edit of its own. A pull
request that edits this file and nothing else in the pair is therefore green and wrong.

**Safe path:** change it in both repositories in the same change, and say so in the description. If
the change has no compatibility path, the `CHANGELOG.md` entry carries the deployment obligation
(cutover, not rolling upgrade) and the migration obligations for a live keyspace, because neither
library ships tooling to perform one.

### A diff that shifts lines can silently disable a mutation exclusion

`.cargo/mutants.toml` excludes documented equivalent mutants by regex, and two entries must
distinguish `cfg(feature)` twins that share a mutant name — so they are anchored to a **line
number**. A diff that shifts lines in `crates/bymax-auth-core/src/engine/builder.rs` or
`crates/bymax-auth-core/src/services/token_manager.rs` breaks the anchor, and the excluded mutant
reappears as a survivor against a floor that is supposed to block a release.

This does **not** fail closed: the mutation sweep runs post-merge, so a survivor is a line in a
report, not a red pull request.

**Safe path:** when a diff touches either file, run
`cargo mutants --list | grep -E "redis_stores|issue_mfa_temp_token"` and confirm only the compiled
twins remain. Tell them apart by content, not position: the excluded `redis_stores` is the bound
**without** `MfaStore`; the excluded `issue_mfa_temp_token` opens
`let _ = (context, tenant_id); tracing::error!`.

### Where this repository narrows a shared rule

**Suppressions.** The shared block names `#[allow(...)]` over a lint gate and `unsafe` without a
`// SAFETY:` comment. This workspace additionally *denies* `clippy::unwrap_used`,
`clippy::expect_used`, `clippy::panic`, `clippy::all` and `missing_docs` — so those are red checks,
not review comments, and the shared block's own rule applies: do not spend a review duplicating a
gate. What is still worth a finding is a diff that **weakens** `[workspace.lints]`, widens
`exclude_re` in `.cargo/mutants.toml`, or adds an `#[ignore]`.

**TypeScript-only rules do not apply.** The shared block's `any`, JSDoc, `interface` vs `type` and
Tailwind rules have no Rust counterpart here. The documentation bar they stand in for is enforced
instead by `missing_docs = "deny"` plus rustdoc on every public item, which the gate reports.
