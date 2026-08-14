//! Pins the exact bytes of `conformance/wire-contract.json`.
//!
//! The file is held **byte-identical** by nest-auth, which can back the same deployment over
//! the same Redis. Everything else in these suites reads a *value* out of it — a preimage
//! template, a status, a record shape — so a change to one of those values fails wherever it is
//! read. This test covers what those cannot: a change to a part of the contract nothing here
//! happens to read yet, and a reformat that rewrites every line while changing no value.
//!
//! # What this catches, and what it does not
//!
//! It catches an **unaccompanied byte change**: an edit that forgets to re-measure, a formatter
//! rewriting the file, a merge resolving it a third way. Every byte change in this repository has
//! to be declared here, in the same commit, by a human who looked at it.
//!
//! It does **not** catch cross-implementation divergence, and the difference is not a footnote.
//! Walk it through: nest-auth changes the contract *and* its own constant in one commit — its
//! suite is green, because it hashes its file and gets its value. Nothing here moved, so this
//! suite is green too. **Both green, bytes divergent.** Two independent local hashes cannot
//! enforce agreement between two repositories, because neither one reads the other. nest-auth
//! pinning the same constant today makes the pair *consistent*; it does not make either side able
//! to detect the other moving.
//!
//! Closing that for real needs a comparison that crosses the boundary — one side fetching the
//! other's committed blob in CI, or both consuming one immutable versioned artifact. Proposed,
//! unbuilt, and a maintainer call on both ends. Until it exists, the identity between the two
//! implementations rests on both maintainers changing the file deliberately and together. This
//! test narrows the accident, not the divergence.

use bymax_auth_crypto::mac::sha256;

/// The SHA-256 of the shared contract, lower-case hex.
///
/// Changing the contract is a two-repository operation by **convention**: change it, re-measure,
/// and move the constant here and in nest-auth in the same change. Nothing enforces the nest-auth
/// half — see the limits at the top of this file before trusting this constant to do more than it
/// does.
const WIRE_CONTRACT_SHA256: &str =
    "d7d0bdf3080946eac8bc79bba989091c6358c18d9489c3e1b7df611b692c0396";

/// The contract, as it sits in the working tree.
///
/// Deliberately the working tree rather than `git show HEAD:` — which is the authoritative form,
/// since a commit hook could rewrite the file between the two measurements. `git` is not reachable
/// from every place these tests run (a mutation run executes against a copied tree with no
/// repository in it), and a check that skipped itself there would pass on a broken state in the
/// very place the gate measuring the tests runs. A reformat changes the hash and fails, which is
/// the correct outcome: the shared file must not be silently reformatted on either side.
fn contract_bytes() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let bytes = std::fs::read(path).unwrap_or_default();
    assert!(
        !bytes.is_empty(),
        "the shared wire contract did not load from {path}"
    );
    bytes
}

#[test]
fn the_shared_wire_contract_carries_the_bytes_this_repository_declared() {
    // Named for what it checks. It is NOT "…what nest-auth holds": this reads one file and one
    // constant, both in this repository, and a name promising the other side would be the same
    // over-reading the module doc warns about.
    //
    // Falsified rather than watched pass: re-serialising the file with identical data and
    // different bytes turns this red, which is the class worth keeping — the two backends share a
    // keyspace, not a set of values that happen to agree.
    // Hex-encoded here rather than through `services::to_hex`: that one is `pub(crate)`, and an
    // integration test is a separate crate. Same idiom the other test crates use.
    let hex: String = sha256(&contract_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    assert_eq!(
        hex, WIRE_CONTRACT_SHA256,
        "the shared wire contract changed without this constant being re-measured. If the change \
         was deliberate, move the constant in the same commit — and move nest-auth's pin too, \
         which nothing here can check for you."
    );
}
