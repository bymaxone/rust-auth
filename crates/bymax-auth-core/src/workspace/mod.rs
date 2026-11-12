//! Workspace derivations and bounds shared with `@bymax-one/nest-auth` (layer: domain).
//!
//! Everything here is a pure function or a constant, pinned by sections of
//! `conformance/wire-contract.json` that this crate reads in its tests rather than restating:
//! the subjects and Redis key identifiers (`keys`), the host-facing scoped name
//! (`scoped_name`), the request bounds (`bounds`), the lifetimes and limits (`limits`) and the
//! names, entry and lifetime of the membership cache (`membership_cache`).

pub mod audit;
pub mod bounds;
pub mod domain;
pub mod keys;
pub mod limits;
pub mod membership_cache;
pub mod roles;
pub mod scoped_name;

#[cfg(test)]
mod domain_tests;
#[cfg(test)]
mod membership_cache_tests;
#[cfg(test)]
mod tests;
