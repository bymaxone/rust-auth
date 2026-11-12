//! Workspace derivations and bounds shared with `@bymax-one/nest-auth` (layer: domain).
//!
//! Everything here is a pure function or a constant, pinned by sections of
//! `conformance/wire-contract.json` that this crate reads in its tests rather than restating:
//! the subjects and Redis key identifiers (`keys`), the host-facing scoped name
//! (`scoped_name`), the request bounds (`bounds`) and the lifetimes and limits (`limits`).

pub mod bounds;
pub mod keys;
pub mod limits;
pub mod scoped_name;

#[cfg(test)]
mod tests;
