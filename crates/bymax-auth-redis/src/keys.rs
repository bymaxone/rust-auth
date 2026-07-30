//! The Redis key catalog and the single namespace-prefixing key builder.
//!
//! [`Prefix`] is the typed set of catalog prefixes from the specification (section 12.4);
//! [`NamespacedRedis`] is the **only** component permitted to construct a fully-qualified
//! `{namespace}:{prefix}:{id}` key, so no call site ever assembles a raw key by hand. The
//! `id` segment is always a hash/HMAC of an identifier (or an opaque high-entropy id), never
//! raw PII (section 24, invariant 9).

/// Lower-case hexadecimal alphabet, indexed by nibble value.
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex-encode a byte slice. Renders a SHA-256 digest into the fixed-length,
/// no-PII suffix a key uses (e.g. the WebSocket ticket's `sha256(ticket)`).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_ALPHABET[usize::from(byte >> 4)] as char);
        out.push(HEX_ALPHABET[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// A Redis key prefix from the catalog (section 12.4). The wire form returned by
/// [`Prefix::as_str`] is byte-identical to nest-auth so both backends can share one Redis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// Dashboard refresh-token session (`rt`).
    Rt,
    /// Access-JWT revocation blacklist (`rv`).
    Rv,
    /// Dashboard per-user token epoch / generation counter (`ep`).
    Ep,
    /// Platform per-user token epoch / generation counter (`pep`).
    Pep,
    /// Dashboard rotation grace pointer (`rp`).
    Rp,
    /// Dashboard consumed-token family marker for reuse detection (`cf`).
    Cf,
    /// Dashboard refresh-token family index SET (`fam`). Its members are bare `sha256` hashes,
    /// not key suffixes: a family only ever indexes live `rt:` sessions, so the prefix is
    /// implied by the index itself.
    Fam,
    /// Dashboard active-session index SET (`sess`). Its members are full key **suffixes** —
    /// `rt:{hash}` for a live session, `rp:{oldHash}` for a rotation grace pointer — never bare
    /// hashes, matching nest-auth so either backend can revoke the other's sessions.
    Sess,
    /// Dashboard per-session detail (`sd`).
    Sd,
    /// Per-tenant failed-login counter (`lf`).
    Lf,
    /// One-time-password record (`otp`).
    Otp,
    /// OTP-resend cooldown (`resend`).
    Resend,
    /// Single-use WebSocket upgrade ticket (`wst`).
    Wst,
    /// Password-reset link token (`pw_reset`).
    PwReset,
    /// Password-reset OTP "verified" token (`pw_vtok`).
    PwVtok,
    /// Pending invitation (`inv`).
    Inv,
    /// Single-use claim on an MFA recovery code (`rcu`).
    Rcu,
    /// Pending address change (`ec`).
    Ec,
    /// Invitee index for a pending invitation (`invidx`). Keyed by
    /// `{tenantId}:{sha256(email)}` and holding the invitation's token hash — the only handle
    /// the issuing side has on a record keyed by a token it never saw.
    Invidx,
    /// Platform-admin refresh session (`prt`).
    Prt,
    /// Platform rotation grace pointer (`prp`).
    Prp,
    /// Platform consumed-token family marker for reuse detection (`pcf`).
    Pcf,
    /// Platform refresh-token family index SET (`pfam`). Members are bare `sha256` hashes, as
    /// on the dashboard plane.
    Pfam,
    /// Platform active-session index SET (`psess`). Members are `prt:{hash}` / `prp:{oldHash}`
    /// key suffixes; the platform keyspace is deliberately separate from the dashboard one.
    Psess,
    /// Platform per-session detail (`psd`).
    Psd,
    /// MFA pending-setup record (`mfa_setup`).
    MfaSetup,
    /// MFA temp-token single-use marker (`mfa`).
    Mfa,
    /// TOTP anti-replay marker (`tu`).
    Tu,
    /// Single-use OAuth `state` + PKCE record (`os`).
    Os,
}

impl Prefix {
    /// The stable wire form of the prefix — the `{prefix}` segment of a key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rt => "rt",
            Self::Rv => "rv",
            Self::Ep => "ep",
            Self::Pep => "pep",
            Self::Rp => "rp",
            Self::Cf => "cf",
            Self::Fam => "fam",
            Self::Sess => "sess",
            Self::Sd => "sd",
            Self::Lf => "lf",
            Self::Otp => "otp",
            Self::Resend => "resend",
            Self::Wst => "wst",
            Self::PwReset => "pw_reset",
            Self::PwVtok => "pw_vtok",
            Self::Inv => "inv",
            Self::Rcu => "rcu",
            Self::Ec => "ec",
            Self::Invidx => "invidx",
            Self::Prt => "prt",
            Self::Prp => "prp",
            Self::Pcf => "pcf",
            Self::Pfam => "pfam",
            Self::Psess => "psess",
            Self::Psd => "psd",
            Self::MfaSetup => "mfa_setup",
            Self::Mfa => "mfa",
            Self::Tu => "tu",
            Self::Os => "os",
        }
    }
}

/// The sole builder of fully-qualified Redis keys. It owns the configured namespace and
/// prepends `{namespace}:` to every key, so the namespace is applied in exactly one place
/// (section 12.2). `KEYS` handed to a Lua script are produced here; a script that must
/// rebuild member keys from a SET receives [`NamespacedRedis::namespace`] as an `ARGV`.
#[derive(Clone, Debug)]
pub struct NamespacedRedis {
    namespace: Box<str>,
}

impl NamespacedRedis {
    /// Wrap a namespace (default `auth`). The namespace isolates the auth keyspace from the
    /// host application's own Redis keys.
    #[must_use]
    pub fn new(namespace: impl Into<Box<str>>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    /// The configured namespace, passed as an `ARGV` element to the scripts that rebuild a
    /// member key from a SET (`invalidate_user_sessions`, which deletes `{namespace}:{member}`
    /// for each member — the member already carries its own prefix).
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Build `"{namespace}:{prefix}:{id}"`. The `id` is always a hash/HMAC or an opaque
    /// high-entropy identifier — never raw PII.
    #[must_use]
    pub fn key(&self, prefix: Prefix, id: &str) -> String {
        format!("{}:{}:{}", self.namespace, prefix.as_str(), id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read `{section}.{key}` from the shared cross-implementation wire contract.
    ///
    /// The file at `conformance/wire-contract.json` is held byte-identical by nest-auth, which
    /// can back the same deployment over the same Redis. Reading it here rather than repeating
    /// its values means a prefix rename on either side turns that side red immediately, instead
    /// of surfacing later as a keyspace that silently split in production.
    fn contract_value(section: &str, key: &str) -> String {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        root.get(section)
            .and_then(|s| s.get(key))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn every_prefix_matches_the_shared_wire_contract() {
        // The prefix each keyspace writes IS the contract with the sibling implementation. A
        // rename landing on one side only splits the keyspace: a reset link emailed by one
        // backend becomes invisible to the other, and a session index written by one is never
        // swept by the other.
        for (name, prefix) in [
            ("dashboardRefreshSession", Prefix::Rt),
            ("dashboardGracePointer", Prefix::Rp),
            ("dashboardConsumedFamilyMarker", Prefix::Cf),
            ("dashboardFamilyIndex", Prefix::Fam),
            ("dashboardSessionIndex", Prefix::Sess),
            ("dashboardSessionDetail", Prefix::Sd),
            ("dashboardTokenEpoch", Prefix::Ep),
            ("platformRefreshSession", Prefix::Prt),
            ("platformGracePointer", Prefix::Prp),
            ("platformConsumedFamilyMarker", Prefix::Pcf),
            ("platformFamilyIndex", Prefix::Pfam),
            ("platformSessionIndex", Prefix::Psess),
            ("platformSessionDetail", Prefix::Psd),
            ("platformTokenEpoch", Prefix::Pep),
            ("accessTokenBlacklist", Prefix::Rv),
            ("failedLoginCounter", Prefix::Lf),
            ("oneTimePassword", Prefix::Otp),
            ("passwordResetToken", Prefix::PwReset),
            ("passwordResetVerifiedToken", Prefix::PwVtok),
            ("totpReplayMarker", Prefix::Tu),
            ("oauthState", Prefix::Os),
            ("wsTicket", Prefix::Wst),
            ("invitation", Prefix::Inv),
        ] {
            assert_eq!(
                contract_value("redisKeyPrefixes", name),
                prefix.as_str(),
                "prefix for {name} drifted from the shared contract"
            );
        }
    }

    #[test]
    fn the_two_identity_planes_never_share_a_prefix() {
        // The planes are keyed by ids from different consumer repositories, which may
        // legitimately collide. One shared index would let a revoke on one plane log the other
        // out, so the separation is a correctness property, not a naming preference.
        assert_ne!(
            contract_value("redisKeyPrefixes", "dashboardSessionIndex"),
            contract_value("redisKeyPrefixes", "platformSessionIndex"),
        );
        assert_ne!(
            contract_value("redisKeyPrefixes", "dashboardSessionDetail"),
            contract_value("redisKeyPrefixes", "platformSessionDetail"),
        );
    }

    #[test]
    fn the_family_index_takes_bare_hashes_and_the_session_index_does_not() {
        // Two indexes, two member shapes, and the difference is load-bearing. A family only ever
        // tracks live refresh sessions, so its members are bare hashes and the revocation script
        // rebuilds `rt:{hash}` from them; the session index mixes live sessions with rotation
        // grace pointers, so its members must carry their own prefix. Swapping either shape
        // makes one backend unable to sweep what the other wrote.
        assert_eq!(
            contract_value("familyIndexMembers", "dashboardLive"),
            "{sha256(refreshToken)}"
        );
        assert_eq!(
            contract_value("familyIndexMembers", "platformLive"),
            "{sha256(refreshToken)}"
        );
        assert!(
            contract_value("sessionIndexMembers", "dashboardLive")
                .starts_with(&format!("{}:", Prefix::Rt.as_str()))
        );
    }

    #[test]
    fn the_rotation_semantics_are_the_ones_this_crate_implements() {
        // These are behaviours rather than bytes, but the two backends share the markers behind
        // them: one side treating a replay as recoverable while the other treats it as theft
        // would make the reaction depend on which backend the request happened to reach.
        let rotate = include_str!("lua/refresh_rotate.lua");
        assert!(
            contract_value("rotationSemantics", "graceWindow").contains("single-shot"),
            "the contract must declare the grace window single-shot"
        );
        // The pointer is consumed on use, which is what makes it single-shot.
        assert!(rotate.contains("redis.call('DEL', KEYS[3])"));
        // A replay past the window is reported as a reuse carrying its family.
        assert!(rotate.contains("'REUSED:'"));
        assert!(
            contract_value("rotationSemantics", "reuseReaction")
                .contains("revoke the whole family")
        );
    }

    #[test]
    fn to_hex_encodes_lower_case_two_chars_per_byte() {
        // The digest-to-suffix encoder must be lower-case, two chars per byte, and handle the
        // empty slice — the format the no-PII key suffix relies on.
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[test]
    fn key_namespaces_every_catalog_prefix() {
        // Every catalog prefix renders its exact wire string under the namespace, with no
        // call site ever building a raw key. Exercising all variants pins the catalog.
        let ns = NamespacedRedis::new("auth");
        assert_eq!(ns.namespace(), "auth");
        let cases = [
            (Prefix::Rt, "auth:rt:abc"),
            (Prefix::Rv, "auth:rv:abc"),
            (Prefix::Ep, "auth:ep:abc"),
            (Prefix::Pep, "auth:pep:abc"),
            (Prefix::Rp, "auth:rp:abc"),
            (Prefix::Cf, "auth:cf:abc"),
            (Prefix::Fam, "auth:fam:abc"),
            (Prefix::Sess, "auth:sess:abc"),
            (Prefix::Sd, "auth:sd:abc"),
            (Prefix::Lf, "auth:lf:abc"),
            (Prefix::Otp, "auth:otp:abc"),
            (Prefix::Resend, "auth:resend:abc"),
            (Prefix::Wst, "auth:wst:abc"),
            (Prefix::PwReset, "auth:pw_reset:abc"),
            (Prefix::PwVtok, "auth:pw_vtok:abc"),
            (Prefix::Inv, "auth:inv:abc"),
            (Prefix::Rcu, "auth:rcu:abc"),
            (Prefix::Ec, "auth:ec:abc"),
            (Prefix::Invidx, "auth:invidx:abc"),
            (Prefix::Prt, "auth:prt:abc"),
            (Prefix::Prp, "auth:prp:abc"),
            (Prefix::Pcf, "auth:pcf:abc"),
            (Prefix::Pfam, "auth:pfam:abc"),
            (Prefix::Psess, "auth:psess:abc"),
            (Prefix::Psd, "auth:psd:abc"),
            (Prefix::MfaSetup, "auth:mfa_setup:abc"),
            (Prefix::Mfa, "auth:mfa:abc"),
            (Prefix::Tu, "auth:tu:abc"),
            (Prefix::Os, "auth:os:abc"),
        ];
        for (prefix, expected) in cases {
            assert_eq!(ns.key(prefix, "abc"), expected);
            // The `Debug`/`Copy`/`Eq` derives back the typed prefix for diagnostics.
            assert_eq!(prefix, prefix);
        }
        // A custom namespace is honored verbatim.
        assert_eq!(
            NamespacedRedis::new("tenant".to_owned()).key(Prefix::Rt, "h"),
            "tenant:rt:h"
        );
    }
}
