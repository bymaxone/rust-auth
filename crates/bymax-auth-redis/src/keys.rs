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
    /// Dashboard rotation grace pointer (`rp`).
    Rp,
    /// Dashboard active-session index SET (`sess`).
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
    /// Password-reset link token (`pr`).
    Pr,
    /// Password-reset OTP "verified" token (`prv`).
    Prv,
    /// Pending invitation (`inv`).
    Inv,
    /// Platform-admin refresh session (`prt`).
    Prt,
    /// Platform rotation grace pointer (`prp`).
    Prp,
    /// Platform active-session index SET (`psess`).
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
            Self::Rp => "rp",
            Self::Sess => "sess",
            Self::Sd => "sd",
            Self::Lf => "lf",
            Self::Otp => "otp",
            Self::Resend => "resend",
            Self::Wst => "wst",
            Self::Pr => "pr",
            Self::Prv => "prv",
            Self::Inv => "inv",
            Self::Prt => "prt",
            Self::Prp => "prp",
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
    /// member key from a SET (`invalidate_user_sessions`).
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
            (Prefix::Rp, "auth:rp:abc"),
            (Prefix::Sess, "auth:sess:abc"),
            (Prefix::Sd, "auth:sd:abc"),
            (Prefix::Lf, "auth:lf:abc"),
            (Prefix::Otp, "auth:otp:abc"),
            (Prefix::Resend, "auth:resend:abc"),
            (Prefix::Wst, "auth:wst:abc"),
            (Prefix::Pr, "auth:pr:abc"),
            (Prefix::Prv, "auth:prv:abc"),
            (Prefix::Inv, "auth:inv:abc"),
            (Prefix::Prt, "auth:prt:abc"),
            (Prefix::Prp, "auth:prp:abc"),
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
