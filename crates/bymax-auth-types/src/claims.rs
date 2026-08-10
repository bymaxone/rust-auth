//! JWT claim structures: [`DashboardClaims`], [`PlatformClaims`], and
//! [`MfaTempClaims`], with the exact on-the-wire field names and the `type`
//! discriminator that keep token bytes compatible with `@bymax-one/nest-auth`.
//!
//! # Wire fidelity
//!
//! The canonical Rust field is `token_type` (since `type` is a keyword); it serializes
//! to the wire name `type` via `#[serde(rename = "type")]`. The discriminator value is
//! a single-variant enum so a wrong `type` fails deserialization rather than silently
//! mis-typing a token. `iat`/`exp` are NumericDate (seconds since the Unix epoch) per
//! RFC 7519. Access claims carry **both** `mfaEnabled` (account has MFA configured) and
//! `mfaVerified` (this session cleared the second factor).

use serde::{Deserialize, Serialize};

/// Discriminator value for a dashboard access token. Serializes to `"dashboard"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "jwt-payload.types.ts"))]
#[serde(rename_all = "snake_case")]
pub enum DashboardType {
    /// The only value — present so a mismatched discriminator fails to deserialize.
    Dashboard,
}

/// Discriminator value for a platform access token. Serializes to `"platform"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "jwt-payload.types.ts"))]
#[serde(rename_all = "snake_case")]
pub enum PlatformType {
    /// The only value.
    Platform,
}

/// Discriminator value for an MFA-temp token. Serializes to `"mfa_challenge"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "jwt-payload.types.ts"))]
#[serde(rename_all = "snake_case")]
pub enum MfaTempType {
    /// The only value.
    MfaChallenge,
}

/// Which identity domain an MFA-temp token bridges — selects the repository and result
/// type downstream. Serializes to `"dashboard"` / `"platform"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "jwt-payload.types.ts"))]
#[serde(rename_all = "snake_case")]
pub enum MfaContext {
    /// Dashboard/tenant user challenge.
    Dashboard,
    /// Platform administrator challenge.
    Platform,
}

impl MfaContext {
    /// The plane's wire name, matching how this enum serializes.
    ///
    /// Used to namespace the MFA store keys and brute-force counters by identity plane. The
    /// two planes' ids come from different consumer repositories and may collide, so a key
    /// derived from the id alone is shared between an unrelated user and admin.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Platform => "platform",
        }
    }
}

/// Access token for tenant/dashboard users. The TypeScript counterpart is
/// `DashboardJwtPayload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "jwt-payload.types.ts", rename = "DashboardJwtPayload")
)]
#[serde(rename_all = "camelCase")]
pub struct DashboardClaims {
    /// Subject — the user id.
    pub sub: String,
    /// Token id (UUID v4) — the access-token blacklist key.
    pub jti: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Authorization role.
    pub role: String,
    /// Discriminator — always `"dashboard"`.
    #[serde(rename = "type")]
    pub token_type: DashboardType,
    /// Account lifecycle status (e.g. "ACTIVE", "PENDING_APPROVAL").
    pub status: String,
    /// Whether the account has MFA configured (drives the MFA-required guard).
    pub mfa_enabled: bool,
    /// Whether this session has cleared the second factor.
    pub mfa_verified: bool,
    /// Issued-at (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub iat: i64,
    /// Expiry (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub exp: i64,
    /// The user's token **epoch** at issuance — a per-user generation counter the server bumps
    /// to invalidate every outstanding access token at once (a password reset or a full
    /// sign-out-everywhere). **Server-side** verification rejects the token when its epoch is
    /// below the user's current stored epoch; the edge/WASM verifier carries this claim but does
    /// not consult it (it checks signature, `iat`, and `exp` only), exactly like the jti
    /// blacklist. Defaults to `0` when the claim is absent, which is never rejected while the
    /// stored epoch is also `0` (the mechanism is inert until a bump) and always rejected once
    /// it is bumped — the fail-closed direction.
    ///
    /// Exported as an optional TS property: the decode-only edge path passes the raw JWT payload
    /// through untyped, so a token really can arrive without the key (serde's default only
    /// applies when deserializing into this struct). Rendered via `Option::<f64>` because
    /// ts-rs maps 64-bit integers to `bigint`, while `JSON.parse` yields a `number`.
    #[serde(default)]
    #[cfg_attr(feature = "ts-export", ts(as = "Option::<f64>", optional))]
    pub epoch: u64,
    /// The `iss` claim, present only when the deployment configured `jwt.issuer`.
    ///
    /// Absent by default. When the verifier is configured with a value, a token carrying a
    /// different one — or none at all — is rejected: accepting an unstamped token would give
    /// an attacker a way to opt out of the check by omitting the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub iss: Option<String>,
    /// The `aud` claim, with the same semantics as [`Self::iss`]. With HS256 the verifier can
    /// also sign, so audience binding is what stops a token minted for one service being
    /// replayed at another that trusts the same secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub aud: Option<String>,
}

/// Access token for platform admins — no `tenantId`. The TypeScript counterpart is
/// `PlatformJwtPayload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "jwt-payload.types.ts", rename = "PlatformJwtPayload")
)]
#[serde(rename_all = "camelCase")]
pub struct PlatformClaims {
    /// Subject — the admin id.
    pub sub: String,
    /// Token id (UUID v4) — the access-token blacklist key.
    pub jti: String,
    /// Authorization role within the platform hierarchy.
    pub role: String,
    /// Discriminator — always `"platform"`.
    #[serde(rename = "type")]
    pub token_type: PlatformType,
    /// Whether the account has MFA configured.
    pub mfa_enabled: bool,
    /// Whether this session has cleared the second factor.
    pub mfa_verified: bool,
    /// Issued-at (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub iat: i64,
    /// Expiry (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub exp: i64,
    /// The admin's token **epoch** at issuance — the platform-domain analogue of
    /// [`DashboardClaims::epoch`]: a per-admin generation counter the server bumps to invalidate
    /// every outstanding platform access token at once. Enforced by **server-side** verification
    /// only; the edge/WASM verifier carries it without consulting it. Defaults to `0` when the
    /// claim is absent, and is exported as an optional TS property for the same reason as
    /// [`DashboardClaims::epoch`].
    #[serde(default)]
    #[cfg_attr(feature = "ts-export", ts(as = "Option::<f64>", optional))]
    pub epoch: u64,
    /// The `iss` claim, present only when the deployment configured `jwt.issuer`.
    ///
    /// Absent by default. When the verifier is configured with a value, a token carrying a
    /// different one — or none at all — is rejected: accepting an unstamped token would give
    /// an attacker a way to opt out of the check by omitting the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub iss: Option<String>,
    /// The `aud` claim, with the same semantics as [`Self::iss`]. With HS256 the verifier can
    /// also sign, so audience binding is what stops a token minted for one service being
    /// replayed at another that trusts the same secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub aud: Option<String>,
}

/// Short-lived token bridging the password step and the MFA challenge. The TypeScript
/// counterpart is `MfaTempPayload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "jwt-payload.types.ts", rename = "MfaTempPayload")
)]
#[serde(rename_all = "camelCase")]
pub struct MfaTempClaims {
    /// Subject — the user/admin id.
    pub sub: String,
    /// Token id (UUID v4) — also written to the single-use MFA marker.
    pub jti: String,
    /// Discriminator — always `"mfa_challenge"`.
    #[serde(rename = "type")]
    pub token_type: MfaTempType,
    /// Which identity domain this challenge belongs to.
    pub context: MfaContext,
    /// The tenant the challenged account belongs to — present on the dashboard plane, absent
    /// on the platform plane, whose admins are cross-tenant and carry none.
    ///
    /// Without it the challenge had no tenant in scope at all, and every decision it makes ran
    /// on an account resolved by id alone: the user lookup passed `None`, so the status gate,
    /// `mfa_enabled`, the encrypted secret and the recovery-code digests were all read from
    /// whichever row the host returned, and the session was minted for that row. Under a host
    /// schema that numbers users per tenant — which a library cannot rule out — every tenant
    /// has a user `1`. It also left the pre-fetch challenge counter with nothing to scope by,
    /// so failures from one tenant spent another tenant's lockout budget.
    ///
    /// Optional in the wire format so the claim is additive, but a dashboard challenge token
    /// WITHOUT it is refused at verification rather than falling back to the unscoped shape —
    /// a fallback would leave the vulnerable derivation reachable by simply omitting a field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub tenant_id: Option<String>,
    /// The subject's token **epoch** at issuance, in the plane named by [`Self::context`].
    ///
    /// The challenge token is a credential like any other — half of one, held by a caller who
    /// has already proved the password — and it must die with the rest when the account's
    /// credentials are rotated. Without this claim it did not: a password reset bumps the epoch
    /// and kills every access token, but nothing touched an outstanding `mfa:` marker, so a
    /// challenge token minted before the reset stayed redeemable for its whole TTL and
    /// completing it issued a full session under the *new* epoch. The reset is meant to end
    /// everything the old credential could still reach.
    ///
    /// Defaults to `0` when the claim is absent, so the mechanism stays inert until the first
    /// bump — the same contract as [`DashboardClaims::epoch`].
    #[serde(default)]
    #[cfg_attr(feature = "ts-export", ts(as = "Option::<f64>", optional))]
    pub epoch: u64,
    /// Issued-at (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub iat: i64,
    /// Expiry (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub exp: i64,
    /// The `iss` claim, present only when the deployment configured `jwt.issuer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub iss: Option<String>,
    /// The `aud` claim, with the same semantics as [`Self::iss`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub aud: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard_claims() -> DashboardClaims {
        DashboardClaims {
            iss: None,
            aud: None,
            sub: "u_1".to_owned(),
            jti: "jti-1".to_owned(),
            tenant_id: "t_1".to_owned(),
            role: "member".to_owned(),
            token_type: DashboardType::Dashboard,
            status: "ACTIVE".to_owned(),
            mfa_enabled: true,
            mfa_verified: false,
            iat: 1_700_000_000,
            exp: 1_700_000_900,
            epoch: 3,
        }
    }

    #[test]
    fn dashboard_claims_emit_the_exact_wire_field_names() {
        // The discriminator is `type`, the tenant/MFA fields are camelCase, and BOTH
        // mfaEnabled and mfaVerified are present — the byte-level nest-auth contract. The
        // per-user token epoch rides along as a plain `epoch` number.
        let json = serde_json::to_value(dashboard_claims()).unwrap_or_default();
        assert_eq!(json["type"], "dashboard");
        assert_eq!(json["tenantId"], "t_1");
        assert_eq!(json["mfaEnabled"], true);
        assert_eq!(json["mfaVerified"], false);
        assert_eq!(json["status"], "ACTIVE");
        assert_eq!(json["epoch"], 3);
        assert!(
            json.get("token_type").is_none(),
            "raw field name must not leak"
        );
    }

    #[test]
    fn a_missing_epoch_deserializes_to_zero() {
        // A legacy token that predates the epoch field must still deserialize, defaulting the
        // epoch to 0 so the mechanism stays inert for it rather than failing the parse.
        let legacy = serde_json::json!({
            "sub": "u_1", "jti": "jti-1", "tenantId": "t_1", "role": "member",
            "type": "dashboard", "status": "ACTIVE", "mfaEnabled": false,
            "mfaVerified": false, "iat": 1, "exp": 2
        });
        let parsed: Result<DashboardClaims, _> = serde_json::from_value(legacy);
        assert!(matches!(parsed, Ok(claims) if claims.epoch == 0));
    }

    #[test]
    fn platform_claims_have_no_tenant_id() {
        // Platform tokens never carry a tenant scope; the field is absent by type.
        let claims = PlatformClaims {
            iss: None,
            aud: None,
            sub: "p_1".to_owned(),
            jti: "jti-2".to_owned(),
            role: "super_admin".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: 1,
            exp: 2,
            epoch: 0,
        };
        let json = serde_json::to_value(claims).unwrap_or_default();
        assert_eq!(json["type"], "platform");
        assert!(json.get("tenantId").is_none());
        assert_eq!(json["mfaEnabled"], false);
    }

    #[test]
    fn mfa_temp_claims_serialize_the_tenant_as_the_camel_case_wire_claim() {
        // The claim NAME is the contract, not the Rust field name. nest-auth signs its payload
        // keys verbatim and uses `tenantId`; a token whose tenant rides under `tenant_id` would
        // deserialize as ABSENT on the other side, and absent is refused — so the two halves
        // would each look correct while agreeing on nothing. Pinned here because `rename_all`
        // is a struct-level attribute that a later edit can drop without touching this field.
        let claims = MfaTempClaims {
            iss: None,
            aud: None,
            sub: "u_1".to_owned(),
            jti: "jti-4".to_owned(),
            token_type: MfaTempType::MfaChallenge,
            context: MfaContext::Dashboard,
            tenant_id: Some("t_1".to_owned()),
            epoch: 0,
            iat: 1,
            exp: 2,
        };
        let json = serde_json::to_value(claims).unwrap_or_default();
        assert_eq!(json["tenantId"], "t_1");
        assert!(json.get("tenant_id").is_none());

        // And it round-trips from that name: a dashboard token minted by the other half must
        // arrive here with its tenant intact, not silently defaulted away.
        let parsed: Result<MfaTempClaims, _> = serde_json::from_value(json);
        assert!(matches!(parsed, Ok(c) if c.tenant_id.as_deref() == Some("t_1")));
    }

    #[test]
    fn mfa_temp_claims_carry_the_challenge_discriminator_and_context() {
        // The temp token's `type` is `mfa_challenge` and its `context` routes
        // persistence to the dashboard or platform store downstream.
        let claims = MfaTempClaims {
            iss: None,
            aud: None,
            sub: "u_1".to_owned(),
            jti: "jti-3".to_owned(),
            token_type: MfaTempType::MfaChallenge,
            context: MfaContext::Platform,
            tenant_id: None,
            epoch: 7,
            iat: 1,
            exp: 2,
        };
        let json = serde_json::to_value(claims).unwrap_or_default();
        assert_eq!(json["type"], "mfa_challenge");
        assert_eq!(json["context"], "platform");
        // The platform arm carries no tenant, and an absent one is absent on the wire rather
        // than a `null` the other implementation would have to special-case.
        assert!(json.get("tenantId").is_none());
        // The challenge token carries the epoch so a credential rotation kills it too.
        assert_eq!(json["epoch"], 7);
    }

    #[test]
    fn a_wrong_discriminator_fails_to_deserialize() {
        // The single-variant discriminator enums reject any other value, so a token
        // minted as a different `type` cannot be parsed into the wrong claim struct.
        let mut value = serde_json::to_value(dashboard_claims()).unwrap_or_default();
        value["type"] = serde_json::Value::String("platform".to_owned());
        let parsed = serde_json::from_value::<DashboardClaims>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn claims_round_trip_through_json() {
        // Lossless (de)serialization of each claim type so a signed-then-parsed token
        // recovers identical claims (the JWT codec depends on this in `bymax-auth-jwt`).
        let claims = dashboard_claims();
        let json = serde_json::to_string(&claims).unwrap_or_default();
        let back = serde_json::from_str::<DashboardClaims>(&json).ok();
        assert_eq!(back, Some(claims));
    }

    #[test]
    fn discriminator_enums_round_trip() {
        // Exercise each discriminator/context enum so the snake_case wire mapping is
        // covered end to end.
        for value in [
            serde_json::to_value(DashboardType::Dashboard).unwrap_or_default(),
            serde_json::to_value(PlatformType::Platform).unwrap_or_default(),
            serde_json::to_value(MfaTempType::MfaChallenge).unwrap_or_default(),
            serde_json::to_value(MfaContext::Dashboard).unwrap_or_default(),
        ] {
            assert!(value.is_string());
        }
        assert_eq!(
            serde_json::from_value::<MfaContext>(serde_json::json!("dashboard")).ok(),
            Some(MfaContext::Dashboard)
        );
    }

    #[test]
    fn the_epoch_claim_matches_the_shared_wire_contract() {
        // The `accessTokenClaims` section of `conformance/wire-contract.json` — held
        // byte-identical by nest-auth — is what makes bulk revocation work across both backends:
        // one side stamps the generation and the other rejects on it. Reading the declaration
        // rather than repeating it means a rename, a type change, or a flipped comparison on
        // either side turns that side red instead of quietly un-revoking tokens in production.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/wire-contract.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        let epoch = root
            .get("accessTokenClaims")
            .and_then(|c| c.get("epoch"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        assert!(
            epoch.is_object(),
            "the wire contract declared no `accessTokenClaims.epoch` — it did not load"
        );

        // The claim is spelled exactly as declared, and both planes stamp it.
        let name = epoch.get("claim").and_then(serde_json::Value::as_str);
        assert_eq!(name, Some("epoch"));
        let dashboard = serde_json::to_value(dashboard_claims()).unwrap_or_default();
        assert_eq!(dashboard.get("epoch"), Some(&serde_json::json!(3)));
        let platform = serde_json::to_value(PlatformClaims {
            iss: None,
            aud: None,
            sub: "p_1".to_owned(),
            jti: "jti-2".to_owned(),
            role: "super_admin".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: 1,
            exp: 2,
            epoch: 7,
        })
        .unwrap_or_default();
        assert_eq!(platform.get("epoch"), Some(&serde_json::json!(7)));

        // A non-negative integer on the wire: `u64` cannot go negative, and the JSON must carry
        // it as a bare number rather than a string a sibling reader would compare lexically.
        assert_eq!(
            epoch.get("type").and_then(serde_json::Value::as_str),
            Some("non-negative integer")
        );
        assert!(
            dashboard
                .get("epoch")
                .is_some_and(serde_json::Value::is_u64)
        );

        // The two rules a verifier implements. `absentReadsAs` is pinned by the legacy-token test
        // above; the rejection is strict `<`, so a token stamped AT the current generation still
        // verifies — an off-by-one here would log every user out on their first bump.
        assert_eq!(
            epoch.get("absentReadsAs"),
            Some(&serde_json::json!(0)),
            "an absent claim reading as anything but 0 would make the mechanism fire on legacy tokens"
        );
        assert_eq!(
            epoch.get("rejectWhen").and_then(serde_json::Value::as_str),
            Some("stampedEpoch < storedEpoch")
        );

        // The stored side of the contract: the key the generation is read back from.
        assert_eq!(
            epoch.get("storedUnder").and_then(serde_json::Value::as_str),
            Some("{ep|pep}:{userId}")
        );
    }
}
