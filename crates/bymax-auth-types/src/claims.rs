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
    /// Issued-at (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub iat: i64,
    /// Expiry (seconds since the Unix epoch).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub exp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard_claims() -> DashboardClaims {
        DashboardClaims {
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
        }
    }

    #[test]
    fn dashboard_claims_emit_the_exact_wire_field_names() {
        // The discriminator is `type`, the tenant/MFA fields are camelCase, and BOTH
        // mfaEnabled and mfaVerified are present — the byte-level nest-auth contract.
        let json = serde_json::to_value(dashboard_claims()).unwrap_or_default();
        assert_eq!(json["type"], "dashboard");
        assert_eq!(json["tenantId"], "t_1");
        assert_eq!(json["mfaEnabled"], true);
        assert_eq!(json["mfaVerified"], false);
        assert_eq!(json["status"], "ACTIVE");
        assert!(
            json.get("token_type").is_none(),
            "raw field name must not leak"
        );
    }

    #[test]
    fn platform_claims_have_no_tenant_id() {
        // Platform tokens never carry a tenant scope; the field is absent by type.
        let claims = PlatformClaims {
            sub: "p_1".to_owned(),
            jti: "jti-2".to_owned(),
            role: "super_admin".to_owned(),
            token_type: PlatformType::Platform,
            mfa_enabled: false,
            mfa_verified: false,
            iat: 1,
            exp: 2,
        };
        let json = serde_json::to_value(claims).unwrap_or_default();
        assert_eq!(json["type"], "platform");
        assert!(json.get("tenantId").is_none());
        assert_eq!(json["mfaEnabled"], false);
    }

    #[test]
    fn mfa_temp_claims_carry_the_challenge_discriminator_and_context() {
        // The temp token's `type` is `mfa_challenge` and its `context` routes
        // persistence to the dashboard or platform store downstream.
        let claims = MfaTempClaims {
            sub: "u_1".to_owned(),
            jti: "jti-3".to_owned(),
            token_type: MfaTempType::MfaChallenge,
            context: MfaContext::Platform,
            iat: 1,
            exp: 2,
        };
        let json = serde_json::to_value(claims).unwrap_or_default();
        assert_eq!(json["type"], "mfa_challenge");
        assert_eq!(json["context"], "platform");
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
}
