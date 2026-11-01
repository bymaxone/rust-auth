//! The body of `POST /auth/ws-ticket` is the one the shared wire contract pins: exactly the keys
//! `responseBodies.wsTicket` lists, in both directions, with `expiresIn` the number of seconds the
//! ticket will actually live. Shares the fixtures of the parent test file.

use std::collections::BTreeSet;

use super::*;

/// The key set `responseBodies.wsTicket` names in the shared wire contract.
fn contract_keys() -> BTreeSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/wire-contract.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    root["responseBodies"]["wsTicket"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .filter_map(|key| key.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn the_mint_response_has_exactly_the_keys_the_shared_contract_lists() {
    let Some(h) = build(EngineSpec {
        mfa: true,
        ..EngineSpec::default()
    }) else {
        return;
    };
    let app = router(&h);
    let reg = Req::post("/auth/register")
        .json(serde_json::json!({
            "email": "wst@e.com", "password": "glidingwalnut42", "name": "Wst", "tenantId": TENANT
        }))
        .send(&app)
        .await;
    let access = reg.cookie_value("access_token").unwrap_or_default();

    let mint = Req::post("/auth/ws-ticket")
        .cookie("access_token", &access)
        .send(&app)
        .await;
    assert_eq!(mint.status, StatusCode::OK);

    let keys: BTreeSet<String> = mint
        .json()
        .as_object()
        .map(|body| body.keys().cloned().collect())
        .unwrap_or_default();
    assert!(
        !contract_keys().is_empty(),
        "the contract section was not read"
    );
    assert_eq!(
        keys,
        contract_keys(),
        "the body and responseBodies.wsTicket must be the same set"
    );

    // `expiresIn` is whole seconds, positive and no longer than the 30 s ceiling the contract
    // states for a ticket (`credentialFormats.wsTicket`).
    let expires_in = mint.json()["expiresIn"].as_u64().unwrap_or(0);
    assert!((1..=30).contains(&expires_in), "expiresIn {expires_in}");
}
