//! Wire-format tests for the optional `sid` of the WebSocket ticket record: named as an optional
//! field by the shared wire contract, written only when the minting token carried one, and read
//! so that a value that does not conform leaves the record a ticket. Shares the
//! `contract_section` fixture of the parent test module.

use super::*;

const SID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

fn ticket() -> serde_json::Value {
    serde_json::json!({
        "sub": "u1", "tenantId": "t1", "role": "MEMBER", "status": "ACTIVE",
        "mfaEnabled": false, "mfaVerified": false, "jti": "jti-1", "epoch": 0,
    })
}

#[test]
fn the_session_id_is_an_optional_field_written_only_when_there_is_one() -> serde_json::Result<()> {
    assert_eq!(
        contract_section("wsTicket").get("optionalFields"),
        Some(&serde_json::json!(["sid"]))
    );

    let bare: WsTicketSnapshot = serde_json::from_value(ticket())?;
    assert_eq!(bare.sid, None);
    assert!(serde_json::to_value(&bare)?.get("sid").is_none());

    let named = WsTicketSnapshot {
        sid: Some(SID.to_owned()),
        ..bare
    };
    assert_eq!(
        serde_json::to_value(named)?.get("sid"),
        Some(&serde_json::json!(SID))
    );
    Ok(())
}

#[test]
fn a_session_id_that_does_not_conform_reads_as_absent() -> serde_json::Result<()> {
    let read = |value: serde_json::Value| -> serde_json::Result<Option<String>> {
        let mut record = ticket();
        record["sid"] = value;
        Ok(serde_json::from_value::<WsTicketSnapshot>(record)?.sid)
    };
    for bad in [
        serde_json::Value::Null,
        serde_json::json!(7),
        serde_json::json!("a:b"),
        serde_json::json!(""),
    ] {
        assert_eq!(read(bad.clone())?, None, "{bad}");
    }
    assert_eq!(read(serde_json::json!(SID))?.as_deref(), Some(SID));
    Ok(())
}
