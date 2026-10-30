//! Wire-format tests for the optional second-factor flag of the refresh-session record: it is
//! named as an optional field by the shared wire contract, written only when `true`, and read
//! strictly. Shares the fixtures (`session_record`, `contract_section`) of the parent test module.

use super::*;

#[test]
fn the_second_factor_flag_is_optional_on_the_wire_and_written_only_when_true()
-> serde_json::Result<()> {
    // The contract names `mfaVerified` as an optional field of the refresh record. A record
    // that never cleared the challenge must stay byte-identical to what it was before the
    // field existed, so `false` is omitted rather than written.
    let optional: Vec<String> = contract_section("refreshSession")
        .get("optionalFields")
        .and_then(serde_json::Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(optional, vec!["mfaVerified".to_owned()]);

    let unverified: serde_json::Value = serde_json::to_value(session_record())?;
    assert!(unverified.get("mfaVerified").is_none());

    let verified = SessionRecord {
        mfa_verified: true,
        ..session_record()
    };
    let verified: serde_json::Value = serde_json::to_value(verified)?;
    assert_eq!(
        verified.get("mfaVerified"),
        Some(&serde_json::Value::Bool(true))
    );
    Ok(())
}

#[test]
fn the_second_factor_flag_is_read_strictly() -> serde_json::Result<()> {
    // Only the JSON boolean `true` is verified. An absent field (a legacy record) and every
    // other value read as false, and none of them fails the record, which would cost the
    // holder a login for a value that was never going to be granted anything.
    let base = serde_json::to_value(session_record())?;
    let read = |value: Option<serde_json::Value>| -> serde_json::Result<bool> {
        let mut record = base.clone();
        if let (Some(object), Some(value)) = (record.as_object_mut(), value) {
            object.insert("mfaVerified".to_owned(), value);
        }
        Ok(serde_json::from_value::<SessionRecord>(record)?.mfa_verified)
    };

    assert!(read(Some(serde_json::json!(true)))?);
    assert!(!read(None)?);
    assert!(!read(Some(serde_json::json!(false)))?);
    assert!(!read(Some(serde_json::json!("true")))?);
    assert!(!read(Some(serde_json::json!(1)))?);
    assert!(!read(Some(serde_json::Value::Null))?);
    assert!(!read(Some(serde_json::json!([true])))?);
    Ok(())
}
