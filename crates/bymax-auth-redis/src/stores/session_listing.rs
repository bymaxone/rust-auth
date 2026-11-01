//! Reading one session-detail record for a listing: which members surface and which are left out.
//!
//! Layer: a pure helper of the session store, kept apart from the Redis calls so the decision is
//! testable without a server.

use bymax_auth_core::traits::SessionDetail;

use super::session::SessionDetailValue;

/// What reading one `sd:`/`psd:` record means for the listing.
#[derive(Debug, PartialEq)]
pub(super) enum DetailRead {
    /// A well-formed record: the session is listed.
    Listed(SessionDetail),
    /// Absent, or present but not a whole detail record. The session is left out of the listing;
    /// whether its index member is also dead is a separate question that only the `rt:` key
    /// answers, because a live session whose detail was lost or damaged is still a session.
    Excluded,
}

/// Interpret the raw `sd:`/`psd:` value stored for the session `hash`.
///
/// A record that fails to parse is excluded rather than failing the whole listing: one corrupt
/// or foreign-written value must not hide every other session of the account.
pub(super) fn read_detail(hash: &str, raw: Option<&str>) -> DetailRead {
    let Some(raw) = raw else { return DetailRead::Excluded };
    match serde_json::from_str::<SessionDetailValue>(raw) {
        Ok(value) => DetailRead::Listed(SessionDetail {
            session_hash: hash.to_owned(),
            device: value.device,
            ip: value.ip,
            created_at: value.created_at,
            last_activity_at: value.last_activity_at,
        }),
        Err(_) => DetailRead::Excluded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed stored detail value.
    fn valid(device: &str) -> String {
        format!(
            r#"{{"device":"{device}","ip":"1.2.3.4","createdAt":1700000000000,"lastActivityAt":1700000001000}}"#
        )
    }

    #[test]
    fn a_well_formed_record_is_listed_under_its_hash() {
        let read = read_detail("h1", Some(&valid("Firefox")));
        assert!(matches!(&read, DetailRead::Listed(d)
            if d.session_hash == "h1" && d.device == "Firefox" && d.ip == "1.2.3.4"));
    }

    #[test]
    fn an_absent_record_is_excluded() {
        assert_eq!(read_detail("h1", None), DetailRead::Excluded);
    }

    #[test]
    fn a_record_that_is_not_a_whole_detail_is_excluded() {
        for raw in [
            "",
            "not json",
            "null",
            "[]",
            "{}",
            r#"{"device":"x","ip":"1.2.3.4","createdAt":"1","lastActivityAt":2}"#,
            r#"{"device":1,"ip":"1.2.3.4","createdAt":1,"lastActivityAt":2}"#,
            r#"{"device":"x","ip":"1.2.3.4","createdAt":1}"#,
        ] {
            assert_eq!(read_detail("h", Some(raw)), DetailRead::Excluded, "{raw:?}");
        }
    }

    #[test]
    fn one_corrupt_record_among_many_still_lists_the_others() {
        let hashes = ["a", "b", "c", "d", "e"];
        let stored = [
            Some(valid("A")),
            Some(valid("B")),
            Some("{broken".to_owned()),
            Some(valid("D")),
            Some(valid("E")),
        ];
        let listed: Vec<String> = hashes
            .iter()
            .zip(&stored)
            .filter_map(|(hash, raw)| match read_detail(hash, raw.as_deref()) {
                DetailRead::Listed(detail) => Some(detail.session_hash),
                DetailRead::Excluded => None,
            })
            .collect();
        assert_eq!(listed, ["a", "b", "d", "e"]);
    }
}
