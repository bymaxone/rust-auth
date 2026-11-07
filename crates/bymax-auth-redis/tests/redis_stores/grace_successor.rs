//! The session a rotated refresh token was rotated into, read from its grace pointer: one `GET`
//! that neither consumes the pointer nor extends its window, and a value that names no
//! well-formed successor names nothing. A child module of the combined store suite, so it reuses
//! that suite's container harness and fixtures.

use super::*;

/// A 64-character lower-case hex hash made of `digit`, the shape a real session hash has.
fn hash_of(digit: char) -> String {
    digit.to_string().repeat(64)
}

#[tokio::test]
async fn a_rotated_token_names_its_successor_and_the_pointer_is_left_as_it_was() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    let (old, new) = (hash_of('a'), hash_of('b'));
    let created = stores
        .create_session(kind, &subject("gs"), &old, &record("gs"), 3600)
        .await;
    assert!(created.is_ok());
    assert!(matches!(
        stores.rotate(kind, &rotation(&old, &new, "gs")).await,
        Ok(RotateOutcome::Rotated(_))
    ));

    let key = format!("auth:rp:{old}");
    let ttl_before = redis.ttl(&key).await;
    assert!(ttl_before > 0, "the rotation wrote a pointer with a window");
    for _ in 0..2 {
        assert_eq!(
            stores.grace_successor(kind, &old).await.ok().flatten(),
            Some(new.clone())
        );
    }
    // Reading consumed nothing and extended nothing.
    assert!(redis.get(&key).await.is_some());
    assert!(redis.ttl(&key).await <= ttl_before);
}

#[tokio::test]
async fn a_hash_with_no_pointer_and_a_malformed_pointer_name_nothing() {
    let Some(redis) = common::try_start().await else {
        return;
    };
    let Some(stores) = redis.stores() else { return };
    let kind = SessionKind::Dashboard;
    assert!(matches!(
        stores.grace_successor(kind, &hash_of('c')).await,
        Ok(None)
    ));
    // A value with no colon, one whose first part is not a hash, and one in upper case.
    let malformed = [
        ("d", "no-colon-here".to_owned()),
        ("e", "not-a-hash:{}".to_owned()),
        ("f", format!("{}:{{}}", "B".repeat(64))),
    ];
    for (digit, value) in malformed {
        let hash = hash_of(digit.chars().next().unwrap_or('d'));
        assert!(redis.set_raw(&format!("auth:rp:{hash}"), &value).await);
        assert!(
            matches!(stores.grace_successor(kind, &hash).await, Ok(None)),
            "{value}"
        );
    }
}
