//! Linking an OAuth identity is restricted to the tenant the write names.

use super::*;

#[tokio::test]
async fn linking_an_identity_is_restricted_to_the_named_tenant() {
    let repo = InMemoryUserRepository::new();
    let created = repo
        .create(CreateUserData {
            email: "link@example.com".to_owned(),
            name: "Link".to_owned(),
            password_hash: None,
            role: None,
            status: Some("ACTIVE".to_owned()),
            tenant_id: "t1".to_owned(),
            email_verified: Some(true),
        })
        .await;
    let Ok(user) = created else { return };

    // Another tenant naming this id changes nothing; its own tenant does.
    assert!(
        repo.link_oauth(&user.id, "t2", "google", "g-9")
            .await
            .is_ok()
    );
    assert!(matches!(
        repo.find_by_oauth_id("google", "g-9", "t1").await,
        Ok(None)
    ));
    assert!(
        repo.link_oauth(&user.id, "t1", "google", "g-9")
            .await
            .is_ok()
    );
    assert!(matches!(
        repo.find_by_oauth_id("google", "g-9", "t1").await,
        Ok(Some(_))
    ));
    assert_eq!(
        repo.link_calls(),
        [
            (user.id.clone(), "t2".to_owned()),
            (user.id, "t1".to_owned())
        ]
    );
}
