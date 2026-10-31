//! Structural guard of a stored invitation: each malformed operand is refused on its own, even when the inviter vouches for the record.

use super::*;

/// Store `invitation` under a fresh token, with an inviter who passes every later check
/// for exactly that record (same tenant, holding the invited role), then accept it.
/// Only the structural guard can refuse such a record, so the outcome isolates it.
async fn accept_with_an_otherwise_valid_inviter(
    s: &Setup,
    slot: u8,
    email: &str,
    tenant_id: &str,
    role: &str,
) -> Result<(), AuthError> {
    let created = s
        .users
        .create(CreateUserData {
            email: format!("inviter{slot}@example.com"),
            name: "Inviter".to_owned(),
            password_hash: Some("$scrypt$x".to_owned()),
            role: Some(role.to_owned()),
            status: Some("ACTIVE".to_owned()),
            tenant_id: tenant_id.to_owned(),
            email_verified: Some(true),
        })
        .await
        // A seeding failure must not look like the refusal under test, so it surfaces as
        // a different variant.
        .map_err(|_| AuthError::InsufficientRole)?;
    let token = format!("{}{slot}", "d".repeat(63));
    s.stores
        .put_invitation(
            &token,
            &StoredInvitation {
                email: email.to_owned(),
                role: role.to_owned(),
                tenant_id: tenant_id.to_owned(),
                inviter_user_id: created.id,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            600,
        )
        .await?;
    s.engine
        .accept_invitation(
            AcceptInvitationInput {
                token,
                name: "N".to_owned(),
                password: "glidingwalnut42".to_owned(),
            },
            "1.2.3.4",
            "agent",
            BTreeMap::new(),
        )
        .await
        .map(|_| ())
}

#[tokio::test]
async fn each_structural_operand_alone_refuses_an_invitation_a_valid_inviter_vouches_for() {
    // The inviter re-check and the duplicate guard downstream refuse most malformed
    // records on their own, which hides an `||` that became an `&&` in the structural
    // guard. Here the inviter matches the record in every respect, so an empty address,
    // an empty tenant and an undeclared role are each refused by the structural guard
    // alone — and a well-formed record is accepted, so the guard refuses the defect
    // rather than the flow.
    let Some(s) = setup(invite_config()) else { return };
    s.users.ignore_tenant_on_id();

    let valid = accept_with_an_otherwise_valid_inviter(&s, 0, "ok@example.com", "t1", "ADMIN");
    assert!(valid.await.is_ok());

    let no_email = accept_with_an_otherwise_valid_inviter(&s, 1, "", "t1", "ADMIN").await;
    assert!(matches!(no_email, Err(AuthError::InvalidInvitationToken)));

    let no_tenant =
        accept_with_an_otherwise_valid_inviter(&s, 2, "b@example.com", "", "ADMIN").await;
    assert!(matches!(no_tenant, Err(AuthError::InvalidInvitationToken)));

    let ghost_role =
        accept_with_an_otherwise_valid_inviter(&s, 3, "c@example.com", "t1", "GHOST").await;
    assert!(matches!(ghost_role, Err(AuthError::InvalidInvitationToken)));
}
