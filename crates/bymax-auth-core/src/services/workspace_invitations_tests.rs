//! The workspace invitation services: invite, resend, revoke, list and preview, with the role
//! ceiling, the limits, the answers that confirm nothing, a delivery that fails, and a record that
//! cannot be trusted (layer: service, tests).

use bymax_auth_types::AuthError;

use super::workspace::PageQuery;
use super::workspace_invitations::{InvitationPreview, WorkspaceInvitationView};
use super::workspace_invitations_support_tests::{
    Inv, Mode, Seeded, is_limited, key_of, place, seed, seed_bootstrap, setup, without_a_store,
};
use super::workspace_support_tests::{active, config, membership, seed_account};
use crate::services::auth::test_support::ctx;
use crate::testing::workspace_invitation_scenarios::InvitationStoreProbe;
use crate::traits::WorkspaceInvitationStore;
use crate::workspace::access::WorkspaceMember;
use crate::workspace::audit::AuditKind;
use crate::workspace::domain::MembershipStatus;

const LONG_AGO: &str = "2026-01-01T00:00:00.000Z";

/// Invites `email` as `role` on behalf of `inv`'s owner.
async fn owner_invites(inv: &Inv, email: &str, role: &str) -> Result<(), AuthError> {
    inv.f
        .engine
        .invite_workspace_member(&inv.owner, email, role, &ctx())
        .await
}

/// The token of the message the mailer sent last.
fn last_token(inv: &Inv) -> String {
    inv.mail
        .sent()
        .last()
        .map(|(_, _, data)| data.invite_token.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn an_owner_invites_an_address_and_the_mail_carries_the_token_of_the_stored_record() {
    let Some(inv) = setup(config()).await else { return };
    let invited = owner_invites(&inv, "  New@X.io ", "member").await;
    assert!(invited.is_ok(), "{invited:?}");
    let sent = inv.mail.sent();
    assert_eq!(sent.len(), 1);
    let (tenant, email, data) = &sent[0];
    assert_eq!((tenant.as_str(), email.as_str()), ("t1", "new@x.io"));
    assert_eq!(data.invite_token.len(), 64);
    assert_eq!(data.role, "member");
    assert_eq!(data.workspace_name, "Workspace w1");
    assert!(!data.account_exists);
    let stored = inv.store.read_record(&key_of(&data.invite_token)).await;
    let record = stored.ok().flatten();
    assert_eq!(record.as_ref().map(InvitationRecordExt::resends), Some(0));
    let indexed = inv.store.read_index(&place(&inv, "new@x.io")).await;
    let named = indexed.ok().flatten().map(|index| index.record_key);
    assert_eq!(named, Some(key_of(&data.invite_token)));
    let events = inv.f.hooks.events(1).await;
    assert!(matches!(
        events.first().map(|event| &event.kind),
        Some(AuditKind::MemberInvited { email, role }) if email == "new@x.io" && role == "member"
    ));
}

/// What the tests read of a record.
trait InvitationRecordExt {
    fn resends(&self) -> u64;
}

impl InvitationRecordExt for crate::workspace::invitation::InvitationRecord {
    fn resends(&self) -> u64 {
        self.base().resend_count
    }
}

#[tokio::test]
async fn the_role_ceiling_decides_who_may_invite_to_which_role() {
    let Some(inv) = setup(config()).await else { return };
    let ask = |who: &'static str, email: &'static str, role: &'static str| {
        let member = match who {
            "owner" => inv.owner.clone(),
            "admin" => inv.admin.clone(),
            _ => inv.member.clone(),
        };
        let engine = &inv.f.engine;
        async move {
            engine
                .invite_workspace_member(&member, email, role, &ctx())
                .await
        }
    };
    assert!(ask("owner", "a@x.io", "owner").await.is_ok());
    assert!(ask("owner", "b@x.io", "admin").await.is_ok());
    assert!(ask("admin", "c@x.io", "member").await.is_ok());
    for (who, email, role) in [
        ("admin", "d@x.io", "admin"),
        ("admin", "e@x.io", "owner"),
        ("member", "f@x.io", "member"),
    ] {
        let refused = ask(who, email, role).await;
        assert!(
            matches!(refused, Err(AuthError::InsufficientWorkspaceRole)),
            "{who} -> {role}: {refused:?}"
        );
    }
    let unknown = ask("owner", "g@x.io", "ghost").await;
    assert!(
        matches!(&unknown, Err(AuthError::Validation { details }) if details.iter().any(|d| d.field == "role")),
        "{unknown:?}"
    );
    assert_eq!(inv.mail.sent().len(), 3, "a refusal sends nothing");
}

#[tokio::test]
async fn an_address_with_a_membership_in_any_status_is_already_a_member() {
    let Some(inv) = setup(config()).await else { return };
    for (email, status) in [
        ("active@x.io", MembershipStatus::Active),
        ("suspended@x.io", MembershipStatus::Suspended),
    ] {
        let id = seed_account(&inv.f, "t1", email, false).await;
        let mut seat = active("t1", "w1", &id, "member");
        seat.status = status;
        inv.f.repo.seed_membership(membership(&seat, 9));
        let refused = owner_invites(&inv, email, "member").await;
        assert!(matches!(refused, Err(AuthError::AlreadyMember)), "{email}");
    }
    seed_account(&inv.f, "t1", "outsider@x.io", false).await;
    assert!(owner_invites(&inv, "outsider@x.io", "member").await.is_ok());
    let sent = inv.mail.sent();
    assert_eq!(sent.len(), 1, "only the outsider was mailed");
    assert!(
        sent[0].2.account_exists,
        "the provider is told the account exists"
    );
}

#[tokio::test]
async fn an_account_of_another_tenant_is_neither_a_member_nor_an_account() {
    let Some(inv) = setup(config()).await else { return };
    seed_account(&inv.f, "t2", "elsewhere@x.io", false).await;
    assert!(
        owner_invites(&inv, "elsewhere@x.io", "member")
            .await
            .is_ok()
    );
    assert!(!inv.mail.sent()[0].2.account_exists);
}

#[tokio::test]
async fn inviting_an_invited_address_again_is_held_to_the_cooldown_and_the_resend_limit() {
    let Some(inv) = setup(config()).await else { return };
    assert!(owner_invites(&inv, "again@x.io", "member").await.is_ok());
    let at_once = owner_invites(&inv, "Again@x.io", "member").await;
    assert!(is_limited(&at_once), "inside the cooldown: {at_once:?}");
    assert_eq!(inv.mail.sent().len(), 1);
    let spent = Seeded {
        email: "spent@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 5,
    };
    seed(&inv, "spent-token", &spent).await;
    let past_the_limit = owner_invites(&inv, "spent@x.io", "member").await;
    assert!(is_limited(&past_the_limit), "{past_the_limit:?}");
    let last_allowed = Seeded {
        resends: 4,
        ..spent
    };
    let old_key = seed(
        &inv,
        "fresh-token",
        &Seeded {
            email: "fourth@x.io",
            ..last_allowed
        },
    )
    .await;
    assert!(owner_invites(&inv, "fourth@x.io", "admin").await.is_ok());
    let token = last_token(&inv);
    let record = inv.store.read_record(&key_of(&token)).await.ok().flatten();
    assert_eq!(record.as_ref().map(InvitationRecordExt::resends), Some(5));
    assert_eq!(
        record.map(|r| r.base().role.clone()),
        Some("admin".to_owned())
    );
    let retired = inv.store.read_record(&old_key).await.ok().flatten();
    assert!(retired.is_none(), "the replaced record is retired");
}

#[tokio::test]
async fn an_inviter_has_twenty_invitations_an_hour() {
    let Some(inv) = setup(config()).await else { return };
    for n in 0..20 {
        let sent = owner_invites(&inv, &format!("p{n}@x.io"), "member").await;
        assert!(sent.is_ok(), "{n}: {sent:?}");
    }
    let twenty_first = owner_invites(&inv, "p20@x.io", "member").await;
    assert!(is_limited(&twenty_first), "{twenty_first:?}");
    assert_eq!(inv.mail.sent().len(), 20);
}

#[tokio::test]
async fn the_pending_cap_refuses_a_first_invitation_and_lets_a_replacement_through() {
    let mut capped = config();
    capped.workspaces.max_pending_invitations_per_workspace = 1;
    let Some(inv) = setup(capped).await else { return };
    let old = Seeded {
        email: "a@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "a-token", &old).await;
    let first = owner_invites(&inv, "b@x.io", "member").await;
    assert!(
        is_limited(&first),
        "a first invitation at the cap: {first:?}"
    );
    assert!(
        owner_invites(&inv, "a@x.io", "member").await.is_ok(),
        "a replacement"
    );
}

async fn resends_ok(inv: &Inv, who: &WorkspaceMember, email: &str) -> bool {
    let engine = &inv.f.engine;
    let resent = engine.resend_workspace_invitation(who, email, &ctx()).await;
    resent.is_ok()
}

async fn revokes_ok(inv: &Inv, who: &WorkspaceMember, email: &str) -> bool {
    let engine = &inv.f.engine;
    let revoked = engine.revoke_workspace_invitation(who, email, &ctx()).await;
    revoked.is_ok()
}

#[tokio::test]
async fn resend_and_revoke_change_nothing_for_an_address_with_no_invitation() {
    let Some(inv) = setup(config()).await else { return };
    assert!(resends_ok(&inv, &inv.owner, "none@x.io").await);
    assert!(revokes_ok(&inv, &inv.owner, "none@x.io").await);
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn resend_and_revoke_change_nothing_for_an_invitation_above_the_actor_and_the_owner_revokes_it()
 {
    let Some(inv) = setup(config()).await else { return };
    let above = Seeded {
        email: "boss@x.io",
        role: "admin",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    let key = seed(&inv, "boss-token", &above).await;
    assert!(resends_ok(&inv, &inv.admin, "boss@x.io").await);
    assert!(revokes_ok(&inv, &inv.admin, "boss@x.io").await);
    assert!(inv.store.read_record(&key).await.ok().flatten().is_some());
    assert!(inv.mail.sent().is_empty());
    assert!(revokes_ok(&inv, &inv.owner, "boss@x.io").await);
    assert!(inv.store.read_record(&key).await.ok().flatten().is_none());
    let events = inv.f.hooks.events(1).await;
    assert!(matches!(
        events.first().map(|event| &event.kind),
        Some(AuditKind::InvitationRevoked { email, role }) if email == "boss@x.io" && role == "admin"
    ));
}

#[tokio::test]
async fn a_resend_mints_a_new_token_and_reports_a_resend() {
    let Some(inv) = setup(config()).await else { return };
    let old = Seeded {
        email: "r@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 1,
    };
    let old_key = seed(&inv, "r-token", &old).await;
    let resent = inv
        .f
        .engine
        .resend_workspace_invitation(&inv.admin, "R@x.io", &ctx())
        .await;
    assert!(resent.is_ok(), "{resent:?}");
    let token = last_token(&inv);
    let record = inv.store.read_record(&key_of(&token)).await.ok().flatten();
    assert_eq!(record.as_ref().map(InvitationRecordExt::resends), Some(2));
    assert!(
        inv.store
            .read_record(&old_key)
            .await
            .ok()
            .flatten()
            .is_none()
    );
    let events = inv.f.hooks.events(1).await;
    assert!(matches!(
        events.first().map(|event| &event.kind),
        Some(AuditKind::InvitationResent { email, .. }) if email == "r@x.io"
    ));
}

#[tokio::test]
async fn an_index_over_a_value_that_is_not_a_record_is_an_internal_error_never_a_cooldown_that_ended()
 {
    let Some(inv) = setup(config()).await else { return };
    let engine = &inv.f.engine;
    let garbage = [
        ("not json", "not a record".to_owned()),
        (
            "an invalid creation time",
            r#"{"email":"u@x.io","role":"member","tenantId":"t1","workspaceId":"w1","createdAt":"garbage","resendCount":0,"kind":"member","inviterUserId":"u"}"#.to_owned(),
        ),
    ];
    for (n, (why, raw)) in garbage.into_iter().enumerate() {
        let email = format!("u{n}@x.io");
        let key = key_of(&format!("g{n}"));
        inv.store
            .plant_raw_record(&key, &raw, std::time::Duration::from_secs(600))
            .await;
        inv.store
            .point_index(
                &place(&inv, &email),
                &key,
                std::time::Duration::from_secs(600),
            )
            .await;
        let invited = owner_invites(&inv, &email, "member").await;
        let resent = engine
            .resend_workspace_invitation(&inv.owner, &email, &ctx())
            .await;
        let revoked = engine
            .revoke_workspace_invitation(&inv.owner, &email, &ctx())
            .await;
        assert!(
            matches!(invited, Err(AuthError::Internal(_))),
            "{why}: {invited:?}"
        );
        assert!(
            matches!(resent, Err(AuthError::Internal(_))),
            "{why}: {resent:?}"
        );
        assert!(revoked.is_ok(), "{why}: revoke has nothing to act on");
    }
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn a_creation_time_in_the_future_counts_as_inside_the_cooldown() {
    let Some(inv) = setup(config()).await else { return };
    let future = Seeded {
        email: "f@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: "2999-01-01T00:00:00.000Z",
        resends: 0,
    };
    seed(&inv, "f-token", &future).await;
    let resent = inv
        .f
        .engine
        .resend_workspace_invitation(&inv.owner, "f@x.io", &ctx())
        .await;
    assert!(is_limited(&resent), "{resent:?}");
}

#[tokio::test]
async fn a_delivery_failure_carries_no_text_of_the_provider_and_leaves_the_record_published() {
    let Some(inv) = setup(config()).await else { return };
    inv.mail.act(Mode::RelayQuotesTheToken);
    let failed = owner_invites(&inv, "d@x.io", "member").await;
    let shown = format!("{failed:?}");
    assert!(matches!(failed, Err(AuthError::Internal(_))), "{shown}");
    assert!(!shown.contains("relay rejected"), "{shown}");
    let indexed = inv
        .store
        .read_index(&place(&inv, "d@x.io"))
        .await
        .ok()
        .flatten();
    assert!(
        indexed.is_some_and(|index| index.record.is_some()),
        "the record stays"
    );
    let token_in_error = indexed_token_in(&shown);
    assert!(!token_in_error, "no 64-character token in {shown}");
}

/// Whether `text` holds a run of 64 hex characters, which is what a token looks like.
fn indexed_token_in(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        run = if byte.is_ascii_hexdigit() { run + 1 } else { 0 };
        if run >= 64 {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn a_provider_without_workspace_invitations_surfaces_as_an_error_not_a_success() {
    let Some(inv) = setup(config()).await else { return };
    inv.mail.act(Mode::Unsupported);
    let result = owner_invites(&inv, "u@x.io", "member").await;
    assert!(matches!(result, Err(AuthError::Internal(_))), "{result:?}");
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn the_invitation_methods_answer_an_internal_error_when_no_store_was_configured() {
    let Some(f) = without_a_store(config()) else { return };
    let member = super::workspace_support_tests::acting_member("t1", "w1", "u", "owner");
    let invited = f
        .engine
        .invite_workspace_member(&member, "a@x.io", "member", &ctx())
        .await;
    let listed = f
        .engine
        .list_workspace_invitations(&member, PageQuery::default())
        .await;
    let previewed = f.engine.preview_workspace_invitation("token").await;
    for answer in [invited.err(), listed.err(), previewed.err()] {
        assert!(matches!(answer, Some(AuthError::Internal(_))), "{answer:?}");
    }
}

async fn page(
    inv: &Inv,
    cursor: Option<&str>,
    limit: &str,
) -> Result<crate::workspace::domain::Page<WorkspaceInvitationView>, AuthError> {
    let query = PageQuery {
        cursor,
        limit: Some(limit),
    };
    inv.f
        .engine
        .list_workspace_invitations(&inv.admin, query)
        .await
}

#[tokio::test]
async fn the_list_is_oldest_first_and_in_pages() {
    let Some(inv) = setup(config()).await else { return };
    let dates = [
        "2026-02-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000Z",
        "2026-03-01T00:00:00.000Z",
    ];
    for (n, at) in dates.into_iter().enumerate() {
        let email = format!("l{n}@x.io");
        let item = Seeded {
            email: &email,
            role: "member",
            inviter: &inv.owner.user_id,
            created_at: at,
            resends: 0,
        };
        seed(&inv, &format!("l-token-{n}"), &item).await;
    }
    let Ok(first) = page(&inv, None, "2").await else { return };
    let emails: Vec<_> = first.items.iter().map(|view| view.email.as_str()).collect();
    assert_eq!(emails, ["l1@x.io", "l0@x.io"], "oldest first");
    assert_eq!(first.items[0].inviter_user_id, inv.owner.user_id);
    assert!(first.next_cursor.is_some());
    let Ok(second) = page(&inv, first.next_cursor.as_deref(), "2").await else { return };
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.next_cursor, None);
}

#[tokio::test]
async fn a_page_size_outside_its_bounds_is_refused() {
    let Some(inv) = setup(config()).await else { return };
    for limit in ["0", "101", "ten"] {
        let bad = page(&inv, None, limit).await;
        assert!(matches!(bad, Err(AuthError::Validation { .. })), "{limit}");
    }
}

async fn previewed(inv: &Inv, token: &str) -> Result<InvitationPreview, AuthError> {
    inv.f.engine.preview_workspace_invitation(token).await
}

#[tokio::test]
async fn a_preview_names_a_member_invitation() {
    let Some(inv) = setup(config()).await else { return };
    seed_account(&inv.f, "t1", "known@x.io", false).await;
    let item = Seeded {
        email: "known@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "good-token", &item).await;
    assert_eq!(
        previewed(&inv, "good-token").await.ok(),
        Some(InvitationPreview::Member {
            workspace_name: "Workspace w1".to_owned(),
            inviter_name: "Member".to_owned(),
            role: "member".to_owned(),
            masked_email: crate::normalize::mask_email("known@x.io"),
            account_exists: true,
        })
    );
}

#[tokio::test]
async fn every_token_that_cannot_be_previewed_is_the_same_error() {
    let Some(inv) = setup(config()).await else { return };
    let item = Seeded {
        email: "x@x.io",
        role: "member",
        inviter: "nobody",
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "no-inviter-token", &item).await;
    let live = Seeded {
        inviter: &inv.owner.user_id,
        ..item
    };
    seed(
        &inv,
        "pending-token",
        &Seeded {
            email: "y@x.io",
            ..live
        },
    )
    .await;
    for token in ["never-existed", "no-inviter-token"] {
        let refused = previewed(&inv, token).await;
        assert!(
            matches!(refused, Err(AuthError::InvalidInvitationToken)),
            "{token}"
        );
    }
    inv.f
        .repo
        .seed_workspace(super::workspace_support_tests::workspace(
            "t1",
            "w1",
            crate::workspace::domain::WorkspaceStatus::PendingDeletion,
            1,
        ));
    let refused = previewed(&inv, "pending-token").await;
    assert!(matches!(refused, Err(AuthError::InvalidInvitationToken)));
}

#[tokio::test]
async fn a_bootstrap_token_previews_while_its_workspace_does_not_exist_and_not_once_it_is_not_active()
 {
    let Some(inv) = setup(config()).await else { return };
    seed_bootstrap(&inv, "boot-token", ("owner-to-be@x.io", "wb", "owner")).await;
    let previewed = inv
        .f
        .engine
        .preview_workspace_invitation("boot-token")
        .await;
    assert_eq!(
        previewed.ok(),
        Some(InvitationPreview::Bootstrap {
            workspace_name: "Acme Inc".to_owned(),
            role: "owner".to_owned(),
            masked_email: crate::normalize::mask_email("owner-to-be@x.io"),
            account_exists: false,
        })
    );
    inv.f
        .repo
        .seed_workspace(super::workspace_support_tests::workspace(
            "t1",
            "wb",
            crate::workspace::domain::WorkspaceStatus::PendingDeletion,
            1,
        ));
    let refused = inv
        .f
        .engine
        .preview_workspace_invitation("boot-token")
        .await;
    assert!(
        matches!(refused, Err(AuthError::InvalidInvitationToken)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_list_leaves_bootstrap_invitations_out() {
    let Some(inv) = setup(config()).await else { return };
    let member = Seeded {
        email: "m@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "m-token", &member).await;
    let bootstrap = seed_bootstrap(&inv, "b-token", ("b@x.io", "w1", "owner")).await;
    let listed = inv
        .f
        .engine
        .list_workspace_invitations(&inv.owner, PageQuery::default())
        .await;
    let emails: Vec<String> = listed
        .map(|page| page.items.into_iter().map(|v| v.email).collect())
        .unwrap_or_default();
    assert_eq!(emails, ["m@x.io"], "bootstrap {bootstrap} is not listed");
}

#[tokio::test]
async fn a_token_whose_role_the_hierarchy_does_not_know_or_a_bootstrap_that_is_not_the_owner_is_invalid()
 {
    let Some(inv) = setup(config()).await else { return };
    let ghost = Seeded {
        email: "g@x.io",
        role: "ghost",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "ghost-token", &ghost).await;
    seed_bootstrap(&inv, "admin-boot", ("a@x.io", "wb", "admin")).await;
    seed_bootstrap(&inv, "unknown-boot", ("u@x.io", "wb2", "ghost")).await;
    for token in ["ghost-token", "admin-boot", "unknown-boot"] {
        let refused = inv.f.engine.preview_workspace_invitation(token).await;
        assert!(
            matches!(refused, Err(AuthError::InvalidInvitationToken)),
            "{token}: {refused:?}"
        );
    }
}
