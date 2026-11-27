//! The workspace invitation services: invite, resend, revoke, list and preview, with the role
//! ceiling, the limits, the answers that confirm nothing, a delivery that fails, and a record that
//! cannot be trusted (layer: service, tests).

use bymax_auth_types::AuthError;

use super::workspace::PageQuery;
use super::workspace_invitations_support_tests::{
    Inv, Mode, Seeded, is_limited, key_of, place, seed, setup, without_a_store,
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(capped).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
    assert!(resends_ok(&inv, &inv.owner, "none@x.io").await);
    assert!(revokes_ok(&inv, &inv.owner, "none@x.io").await);
    assert!(inv.mail.sent().is_empty());
    let events = inv.f.hooks.events(0).await;
    assert!(events.is_empty(), "nothing was removed: {events:?}");
}

#[tokio::test]
async fn resend_and_revoke_change_nothing_for_an_invitation_above_the_actor_and_the_owner_revokes_it()
 {
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let events = inv.f.hooks.events(0).await;
    assert!(events.is_empty(), "nothing was removed: {events:?}");
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
    inv.mail.act(Mode::Unsupported);
    let result = owner_invites(&inv, "u@x.io", "member").await;
    assert!(matches!(result, Err(AuthError::Internal(_))), "{result:?}");
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn the_invitation_methods_answer_an_internal_error_when_no_store_was_configured() {
    let Some(f) = without_a_store(config()) else { unreachable!() };
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

#[tokio::test]
async fn an_invitation_over_a_live_one_to_a_role_above_the_actor_is_refused() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let above = Seeded {
        email: "up@x.io",
        role: "admin",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    seed(&inv, "up-token", &above).await;
    let refused = inv
        .f
        .engine
        .invite_workspace_member(&inv.admin, "up@x.io", "member", &ctx())
        .await;
    assert!(
        matches!(refused, Err(AuthError::InsufficientWorkspaceRole)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_blank_address_is_a_validation_error_naming_email() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let refused = owner_invites(&inv, "   ", "member").await;
    assert!(
        matches!(&refused, Err(AuthError::Validation { details }) if details.iter().any(|d| d.field == "email")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_invitation_to_a_workspace_that_is_not_active_is_not_found() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    inv.f
        .repo
        .seed_workspace(super::workspace_support_tests::workspace(
            "t1",
            "w1",
            crate::workspace::domain::WorkspaceStatus::PendingDeletion,
            1,
        ));
    let refused = owner_invites(&inv, "nobody@x.io", "member").await;
    assert!(
        matches!(refused, Err(AuthError::WorkspaceNotFound)),
        "{refused:?}"
    );
    assert!(inv.mail.sent().is_empty());
}

#[tokio::test]
async fn a_stored_record_with_no_valid_creation_time_is_never_trusted_for_a_cooldown() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let Some(runtime) = inv.f.engine.workspaces() else { unreachable!() };
    let record = crate::workspace::invitation::InvitationRecord::Member {
        base: crate::workspace::invitation::InvitationBase {
            email: "t@x.io".to_owned(),
            role: "member".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: "not a time".to_owned(),
            resend_count: 0,
        },
        inviter_user_id: "u".to_owned(),
    };
    let refused = runtime.assert_may_reissue("owner", &record, time::OffsetDateTime::now_utc());
    assert!(
        matches!(refused, Err(AuthError::Internal(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_member_with_a_blank_workspace_id_is_a_validation_error_naming_it() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let blank = super::workspace_support_tests::acting_member("t1", "", "u", "owner");
    let refused = inv
        .f
        .engine
        .invite_workspace_member(&blank, "a@x.io", "member", &ctx())
        .await;
    assert!(
        matches!(&refused, Err(AuthError::Validation { details }) if details.iter().any(|d| d.field == "workspaceId")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_revoke_from_another_tenant_leaves_the_invitation_of_the_same_workspace_id() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let pending = Seeded {
        email: "a@x.io",
        role: "member",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    let key = seed(&inv, "tenant-token", &pending).await;
    let stranger = super::workspace_support_tests::acting_member("t2", "w1", "u", "owner");
    assert!(revokes_ok(&inv, &stranger, "a@x.io").await);
    assert!(inv.store.read_record(&key).await.ok().flatten().is_some());
}

/// An invitation issued `age_seconds` before `now`, as a record the reissue check reads.
fn issued_ago(
    age_seconds: i64,
    now: time::OffsetDateTime,
) -> crate::workspace::invitation::InvitationRecord {
    let at = now - time::Duration::seconds(age_seconds);
    crate::workspace::invitation::InvitationRecord::Member {
        base: crate::workspace::invitation::InvitationBase {
            email: "c@x.io".to_owned(),
            role: "member".to_owned(),
            tenant_id: "t1".to_owned(),
            workspace_id: "w1".to_owned(),
            created_at: crate::workspace::audit::iso_instant(at),
            resend_count: 0,
        },
        inviter_user_id: "u".to_owned(),
    }
}

#[tokio::test]
async fn the_cooldown_is_sixty_seconds_and_ends_on_the_sixtieth() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let Some(runtime) = inv.f.engine.workspaces() else { unreachable!() };
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(time::OffsetDateTime::now_utc());
    for (age, limited) in [(0, true), (30, true), (59, true), (60, false), (61, false)] {
        let checked = runtime.assert_may_reissue("owner", &issued_ago(age, now), now);
        assert_eq!(
            is_limited(&checked),
            limited,
            "an invitation {age} s old: {checked:?}"
        );
    }
}

#[tokio::test]
async fn a_resend_tells_the_provider_whether_the_address_has_an_account() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    seed_account(&inv.f, "t1", "has@x.io", false).await;
    for email in ["has@x.io", "hasnt@x.io"] {
        let old = Seeded {
            email,
            role: "member",
            inviter: &inv.owner.user_id,
            created_at: LONG_AGO,
            resends: 0,
        };
        seed(&inv, &format!("{email}-old"), &old).await;
        assert!(resends_ok(&inv, &inv.owner, email).await);
    }
    let sent = inv.mail.sent();
    let flags: Vec<_> = sent
        .iter()
        .map(|(_, email, data)| (email.as_str(), data.account_exists))
        .collect();
    assert_eq!(flags, [("has@x.io", true), ("hasnt@x.io", false)]);
}

#[tokio::test]
async fn an_invitation_expires_the_configured_lifetime_after_it_was_issued() {
    let mut configured = config();
    configured.workspaces.invitation_ttl_seconds = 3_600;
    let Some(inv) = setup(configured).await else { unreachable!() };
    let before = time::OffsetDateTime::now_utc();
    assert!(owner_invites(&inv, "ttl@x.io", "member").await.is_ok());
    let sent = inv.mail.sent();
    let Some((_, _, data)) = sent.first() else { unreachable!() };
    let lifetime = data.expires_at - before;
    assert!(
        lifetime >= time::Duration::seconds(3_599) && lifetime <= time::Duration::seconds(3_601),
        "expires {lifetime} after it was issued"
    );
}

#[tokio::test]
async fn the_fixture_engine_builds_with_the_invitation_store_so_no_test_returns_early_without_one()
{
    let inv = setup(config()).await;
    assert!(
        inv.is_some(),
        "the engine did not build with the store the builder was given"
    );
    let Some(inv) = inv else { unreachable!() };
    assert!(owner_invites(&inv, "built@x.io", "member").await.is_ok());
    assert_eq!(inv.mail.sent().len(), 1);
}

#[tokio::test]
async fn blank_invitations_take_no_hourly_slot_from_the_inviter() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    for _ in 0..20 {
        let refused = owner_invites(&inv, "   ", "member").await;
        assert!(
            matches!(refused, Err(AuthError::Validation { .. })),
            "{refused:?}"
        );
    }
    let invited = owner_invites(&inv, "ok@x.io", "member").await;
    assert!(invited.is_ok(), "{invited:?}");
}

#[tokio::test]
async fn an_owner_resend_of_a_role_the_hierarchy_no_longer_knows_mails_nothing_and_revoke_still_works()
 {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let ghost = Seeded {
        email: "ghost@x.io",
        role: "ghost",
        inviter: &inv.owner.user_id,
        created_at: LONG_AGO,
        resends: 0,
    };
    let key = seed(&inv, "ghost-token", &ghost).await;
    assert!(resends_ok(&inv, &inv.owner, "ghost@x.io").await);
    assert!(
        inv.mail.sent().is_empty(),
        "no mail for a role nobody can accept"
    );
    assert!(inv.store.read_record(&key).await.ok().flatten().is_some());
    assert!(revokes_ok(&inv, &inv.owner, "ghost@x.io").await);
    assert!(inv.store.read_record(&key).await.ok().flatten().is_none());
}
