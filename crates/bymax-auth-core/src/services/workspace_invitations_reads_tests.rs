//! The workspace invitation reads: the list in pages and the preview by token, with the answers that
//! confirm nothing and the records that are never trusted (layer: service, tests).

use bymax_auth_types::AuthError;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::workspace::PageQuery;
use super::workspace_invitations::{InvitationPreview, WorkspaceInvitationView};
use super::workspace_invitations_support_tests::{Inv, Seeded, seed, seed_bootstrap, setup};
use super::workspace_support_tests::{config, seed_account};

const LONG_AGO: &str = "2026-01-01T00:00:00.000Z";

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

/// A page that must be served: a failed listing fails the test instead of ending it silently.
async fn listed(
    inv: &Inv,
    cursor: Option<&str>,
    limit: &str,
) -> Option<crate::workspace::domain::Page<WorkspaceInvitationView>> {
    let served = page(inv, cursor, limit).await;
    assert!(served.is_ok(), "{:?}", served.as_ref().err());
    served.ok()
}

#[tokio::test]
async fn the_list_view_carries_the_role_the_times_and_the_resend_count_of_the_record() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    let item = Seeded {
        email: "v@x.io",
        role: "admin",
        inviter: &inv.owner.user_id,
        created_at: "2026-02-03T04:05:06.007Z",
        resends: 3,
    };
    seed(&inv, "v-token", &item).await;
    let Some(listing) = listed(&inv, None, "10").await else { unreachable!() };
    let Some(view) = listing.items.first() else {
        assert!(!listing.items.is_empty(), "the invitation is listed");
        return;
    };
    assert_eq!(view.role, "admin");
    assert_eq!(view.created_at, "2026-02-03T04:05:06.007Z");
    assert_eq!(view.resend_count, 3);
    assert_eq!(view.inviter_user_id, inv.owner.user_id);
    let expires = OffsetDateTime::parse(&view.expires_at, &Rfc3339);
    assert!(expires.is_ok(), "{}", view.expires_at);
    let left = expires.map_or(i64::MIN, |at| {
        (at - OffsetDateTime::now_utc()).whole_seconds()
    });
    assert!((590..=600).contains(&left), "the seed lives 600 s: {left}");
}

#[tokio::test]
async fn the_list_is_oldest_first_and_in_pages() {
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(first) = listed(&inv, None, "2").await else { unreachable!() };
    let emails: Vec<_> = first.items.iter().map(|view| view.email.as_str()).collect();
    assert_eq!(emails, ["l1@x.io", "l0@x.io"], "oldest first");
    assert_eq!(first.items[0].inviter_user_id, inv.owner.user_id);
    assert!(first.next_cursor.is_some());
    let Some(second) = listed(&inv, first.next_cursor.as_deref(), "2").await else {
        unreachable!()
    };
    let emails: Vec<_> = second
        .items
        .iter()
        .map(|view| view.email.as_str())
        .collect();
    assert_eq!(
        emails,
        ["l2@x.io"],
        "the page after the cursor, not the cursor's own"
    );
    assert_eq!(second.next_cursor, None);
    let Some(whole) = listed(&inv, None, "3").await else { unreachable!() };
    assert_eq!(whole.items.len(), 3);
    assert_eq!(
        whole.next_cursor, None,
        "a page that holds the rest has no next page"
    );
}

#[tokio::test]
async fn a_page_size_outside_its_bounds_is_refused() {
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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
    let Some(inv) = setup(config()).await else { unreachable!() };
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

#[tokio::test]
async fn the_list_orders_by_the_instant_whatever_offset_and_precision_the_times_use() {
    let Some(inv) = setup(config()).await else { unreachable!() };
    // 10:00:00.000Z, and 08:00:00.123456Z written with an offset: the second is the older.
    for (email, at) in [
        ("late@x.io", "2026-11-20T10:00:00.000Z"),
        ("early@x.io", "2026-11-20T10:00:00.123456+02:00"),
    ] {
        let item = Seeded {
            email,
            role: "member",
            inviter: &inv.owner.user_id,
            created_at: at,
            resends: 0,
        };
        seed(&inv, &format!("{email}-token"), &item).await;
    }
    let Some(first) = listed(&inv, None, "1").await else { unreachable!() };
    assert_eq!(first.items[0].email, "early@x.io");
    let Some(second) = listed(&inv, first.next_cursor.as_deref(), "1").await else {
        unreachable!()
    };
    assert_eq!(second.items[0].email, "late@x.io");
    assert_eq!(second.next_cursor, None);
}
