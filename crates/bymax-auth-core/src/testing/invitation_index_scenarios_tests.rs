//! Runs the invitee index scenarios against the in-memory store.

use super::InMemoryStores;
use super::invitation_index_scenarios::run_invitation_index_scenarios;

#[tokio::test]
async fn the_in_memory_store_keeps_the_invitation_index_rules() {
    run_invitation_index_scenarios(&InMemoryStores::new()).await;
}
