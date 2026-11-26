//! Runs the invitee index scenarios against the in-memory store.

use super::InMemoryStores;
use super::invitation_index_scenarios::run_invitation_index_scenarios;

#[tokio::test]
async fn the_in_memory_store_releases_an_index_only_while_it_holds_the_named_hash() {
    run_invitation_index_scenarios(&InMemoryStores::new()).await;
}
