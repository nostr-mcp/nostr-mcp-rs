use crate::error::CoreError;
use nostr_mcp_types::follows::PublishFollowsResult;
use nostr_mcp_types::settings::FollowEntry;
use nostr_sdk::prelude::*;

pub struct FollowsService;

impl FollowsService {
    pub async fn fetch(client: &Client, pubkey: &PublicKey) -> Result<Vec<FollowEntry>, CoreError> {
        crate::follows::fetch_follows(client, pubkey).await
    }

    pub async fn publish(
        client: &Client,
        follows: &[FollowEntry],
    ) -> Result<PublishFollowsResult, CoreError> {
        crate::follows::publish_follows(client, follows).await
    }
}
