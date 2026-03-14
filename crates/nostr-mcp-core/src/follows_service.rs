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

#[cfg(test)]
mod tests {
    use super::FollowsService;
    use nostr_sdk::prelude::*;

    #[tokio::test]
    async fn service_fetch_surfaces_client_failures() {
        let client = Client::new(Keys::generate());
        let err = FollowsService::fetch(&client, &Keys::generate().public_key())
            .await
            .unwrap_err();

        assert!(err.to_string().contains("fetch follows"));
    }

    #[tokio::test]
    async fn service_publish_surfaces_client_failures() {
        let client = Client::new(Keys::generate());
        let err = FollowsService::publish(&client, &[]).await.unwrap_err();

        assert!(err.to_string().contains("publish follows"));
    }
}
