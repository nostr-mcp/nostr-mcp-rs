use crate::error::CoreError;
use nostr_mcp_types::nip58::{
    Nip58BadgeAwardArgs, Nip58BadgeDefinitionArgs, Nip58ProfileBadgesArgs,
};
use nostr_mcp_types::nip89::{Nip89HandlerInfoArgs, Nip89RecommendArgs};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;

pub struct ProtocolPublishingService;

impl ProtocolPublishingService {
    pub async fn post_recommendation(
        client: &Client,
        args: Nip89RecommendArgs,
    ) -> Result<SendResult, CoreError> {
        crate::nip89::post_recommendation(client, args).await
    }

    pub async fn post_handler_info(
        client: &Client,
        args: Nip89HandlerInfoArgs,
    ) -> Result<SendResult, CoreError> {
        crate::nip89::post_handler_info(client, args).await
    }

    pub async fn post_badge_definition(
        client: &Client,
        args: Nip58BadgeDefinitionArgs,
    ) -> Result<SendResult, CoreError> {
        crate::nip58::post_badge_definition(client, args).await
    }

    pub async fn post_badge_award(
        client: &Client,
        args: Nip58BadgeAwardArgs,
    ) -> Result<SendResult, CoreError> {
        crate::nip58::post_badge_award(client, args).await
    }

    pub async fn post_profile_badges(
        client: &Client,
        args: Nip58ProfileBadgesArgs,
    ) -> Result<SendResult, CoreError> {
        crate::nip58::post_profile_badges(client, args).await
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolPublishingService;
    use nostr_mcp_types::nip58::{
        Nip58BadgeAwardArgs, Nip58BadgeDefinitionArgs, Nip58BadgeDisplay, Nip58ProfileBadgesArgs,
    };
    use nostr_mcp_types::nip89::{Nip89HandlerInfoArgs, Nip89RecommendArgs};
    use nostr_sdk::prelude::*;

    fn client() -> Client {
        Client::new(Keys::generate())
    }

    #[tokio::test]
    async fn service_post_recommendation_rejects_missing_handlers() {
        let err = ProtocolPublishingService::post_recommendation(
            &client(),
            Nip89RecommendArgs {
                supported_kind: 1,
                handlers: vec![],
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("handlers must include"));
    }

    #[tokio::test]
    async fn service_post_handler_info_rejects_empty_identifier() {
        let err = ProtocolPublishingService::post_handler_info(
            &client(),
            Nip89HandlerInfoArgs {
                identifier: "   ".to_string(),
                kinds: vec![1],
                links: vec![],
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[tokio::test]
    async fn service_post_badge_definition_rejects_empty_identifier() {
        let err = ProtocolPublishingService::post_badge_definition(
            &client(),
            Nip58BadgeDefinitionArgs {
                identifier: "   ".to_string(),
                name: None,
                description: None,
                image: None,
                thumbs: None,
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[tokio::test]
    async fn service_post_badge_award_rejects_missing_recipients() {
        let err = ProtocolPublishingService::post_badge_award(
            &client(),
            Nip58BadgeAwardArgs {
                badge:
                    "30009:0000000000000000000000000000000000000000000000000000000000000000:badge"
                        .to_string(),
                badge_relay: None,
                recipients: vec![],
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("recipients must include"));
    }

    #[tokio::test]
    async fn service_post_profile_badges_rejects_bad_coordinate() {
        let err = ProtocolPublishingService::post_profile_badges(
            &client(),
            Nip58ProfileBadgesArgs {
                badges: vec![Nip58BadgeDisplay {
                    badge:
                        "1:0000000000000000000000000000000000000000000000000000000000000000:badge"
                            .to_string(),
                    badge_relay: None,
                    award_event_id:
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    award_relay: None,
                }],
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("kind 30009"));
    }
}
