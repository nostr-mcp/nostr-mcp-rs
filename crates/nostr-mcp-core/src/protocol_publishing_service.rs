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
