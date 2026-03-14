use super::{NostrMcpServer, core_error};
use nostr_mcp_core::client::ActiveClient;
use nostr_mcp_core::nip58::{post_badge_award, post_badge_definition, post_profile_badges};
use nostr_mcp_core::nip89::{post_handler_info, post_recommendation};
use nostr_mcp_types::nip58::{
    Nip58BadgeAwardArgs, Nip58BadgeDefinitionArgs, Nip58ProfileBadgesArgs,
};
use nostr_mcp_types::nip89::{Nip89HandlerInfoArgs, Nip89RecommendArgs};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

#[tool_router(router = protocol_publishing_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn protocol_publishing_client(&self) -> Result<ActiveClient, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        self.ensure_client_from(keystore, settings_store).await
    }

    #[tool(
        description = "Publish a NIP-89 handler recommendation (kind 31989). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_handlers_recommend(
        &self,
        Parameters(args): Parameters<Nip89RecommendArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.protocol_publishing_client().await?;
        let result = post_recommendation(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a NIP-89 handler information event (kind 31990). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_handlers_register(
        &self,
        Parameters(args): Parameters<Nip89HandlerInfoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.protocol_publishing_client().await?;
        let result = post_handler_info(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a NIP-58 badge definition (kind 30009). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_badges_define(
        &self,
        Parameters(args): Parameters<Nip58BadgeDefinitionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.protocol_publishing_client().await?;
        let result = post_badge_definition(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a NIP-58 badge award (kind 8). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_badges_award(
        &self,
        Parameters(args): Parameters<Nip58BadgeAwardArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.protocol_publishing_client().await?;
        let result = post_badge_award(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a NIP-58 profile badges event (kind 30008). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_badges_set_profile(
        &self,
        Parameters(args): Parameters<Nip58ProfileBadgesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.protocol_publishing_client().await?;
        let result = post_profile_badges(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
