use super::{NostrMcpServer, core_error};
use nostr_mcp_core::relay_info::fetch_relay_info;
use nostr_mcp_core::relays::{
    connect_relays, disconnect_relays, get_relay_urls, list_relays, set_relays, status_summary,
};
use nostr_mcp_core::settings::{KeySettings, SettingsStore};
use nostr_mcp_types::common::EmptyArgs;
use nostr_mcp_types::relay_info::RelayInfoArgs;
use nostr_mcp_types::relays::{RelaysConnectArgs, RelaysDisconnectArgs, RelaysSetArgs};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};
use std::sync::Arc;

#[tool_router(router = relay_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn persist_relay_settings(
        &self,
        settings_store: Arc<SettingsStore>,
        pubkey_hex: String,
        relay_urls: Vec<String>,
    ) -> Result<(), ErrorData> {
        let existing = settings_store.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: relay_urls,
            metadata: existing
                .as_ref()
                .and_then(|settings| settings.metadata.clone()),
            follows: existing
                .as_ref()
                .map(|settings| settings.follows.clone())
                .unwrap_or_default(),
        };
        settings_store
            .save_settings(pubkey_hex, settings)
            .await
            .map_err(core_error)
    }

    #[tool(
        description = "Set relays and connect. Requires an active nostr key. read_write: read|write|both"
    )]
    pub async fn nostr_relays_set(
        &self,
        Parameters(args): Parameters<RelaysSetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self
            .ensure_client_from(keystore, settings_store.clone())
            .await?;
        set_relays(&active_client.client, args)
            .await
            .map_err(core_error)?;

        let relay_urls = get_relay_urls(&active_client.client).await;
        self.persist_relay_settings(
            settings_store,
            active_client.active_pubkey.to_hex(),
            relay_urls,
        )
        .await?;

        let rows = list_relays(&active_client.client)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "relays": rows }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Connect to relays that were previously added. Requires an active nostr key."
    )]
    pub async fn nostr_relays_connect(
        &self,
        Parameters(args): Parameters<RelaysConnectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self.ensure_client_from(keystore, settings_store).await?;
        connect_relays(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let rows = list_relays(&active_client.client)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "relays": rows }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Disconnect or remove relays. When force_remove=true, relays are removed from the pool."
    )]
    pub async fn nostr_relays_disconnect(
        &self,
        Parameters(args): Parameters<RelaysDisconnectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self
            .ensure_client_from(keystore, settings_store.clone())
            .await?;
        disconnect_relays(&active_client.client, args)
            .await
            .map_err(core_error)?;

        let relay_urls = get_relay_urls(&active_client.client).await;
        self.persist_relay_settings(
            settings_store,
            active_client.active_pubkey.to_hex(),
            relay_urls,
        )
        .await?;

        let rows = list_relays(&active_client.client)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "relays": rows }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "List relay status and flags")]
    pub async fn nostr_relays_status(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self.ensure_client_from(keystore, settings_store).await?;
        let rows = list_relays(&active_client.client)
            .await
            .map_err(core_error)?;
        let summary = status_summary(&active_client.client)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "summary": summary, "relays": rows }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch relay information document (NIP-11). Accepts ws/wss/http/https relay URL. Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_relays_get_info(
        &self,
        Parameters(args): Parameters<RelayInfoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = fetch_relay_info(args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
