use super::{NostrMcpServer, core_error, invalid_params};
use nostr::nips::nip19::ToBech32;
use nostr_mcp_core::metadata::{
    MetadataResult, args_to_profile, fetch_metadata, fetch_profile, publish_metadata,
};
use nostr_mcp_core::settings::{KeySettings, ProfileMetadata, SettingsStore};
use nostr_mcp_types::common::EmptyArgs;
use nostr_mcp_types::metadata::{FetchMetadataArgs, ProfileGetArgs, SetMetadataArgs};
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tool_router(router = metadata_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn persist_metadata_settings(
        &self,
        settings_store: Arc<SettingsStore>,
        pubkey_hex: String,
        profile: ProfileMetadata,
    ) -> Result<(), ErrorData> {
        let existing = settings_store.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|settings| settings.relays.clone())
                .unwrap_or_default(),
            metadata: Some(profile),
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
        description = "Set kind 0 metadata (profile) for the active key. All fields are optional. Set publish=true to broadcast to relays immediately using the active key (default: true). Returns the pubkey that signed the metadata event for verification"
    )]
    pub async fn nostr_metadata_set(
        &self,
        Parameters(args): Parameters<SetMetadataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;
        let profile = args_to_profile(&args);

        self.persist_metadata_settings(settings_store.clone(), pubkey.to_hex(), profile.clone())
            .await?;

        let result = if args.publish.unwrap_or(true) {
            let active_client = self.ensure_client_from(keystore, settings_store).await?;
            publish_metadata(&active_client.client, &profile)
                .await
                .map_err(core_error)?
        } else {
            MetadataResult {
                saved: true,
                published: false,
                event_id: None,
                pubkey: None,
                success_relays: vec![],
                failed_relays: HashMap::new(),
            }
        };

        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get kind 0 metadata (profile) for the active key from local settings")]
    pub async fn nostr_metadata_get(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;
        let metadata = settings_store
            .get_settings(&pubkey.to_hex())
            .await
            .and_then(|settings| settings.metadata);

        let content = Content::json(serde_json::json!({
            "pubkey": active.public_key,
            "metadata": metadata
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch kind 0 metadata (profile) from relays for a key. Uses active key if no label specified."
    )]
    pub async fn nostr_metadata_fetch(
        &self,
        Parameters(args): Parameters<FetchMetadataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self
            .ensure_client_from(keystore.clone(), settings_store)
            .await?;

        let target_pubkey = if let Some(label) = args.label {
            let keys = keystore.list().await;
            let entry = keys.iter().find(|key| key.label == label).ok_or_else(|| {
                ErrorData::invalid_params(format!("key with label '{label}' not found"), None)
            })?;
            PublicKey::from_bech32(&entry.public_key).map_err(invalid_params)?
        } else {
            active_client.active_pubkey
        };

        let metadata = fetch_metadata(&active_client.client, &target_pubkey)
            .await
            .map_err(core_error)?;

        let content = Content::json(serde_json::json!({
            "pubkey": target_pubkey.to_bech32().unwrap(),
            "metadata": metadata
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch kind 0 profile metadata for a pubkey (hex or npub). Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_profiles_get(
        &self,
        Parameters(args): Parameters<ProfileGetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self.ensure_client_from(keystore, settings_store).await?;

        let result = fetch_profile(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
