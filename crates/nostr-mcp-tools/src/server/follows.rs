use super::{NostrMcpServer, core_error, invalid_params};
use crate::host_runtime::settings::{KeySettings, SettingsStore};
use nostr::nips::nip19::ToBech32;
use nostr_mcp_core::follows_service::FollowsService;
use nostr_mcp_policy::{AuthoringAction, CapabilityScope, SignerMethod};
use nostr_mcp_types::common::EmptyArgs;
use nostr_mcp_types::follows::{
    AddFollowArgs, FollowsLookupResult, FollowsMutationResult, PublishFollowsResult,
    RemoveFollowArgs, SetFollowsArgs,
};
use nostr_mcp_types::settings::FollowEntry;
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tool_router(router = follow_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn persist_follow_settings(
        &self,
        settings_store: Arc<SettingsStore>,
        pubkey_hex: String,
        follows: Vec<FollowEntry>,
    ) -> Result<(), ErrorData> {
        let existing = settings_store.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|settings| settings.relays.clone())
                .unwrap_or_default(),
            metadata: existing
                .as_ref()
                .and_then(|settings| settings.metadata.clone()),
            follows,
        };
        settings_store
            .save_settings(pubkey_hex, settings)
            .await
            .map_err(core_error)
    }

    fn unpublished_follow_result() -> PublishFollowsResult {
        PublishFollowsResult {
            saved: true,
            published: false,
            event_id: None,
            pubkey: None,
            success_relays: vec![],
            failed_relays: HashMap::new(),
        }
    }

    #[tool(
        description = "Set kind 3 follow list for the active key. Replaces entire follow list. Set publish=true to broadcast to relays immediately (default: true). Each follow must have pubkey (hex), optional relay_url, and optional petname. Returns the event ID and pubkey that signed it for verification"
    )]
    pub async fn nostr_follows_set(
        &self,
        Parameters(args): Parameters<SetFollowsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = if args.publish.unwrap_or(true) {
            self.authoring_request(
                CapabilityScope::ManageFollows,
                AuthoringAction::Publish,
                Some(SignerMethod::SignEvent),
                Some(3),
                None,
            )
        } else {
            self.capability_request(CapabilityScope::ManageFollows)
        };
        self.authorize_policy_request(request).await?;
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;

        self.persist_follow_settings(
            settings_store.clone(),
            pubkey.to_hex(),
            args.follows.clone(),
        )
        .await?;

        let result = if args.publish.unwrap_or(true) {
            let active_client = self.ensure_client_from(keystore, settings_store).await?;
            FollowsService::publish(&active_client.client, &args.follows)
                .await
                .map_err(core_error)?
        } else {
            Self::unpublished_follow_result()
        };

        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get kind 3 follow list for the active key from local settings")]
    pub async fn nostr_follows_get(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;

        let follows = settings_store
            .get_settings(&pubkey.to_hex())
            .await
            .map(|settings| settings.follows)
            .unwrap_or_default();

        let count = follows.len();
        let content = Content::json(serde_json::json!(FollowsLookupResult {
            pubkey: active.public_key,
            follows,
            count,
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch kind 3 follow list from relays for the active key. Updates local settings with fetched data"
    )]
    pub async fn nostr_follows_fetch(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        let active_client = self
            .ensure_client_from(keystore, settings_store.clone())
            .await?;

        let follows = FollowsService::fetch(&active_client.client, &active_client.active_pubkey)
            .await
            .map_err(core_error)?;

        self.persist_follow_settings(
            settings_store,
            active_client.active_pubkey.to_hex(),
            follows.clone(),
        )
        .await?;

        let count = follows.len();
        let content = Content::json(serde_json::json!(FollowsLookupResult {
            pubkey: active_client.active_pubkey.to_bech32().unwrap(),
            follows,
            count,
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Add a follow to the active key's follow list. Adds to existing follows and publishes to relays (default: true). Requires pubkey (hex), optional relay_url, and optional petname. Returns updated follow list and event ID"
    )]
    pub async fn nostr_follows_add(
        &self,
        Parameters(args): Parameters<AddFollowArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = if args.publish.unwrap_or(true) {
            self.authoring_request(
                CapabilityScope::ManageFollows,
                AuthoringAction::Publish,
                Some(SignerMethod::SignEvent),
                Some(3),
                None,
            )
        } else {
            self.capability_request(CapabilityScope::ManageFollows)
        };
        self.authorize_policy_request(request).await?;
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let existing = settings_store.get_settings(&pubkey_hex).await;
        let mut follows = existing
            .as_ref()
            .map(|settings| settings.follows.clone())
            .unwrap_or_default();

        if follows.iter().any(|follow| follow.pubkey == args.pubkey) {
            return Err(ErrorData::invalid_params(
                format!("already following pubkey: {}", args.pubkey),
                None,
            ));
        }

        follows.push(FollowEntry {
            pubkey: args.pubkey,
            relay_url: args.relay_url,
            petname: args.petname,
        });

        self.persist_follow_settings(settings_store.clone(), pubkey_hex, follows.clone())
            .await?;

        let result = if args.publish.unwrap_or(true) {
            let active_client = self.ensure_client_from(keystore, settings_store).await?;
            FollowsService::publish(&active_client.client, &follows)
                .await
                .map_err(core_error)?
        } else {
            Self::unpublished_follow_result()
        };

        let count = follows.len();
        let content = Content::json(serde_json::json!(FollowsMutationResult {
            follows,
            count,
            result,
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Remove a follow from the active key's follow list by pubkey. Removes from existing follows and publishes to relays (default: true). Returns updated follow list and event ID"
    )]
    pub async fn nostr_follows_remove(
        &self,
        Parameters(args): Parameters<RemoveFollowArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = if args.publish.unwrap_or(true) {
            self.authoring_request(
                CapabilityScope::ManageFollows,
                AuthoringAction::Publish,
                Some(SignerMethod::SignEvent),
                Some(3),
                None,
            )
        } else {
            self.capability_request(CapabilityScope::ManageFollows)
        };
        self.authorize_policy_request(request).await?;
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;

        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key).map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let existing = settings_store.get_settings(&pubkey_hex).await;
        let mut follows = existing
            .as_ref()
            .map(|settings| settings.follows.clone())
            .unwrap_or_default();

        let original_len = follows.len();
        follows.retain(|follow| follow.pubkey != args.pubkey);

        if follows.len() == original_len {
            return Err(ErrorData::invalid_params(
                format!("not following pubkey: {}", args.pubkey),
                None,
            ));
        }

        self.persist_follow_settings(settings_store.clone(), pubkey_hex, follows.clone())
            .await?;

        let result = if args.publish.unwrap_or(true) {
            let active_client = self.ensure_client_from(keystore, settings_store).await?;
            FollowsService::publish(&active_client.client, &follows)
                .await
                .map_err(core_error)?
        } else {
            Self::unpublished_follow_result()
        };

        let count = follows.len();
        let content = Content::json(serde_json::json!(FollowsMutationResult {
            follows,
            count,
            result,
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
