mod event_authoring;
mod follows;
mod keys;
mod metadata;
mod relays;

use crate::runtime::{NostrMcpPaths, NostrMcpRuntime};
use crate::util;
use nostr_mcp_core::client::{ActiveClient, ClientStore};
use nostr_mcp_core::error::CoreError;
use nostr_mcp_core::events::{
    list_events, list_long_form_events, query_events, search_events,
    subscription_targets_mentions_me, subscription_targets_my_metadata,
    subscription_targets_my_notes, EventsListArgs, LongFormListArgs, QueryEventsArgs,
    SearchEventsArgs,
};
use nostr_mcp_core::groups::{
    create_group, create_invite, delete_group, delete_group_event, edit_group_metadata, join_group,
    leave_group, put_user, remove_user, CreateGroupArgs, CreateInviteArgs, DeleteEventArgs,
    DeleteGroupArgs, EditGroupMetadataArgs, JoinGroupArgs, LeaveGroupArgs, PutUserArgs,
    RemoveUserArgs,
};
use nostr_mcp_core::key_store::KeyStore;
use nostr_mcp_core::nip01;
use nostr_mcp_core::nip05::{resolve_nip05, verify_nip05, Nip05ResolveArgs, Nip05VerifyArgs};
use nostr_mcp_core::nip30::{parse_nip30_emojis, Nip30ParseArgs};
use nostr_mcp_core::nip44::{decrypt_nip44, encrypt_nip44, Nip44DecryptArgs, Nip44EncryptArgs};
use nostr_mcp_core::nip58::{
    post_badge_award, post_badge_definition, post_profile_badges, Nip58BadgeAwardArgs,
    Nip58BadgeDefinitionArgs, Nip58ProfileBadgesArgs,
};
use nostr_mcp_core::nip89::{
    post_handler_info, post_recommendation, Nip89HandlerInfoArgs, Nip89RecommendArgs,
};
use nostr_mcp_core::polls::{get_poll_results, GetPollResultsArgs};
use nostr_mcp_core::references::{parse_text_references, ParseReferencesArgs};
#[cfg(not(feature = "keyring"))]
use nostr_mcp_core::secrets::InMemorySecretStore;
#[cfg(feature = "keyring")]
use nostr_mcp_core::secrets::KeyringSecretStore;
use nostr_mcp_core::secrets::SecretStore;
use nostr_mcp_core::settings::SettingsStore;
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, ErrorData, Implementation, ProtocolVersion, ServerCapabilities,
        ServerInfo,
    },
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tokio::time::{sleep, Duration};
use tracing::info;

fn secret_store(runtime: &NostrMcpRuntime) -> Arc<dyn SecretStore> {
    #[cfg(feature = "keyring")]
    {
        Arc::new(KeyringSecretStore::new(&runtime.keyring_service))
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = runtime;
        Arc::new(InMemorySecretStore::new())
    }
}

async fn load_or_init_keystore(
    paths: &NostrMcpPaths,
    runtime: &NostrMcpRuntime,
) -> Result<KeyStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    KeyStore::load_or_init(paths.index_path.clone(), pass, secret_store(runtime)).await
}

async fn load_or_init_settings(paths: &NostrMcpPaths) -> Result<SettingsStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    SettingsStore::load_or_init(paths.settings_path.clone(), pass).await
}

fn core_error(err: CoreError) -> ErrorData {
    match err {
        CoreError::InvalidInput(msg) => ErrorData::invalid_params(msg, None),
        _ => ErrorData::internal_error(err.to_string(), None),
    }
}

fn invalid_params<E: ToString>(err: E) -> ErrorData {
    ErrorData::invalid_params(err.to_string(), None)
}

struct ServerStores {
    keystore: Arc<KeyStore>,
    settings_store: Arc<SettingsStore>,
}

struct ServerContext {
    runtime: NostrMcpRuntime,
    stores: OnceCell<ServerStores>,
    client_store: ClientStore,
}

impl ServerContext {
    fn new(runtime: NostrMcpRuntime) -> Self {
        Self {
            runtime,
            stores: OnceCell::const_new(),
            client_store: ClientStore::new(),
        }
    }

    async fn stores(&self) -> Result<&ServerStores, CoreError> {
        let runtime = self.runtime.clone();
        self.stores
            .get_or_try_init(move || {
                let runtime = runtime.clone();
                async move {
                    let keystore = Arc::new(load_or_init_keystore(&runtime.paths, &runtime).await?);
                    let settings_store = Arc::new(load_or_init_settings(&runtime.paths).await?);
                    Ok(ServerStores {
                        keystore,
                        settings_store,
                    })
                }
            })
            .await
    }
}

#[derive(Clone)]
pub struct NostrMcpServer {
    tool_router: ToolRouter<Self>,
    context: Arc<ServerContext>,
}

impl NostrMcpServer {
    async fn initialize(&self) -> Result<(), CoreError> {
        self.context.stores().await?;
        Ok(())
    }

    async fn keystore(&self) -> Result<Arc<KeyStore>, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        Ok(stores.keystore.clone())
    }

    async fn settings_store(&self) -> Result<Arc<SettingsStore>, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        Ok(stores.settings_store.clone())
    }

    async fn ensure_client_from(
        &self,
        keystore: Arc<KeyStore>,
        settings_store: Arc<SettingsStore>,
    ) -> Result<ActiveClient, ErrorData> {
        self.context
            .client_store
            .ensure_client(keystore, settings_store)
            .await
            .map_err(core_error)
    }

    async fn reset_client(&self) -> Result<(), ErrorData> {
        self.context.client_store.reset().await.map_err(core_error)
    }

    #[cfg(test)]
    async fn client(&self) -> Result<ActiveClient, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        self.ensure_client_from(stores.keystore.clone(), stores.settings_store.clone())
            .await
    }
}

#[tool_router]
impl NostrMcpServer {
    pub fn new() -> Self {
        Self::with_runtime(NostrMcpRuntime::default())
    }

    pub fn with_runtime(runtime: NostrMcpRuntime) -> Self {
        Self {
            tool_router: Self::tool_router()
                + Self::event_authoring_tool_router()
                + Self::follow_tool_router()
                + Self::key_tool_router()
                + Self::relay_tool_router()
                + Self::metadata_tool_router(),
            context: Arc::new(ServerContext::new(runtime)),
        }
    }

    #[tool(
        description = "Resolve a NIP-05 identifier (name@domain) to a pubkey and relay hints. Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_nip05_resolve(
        &self,
        Parameters(args): Parameters<Nip05ResolveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = resolve_nip05(args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Verify a NIP-05 identifier against a pubkey (npub or 64-char hex). Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_nip05_verify(
        &self,
        Parameters(args): Parameters<Nip05VerifyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = verify_nip05(args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Encrypt plaintext using NIP-44.")]
    pub async fn nostr_nip44_encrypt(
        &self,
        Parameters(args): Parameters<Nip44EncryptArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = encrypt_nip44(args).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Decrypt ciphertext using NIP-44.")]
    pub async fn nostr_nip44_decrypt(
        &self,
        Parameters(args): Parameters<Nip44DecryptArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = decrypt_nip44(args).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a NIP-89 handler recommendation (kind 31989). Optional: pow (u8), to_relays (urls)."
    )]
    pub async fn nostr_handlers_recommend(
        &self,
        Parameters(args): Parameters<Nip89RecommendArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = post_recommendation(&ac.client, args)
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
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = post_handler_info(&ac.client, args)
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
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = post_badge_definition(&ac.client, args)
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
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = post_badge_award(&ac.client, args)
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
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = post_profile_badges(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Parse NIP-30 emoji tags and shortcode mentions in content.")]
    pub async fn nostr_events_parse_emojis(
        &self,
        Parameters(args): Parameters<Nip30ParseArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = parse_nip30_emojis(args);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch events using presets or custom filters. Presets: my_notes, mentions_me, my_metadata, by_author, by_kind. For by_kind: specify 'kind' parameter. Optional: limit, timeout_secs, since (unix timestamp), until (unix timestamp), author_npub (for by_author)"
    )]
    pub async fn nostr_events_list(
        &self,
        Parameters(args): Parameters<EventsListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        nip01::validate_time_bounds(args.since, args.until).map_err(core_error)?;
        nip01::validate_limit(args.limit).map_err(core_error)?;
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;

        let since_ts = args.since.map(Timestamp::from);
        let until_ts = args.until.map(Timestamp::from);

        let preset = args.preset.to_ascii_lowercase();
        let mut filter = match preset.as_str() {
            "my_notes" => subscription_targets_my_notes(ac.active_pubkey, since_ts, until_ts).await,
            "mentions_me" => {
                subscription_targets_mentions_me(ac.active_pubkey, since_ts, until_ts).await
            }
            "my_metadata" => subscription_targets_my_metadata(ac.active_pubkey).await,
            "by_author" => {
                let npub_ref = args.author_npub.as_ref().ok_or_else(|| {
                    ErrorData::invalid_params(
                        "author_npub is required for preset 'by_author'",
                        None,
                    )
                })?;
                let pk = PublicKey::from_bech32(npub_ref).map_err(invalid_params)?;

                let default_since = Timestamp::now() - 86400 * 7;
                let mut f = Filter::new()
                    .author(pk)
                    .since(since_ts.unwrap_or(default_since));

                if let Some(u) = until_ts {
                    f = f.until(u);
                }
                f
            }
            "by_kind" => {
                let kind_num = args.kind.ok_or_else(|| {
                    ErrorData::invalid_params("kind is required for preset 'by_kind'", None)
                })?;

                let default_since = Timestamp::now() - 86400 * 7;
                let mut f = Filter::new()
                    .kind(Kind::from(kind_num))
                    .since(since_ts.unwrap_or(default_since));

                if let Some(u) = until_ts {
                    f = f.until(u);
                }

                if let Some(npub_ref) = &args.author_npub {
                    let pk = PublicKey::from_bech32(npub_ref).map_err(invalid_params)?;
                    f = f.author(pk);
                }
                f
            }
            _ => return Err(ErrorData::invalid_params("unknown preset", None)),
        };
        if let Some(l) = args.limit {
            filter = filter.limit(l as usize);
        }
        let events = list_events(&ac.client, filter, args.timeout())
            .await
            .map_err(core_error)?;
        let items: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id.to_string(),
                    "kind": e.kind.as_u16(),
                    "pubkey": e.pubkey.to_string(),
                    "created_at": e.created_at.as_secs(),
                    "content": e.content,
                    "tags": e.tags.to_vec(),
                })
            })
            .collect();
        let content = Content::json(serde_json::json!({ "items": items, "count": items.len() }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "List kind 30023 long-form notes (NIP-23). Requires at least one of author_npub, identifier, hashtags. Optional: limit, since (unix timestamp), until (unix timestamp), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_list_long_form(
        &self,
        Parameters(args): Parameters<LongFormListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss).await?;
        let events = list_long_form_events(&ac.client, args)
            .await
            .map_err(core_error)?;
        let items: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id.to_string(),
                    "kind": e.kind.as_u16(),
                    "pubkey": e.pubkey.to_string(),
                    "created_at": e.created_at.as_secs(),
                    "content": e.content,
                    "tags": e.tags.to_vec(),
                })
            })
            .collect();
        let content = Content::json(serde_json::json!({ "items": items, "count": items.len() }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Parse nostr: references in text content (NIP-27). Returns decoded references with types and metadata."
    )]
    pub async fn nostr_events_parse_refs(
        &self,
        Parameters(args): Parameters<ParseReferencesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = parse_text_references(args);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Query events using one or more NIP-01 filters. Provide filters as an array of filter objects. Optional: limit (applies to all filters), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_query(
        &self,
        Parameters(args): Parameters<QueryEventsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss).await?;
        let events = query_events(&ac.client, args).await.map_err(core_error)?;
        let items: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id.to_string(),
                    "kind": e.kind.as_u16(),
                    "pubkey": e.pubkey.to_string(),
                    "created_at": e.created_at.as_secs(),
                    "content": e.content,
                    "tags": e.tags.to_vec(),
                })
            })
            .collect();
        let content = Content::json(serde_json::json!({ "items": items, "count": items.len() }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Search events using NIP-50 search query. Requires query. Optional: kinds (array), author_npub, limit, since (unix timestamp), until (unix timestamp), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_search(
        &self,
        Parameters(args): Parameters<SearchEventsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss).await?;
        let events = search_events(&ac.client, args).await.map_err(core_error)?;
        let items: Vec<serde_json::Value> = events
            .into_iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id.to_string(),
                    "kind": e.kind.as_u16(),
                    "pubkey": e.pubkey.to_string(),
                    "created_at": e.created_at.as_secs(),
                    "content": e.content,
                    "tags": e.tags.to_vec(),
                })
            })
            .collect();
        let content = Content::json(serde_json::json!({ "items": items, "count": items.len() }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Get results for a kind=1068 poll (NIP-88). Fetches the poll and all kind=1018 responses, counts votes (one per pubkey, most recent wins), and returns results with vote counts per option. Respects poll end time if set. Returns poll details, vote counts, and whether poll has ended. Optional: timeout_secs (default: 10)"
    )]
    pub async fn nostr_events_get_poll_results(
        &self,
        Parameters(args): Parameters<GetPollResultsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let results = get_poll_results(
            &ac.client,
            &args.poll_event_id,
            args.timeout_secs.unwrap_or(10),
        )
        .await
        .map_err(core_error)?;
        let content = Content::json(serde_json::json!(results))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Add or update a user in a group using the active key (kind 9000, NIP-29). Moderation event requiring admin privileges. Use pubkey (hex) to specify user and optional roles array (e.g., ['admin', 'moderator']). Returns the event ID and pubkey that signed it for verification. Optional: roles (array), previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_put_user(
        &self,
        Parameters(args): Parameters<PutUserArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = put_user(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Remove a user from a group using the active key (kind 9001, NIP-29). Moderation event requiring admin privileges. Use pubkey (hex) to specify user to remove. Returns the event ID and pubkey that signed it for verification. Optional: previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_remove_user(
        &self,
        Parameters(args): Parameters<RemoveUserArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = remove_user(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Edit group metadata using the active key (kind 9002, NIP-29). Moderation event requiring admin privileges. Supports partial updates - only include fields to change. Positive visibility/write/read toggles map to NIP-29 moderation tags: unrestricted, visible, public, open. Returns the event ID and pubkey that signed it for verification. Optional: name, picture, about, unrestricted (bool), visible (bool), public (bool), open (bool), previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_edit_metadata(
        &self,
        Parameters(args): Parameters<EditGroupMetadataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = edit_group_metadata(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Delete an event from a group using the active key (kind 9005, NIP-29). Moderation event requiring admin privileges. Use event_id (hex) to specify event to delete. Returns the event ID and pubkey that signed it for verification. Optional: previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_delete_event(
        &self,
        Parameters(args): Parameters<DeleteEventArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = delete_group_event(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Create a new group using the active key (kind 9007, NIP-29). Moderation event typically used by relay master key. Returns the event ID and pubkey that signed it for verification. Optional: previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_create_group(
        &self,
        Parameters(args): Parameters<CreateGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = create_group(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Delete an entire group using the active key (kind 9008, NIP-29). Moderation event requiring admin privileges. Permanently removes the group. Returns the event ID and pubkey that signed it for verification. Optional: previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_delete_group(
        &self,
        Parameters(args): Parameters<DeleteGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = delete_group(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Create an invite code for a group using the active key (kind 9009, NIP-29). Moderation event requiring admin privileges. Generated invite can be used with kind 9021 join requests. Returns the event ID and pubkey that signed it for verification. Optional: code, previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_create_invite(
        &self,
        Parameters(args): Parameters<CreateInviteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = create_invite(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Request to join a group using the active key (kind 9021, NIP-29). User event requesting admission to a group. For open groups, automatically approved. For closed groups, requires invite code or manual approval. Returns the event ID and pubkey that signed it for verification. Optional: invite_code, pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_join(
        &self,
        Parameters(args): Parameters<JoinGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = join_group(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Request to leave a group using the active key (kind 9022, NIP-29). User event requesting removal from group. Relay will automatically issue kind 9001 removal event in response. Returns the event ID and pubkey that signed it for verification. Optional: pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_leave(
        &self,
        Parameters(args): Parameters<LeaveGroupArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = self.keystore().await?;
        let ss = self.settings_store().await?;
        let ac = self.ensure_client_from(ks, ss.clone()).await?;
        let result = leave_group(&ac.client, args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}

impl Default for NostrMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for NostrMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Tools: nostr_keys_generate, nostr_keys_import, nostr_keys_export, nostr_keys_verify, nostr_keys_derive_public, nostr_keys_remove, nostr_keys_list, nostr_keys_set_active, nostr_keys_get_active, nostr_keys_rename_label, nostr_relays_set, nostr_relays_connect, nostr_relays_disconnect, nostr_relays_status, nostr_relays_get_info, nostr_nip05_resolve, nostr_nip05_verify, nostr_nip44_encrypt, nostr_nip44_decrypt, nostr_handlers_recommend, nostr_handlers_register, nostr_badges_define, nostr_badges_award, nostr_badges_set_profile, nostr_events_parse_emojis, nostr_events_list, nostr_events_list_long_form, nostr_events_parse_refs, nostr_events_query, nostr_events_search, nostr_events_create_text, nostr_events_sign, nostr_events_post_text, nostr_events_post_thread, nostr_events_post_long_form, nostr_events_post_anonymous, nostr_events_repost, nostr_events_delete, nostr_events_post_group_chat, nostr_events_post_reaction, nostr_events_publish_signed, nostr_events_post_reply, nostr_events_post_comment, nostr_events_create_poll, nostr_events_vote_poll, nostr_events_get_poll_results, nostr_groups_put_user, nostr_groups_remove_user, nostr_groups_edit_metadata, nostr_groups_delete_event, nostr_groups_create_group, nostr_groups_delete_group, nostr_groups_create_invite, nostr_groups_join, nostr_groups_leave, nostr_metadata_set, nostr_metadata_get, nostr_metadata_fetch, nostr_profiles_get, nostr_follows_set, nostr_follows_get, nostr_follows_fetch, nostr_follows_add, nostr_follows_remove"
                    .to_string(),
            ),
        }
    }
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn start_stdio_server() -> anyhow::Result<()> {
    start_stdio_server_with_runtime(NostrMcpRuntime::default()).await
}

pub async fn start_stdio_server_with_runtime(
    runtime_config: NostrMcpRuntime,
) -> anyhow::Result<()> {
    let server_name = runtime_config.server_name.clone();
    let server = NostrMcpServer::with_runtime(runtime_config);
    server.initialize().await?;
    info!("starting {server_name} MCP server (stdio)");
    loop {
        let service = server.clone().serve(stdio()).await?;
        info!("server ready (stdio)");
        tokio::select! {
            _ = service.waiting() => {
                info!("stdio input closed; restarting");
                sleep(Duration::from_millis(200)).await;
                continue;
            }
            _ = wait_for_shutdown() => {
                info!("shutdown signal received");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NostrMcpRuntime, NostrMcpServer};
    use rmcp::ServerHandler;
    use serde::Deserialize;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Deserialize)]
    struct ToolRegistry {
        tools: Vec<ToolEntry>,
    }

    #[derive(Deserialize)]
    struct ToolEntry {
        name: String,
        status: String,
    }

    fn load_tool_registry() -> ToolRegistry {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/registry/tools.json");
        let data = std::fs::read_to_string(&path).expect("read tools registry");
        serde_json::from_str(&data).expect("parse tools registry")
    }

    fn is_generic_tool(tool: &ToolEntry) -> bool {
        tool.status == "stable"
            && !matches!(
                tool.name.as_str(),
                "nostr_config_dir_get" | "nostr_config_dir_set"
            )
    }

    #[test]
    fn tool_router_registers_core_tools() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        for tool in registry.tools.into_iter().filter(is_generic_tool) {
            assert!(
                server.tool_router.has_route(&tool.name),
                "missing tool route: {}",
                tool.name
            );
        }
    }

    #[test]
    fn tool_router_excludes_host_local_runtime_tools() {
        let server = NostrMcpServer::new();
        assert!(!server.tool_router.has_route("nostr_config_dir_get"));
        assert!(!server.tool_router.has_route("nostr_config_dir_set"));
    }

    #[test]
    fn tool_schema_is_present() {
        let server = NostrMcpServer::new();
        let route = server
            .tool_router
            .map
            .get("nostr_keys_generate")
            .expect("tool");
        assert!(!route.attr.input_schema.is_empty());
    }

    #[test]
    fn server_info_advertises_tools() {
        let server = NostrMcpServer::new();
        let info = ServerHandler::get_info(&server);
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn server_state_is_scoped_per_instance() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let server_a = NostrMcpServer::with_runtime(NostrMcpRuntime::new(
            "nostr-a",
            "service-a",
            dir_a.path().to_path_buf(),
        ));
        let server_b = NostrMcpServer::with_runtime(NostrMcpRuntime::new(
            "nostr-b",
            "service-b",
            dir_b.path().to_path_buf(),
        ));

        let keystore_a = server_a.keystore().await.unwrap();
        let settings_a = server_a.settings_store().await.unwrap();
        let keystore_b = server_b.keystore().await.unwrap();
        let settings_b = server_b.settings_store().await.unwrap();
        keystore_a
            .generate("default".into(), true, false)
            .await
            .unwrap();
        keystore_b
            .generate("default".into(), true, false)
            .await
            .unwrap();
        let client_a = server_a.client().await.unwrap();
        let client_b = server_b.client().await.unwrap();

        assert_eq!(server_a.context.runtime.server_name, "nostr-a");
        assert_eq!(server_b.context.runtime.server_name, "nostr-b");
        assert_eq!(
            server_a.context.runtime.paths.config_root,
            dir_a.path().to_path_buf()
        );
        assert_eq!(
            server_b.context.runtime.paths.config_root,
            dir_b.path().to_path_buf()
        );
        assert!(dir_a.path().join("keystore.secret").exists());
        assert!(dir_b.path().join("keystore.secret").exists());
        assert!(Arc::ptr_eq(
            &keystore_a,
            &server_a.keystore().await.unwrap()
        ));
        assert!(Arc::ptr_eq(
            &settings_a,
            &server_a.settings_store().await.unwrap()
        ));
        assert!(!Arc::ptr_eq(&keystore_a, &keystore_b));
        assert!(!Arc::ptr_eq(&settings_a, &settings_b));
        assert_eq!(client_a.active_label, "default");
        assert_eq!(client_b.active_label, "default");
        assert_ne!(client_a.active_pubkey, client_b.active_pubkey);
    }
}
