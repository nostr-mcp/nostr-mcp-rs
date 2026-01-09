use crate::util;
use nostr_mcp_core::client::{ensure_client, reset_cached_client};
use nostr_mcp_core::error::CoreError;
use nostr_mcp_core::events::{
    list_events, subscription_targets_mentions_me, subscription_targets_my_metadata,
    subscription_targets_my_notes, EventsListArgs,
};
use nostr_mcp_core::follows::{
    fetch_follows, publish_follows, AddFollowArgs, PublishFollowsResult, RemoveFollowArgs,
    SetFollowsArgs,
};
use nostr_mcp_core::groups::{
    create_group, create_invite, delete_group, delete_group_event, edit_group_metadata, join_group,
    leave_group, put_user, remove_user, CreateGroupArgs, CreateInviteArgs, DeleteEventArgs,
    DeleteGroupArgs, EditGroupMetadataArgs, JoinGroupArgs, LeaveGroupArgs, PutUserArgs,
    RemoveUserArgs,
};
use nostr_mcp_core::key_store::{
    EmptyArgs, ExportArgs, GenerateArgs, ImportArgs, KeyStore, RemoveArgs, RenameLabelArgs,
    SetActiveArgs,
};
use nostr_mcp_core::keys::{derive_public_from_private, verify_key, DerivePublicArgs, VerifyArgs};
use nostr_mcp_core::metadata::{
    args_to_profile, fetch_metadata, publish_metadata, FetchMetadataArgs, MetadataResult,
    SetMetadataArgs,
};
use nostr_mcp_core::nip01;
use nostr_mcp_core::polls::{
    create_poll, get_poll_results, vote_poll, CreatePollArgs, GetPollResultsArgs, VotePollArgs,
};
use nostr_mcp_core::publish::{
    post_group_chat, post_reaction, post_text_note, post_thread, PostGroupChatArgs, PostReactionArgs,
    PostTextArgs, PostThreadArgs,
};
use nostr_mcp_core::relays::{
    connect_relays, disconnect_relays, get_relay_urls, list_relays, set_relays, status_summary,
    RelaysConnectArgs, RelaysDisconnectArgs, RelaysSetArgs,
};
use nostr_mcp_core::replies::{post_comment, post_reply, PostCommentArgs, PostReplyArgs};
#[cfg(not(feature = "keyring"))]
use nostr_mcp_core::secrets::InMemorySecretStore;
use nostr_mcp_core::secrets::SecretStore;
#[cfg(feature = "keyring")]
use nostr_mcp_core::secrets::KeyringSecretStore;
use nostr_mcp_core::settings::{FollowEntry, KeySettings, SettingsStore};
use nostr::nips::nip19::ToBech32;
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, ErrorData, Implementation, ProtocolVersion, ServerCapabilities,
        ServerInfo,
    },
    schemars::JsonSchema,
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{OnceCell, RwLock};
use tokio::time::{sleep, Duration};
use tracing::info;

static KEYSTORE: OnceCell<RwLock<Arc<KeyStore>>> = OnceCell::const_new();
static SETTINGS_STORE: OnceCell<RwLock<Arc<SettingsStore>>> = OnceCell::const_new();

fn secret_store() -> Arc<dyn SecretStore> {
    #[cfg(feature = "keyring")]
    {
        Arc::new(KeyringSecretStore::new("goostr"))
    }
    #[cfg(not(feature = "keyring"))]
    {
        Arc::new(InMemorySecretStore::new())
    }
}

async fn load_or_init_keystore(path: PathBuf) -> Result<KeyStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret()?);
    let legacy_path = Some(util::legacy_keys_json_path());
    KeyStore::load_or_init(path, pass, secret_store(), legacy_path).await
}

async fn load_or_init_settings(path: PathBuf) -> Result<SettingsStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret()?);
    SettingsStore::load_or_init(path, pass).await
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

#[derive(Clone)]
pub struct NostrMcpServer {
    tool_router: ToolRouter<Self>,
}

impl NostrMcpServer {
    async fn keystore() -> Result<Arc<KeyStore>, ErrorData> {
        let cell = KEYSTORE
            .get_or_try_init(|| async {
                let path = util::nostr_index_path();
                let ks = load_or_init_keystore(path).await?;
                Ok::<RwLock<Arc<KeyStore>>, CoreError>(RwLock::new(Arc::new(ks)))
            })
            .await
            .map_err(core_error)?;
        let guard = cell.read().await;
        Ok(guard.clone())
    }

    async fn settings_store() -> Result<Arc<SettingsStore>, ErrorData> {
        let cell = SETTINGS_STORE
            .get_or_try_init(|| async {
                let path = util::nostr_settings_path();
                let ss = load_or_init_settings(path).await?;
                Ok::<RwLock<Arc<SettingsStore>>, CoreError>(RwLock::new(Arc::new(ss)))
            })
            .await
            .map_err(core_error)?;
        let guard = cell.read().await;
        Ok(guard.clone())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConfigDirArgs {
    pub path: Option<String>,
}

#[tool_router]
impl NostrMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Generate a new Nostr keypair")]
    pub async fn nostr_keys_generate(
        &self,
        Parameters(args): Parameters<GenerateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let entry = ks
            .generate(
                args.label,
                args.make_active.unwrap_or(true),
                args.persist_secret.unwrap_or(true),
            )
            .await
            .map_err(core_error)?;
        reset_cached_client()
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Import secret key (nsec or npub)")]
    pub async fn nostr_keys_import(
        &self,
        Parameters(args): Parameters<ImportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let entry = ks
            .import_secret(
                args.label,
                args.key_material,
                args.make_active.unwrap_or(true),
                args.persist_secret.unwrap_or(true),
            )
            .await
            .map_err(core_error)?;
        reset_cached_client()
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Remove a key by label")]
    pub async fn nostr_keys_remove(
        &self,
        Parameters(args): Parameters<RemoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let removed = ks
            .remove(args.label)
            .await
            .map_err(core_error)?;
        reset_cached_client()
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "removed": removed.is_some() }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "List all stored keys (metadata only)")]
    pub async fn nostr_keys_list(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let keys = ks.list().await;
        let active_label = ks.get_active().await.map(|k| k.label);
        let payload =
            serde_json::json!({ "keys": keys, "count": keys.len(), "active": active_label });
        let content = Content::json(payload)?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Set the active key by label")]
    pub async fn nostr_keys_set_active(
        &self,
        Parameters(args): Parameters<SetActiveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let entry = ks
            .set_active(args.label)
            .await
            .map_err(core_error)?;
        reset_cached_client()
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get the active key (metadata only)")]
    pub async fn nostr_keys_active(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let active = ks.get_active().await;
        let content = Content::json(serde_json::json!(active))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Rename a key's label; when 'from' is omitted, renames the active key")]
    pub async fn nostr_keys_rename_label(
        &self,
        Parameters(args): Parameters<RenameLabelArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let source = match args.from {
            Some(f) => f,
            None => ks
                .get_active()
                .await
                .map(|k| k.label)
                .ok_or_else(|| ErrorData::invalid_params("no active key to rename", None))?,
        };
        let entry = ks
            .rename_label(source, args.to)
            .await
            .map_err(core_error)?;
        reset_cached_client()
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Export a key in various formats (npub/nsec/hex). Exports active key if label not specified. WARNING: include_private=true will expose your private key"
    )]
    pub async fn nostr_keys_export(
        &self,
        Parameters(args): Parameters<ExportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let result = ks
            .export_key(args.label, args.format, args.include_private)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Verify a Nostr key format and validity. Checks if a string is a valid npub, nsec, or hex key"
    )]
    pub async fn nostr_keys_verify(
        &self,
        Parameters(args): Parameters<VerifyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = verify_key(&args.key);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Derive public key from a private key. Accepts nsec or hex private key format"
    )]
    pub async fn nostr_keys_get_public_from_private(
        &self,
        Parameters(args): Parameters<DerivePublicArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = derive_public_from_private(&args.private_key)
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get or set the directory used to persist the key index (no secrets)")]
    pub async fn nostr_config_dir(
        &self,
        Parameters(args): Parameters<ConfigDirArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(p) = args.path {
            std::env::set_var("GOOSTR_DIR", p);
            let path = util::nostr_index_path();
            let new_store = load_or_init_keystore(path)
                .await
                .map_err(core_error)?;
            let cell = KEYSTORE
                .get_or_try_init(|| async {
                    let path = util::nostr_index_path();
                    let ks = load_or_init_keystore(path).await?;
                    Ok::<RwLock<Arc<KeyStore>>, CoreError>(RwLock::new(Arc::new(ks)))
                })
                .await
                .map_err(core_error)?;
            let mut w = cell.write().await;
            *w = Arc::new(new_store);
            reset_cached_client()
                .await
                .map_err(core_error)?;
        }
        let current = util::nostr_config_root();
        let content = Content::json(serde_json::json!({
            "dir": current,
            "file": util::nostr_index_path()
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Set relays and connect. Requires an active nostr key. read_write: read|write|both"
    )]
    pub async fn nostr_relays_set(
        &self,
        Parameters(args): Parameters<RelaysSetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        set_relays(&ac.client, args)
            .await
            .map_err(core_error)?;

        let relay_urls = get_relay_urls(&ac.client).await;
        let pubkey_hex = ac.active_pubkey.to_hex();
        let existing = ss.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: relay_urls.clone(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: existing
                .as_ref()
                .map(|s| s.follows.clone())
                .unwrap_or_default(),
        };
        ss.save_settings(pubkey_hex, settings)
            .await
            .map_err(core_error)?;

        let rows = list_relays(&ac.client)
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        connect_relays(&ac.client, args)
            .await
            .map_err(core_error)?;
        let rows = list_relays(&ac.client)
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        disconnect_relays(&ac.client, args)
            .await
            .map_err(core_error)?;

        let relay_urls = get_relay_urls(&ac.client).await;
        let pubkey_hex = ac.active_pubkey.to_hex();
        let existing = ss.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: relay_urls.clone(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: existing
                .as_ref()
                .map(|s| s.follows.clone())
                .unwrap_or_default(),
        };
        ss.save_settings(pubkey_hex, settings)
            .await
            .map_err(core_error)?;

        let rows = list_relays(&ac.client)
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let rows = list_relays(&ac.client)
            .await
            .map_err(core_error)?;
        let summary = status_summary(&ac.client)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!({ "summary": summary, "relays": rows }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch events using presets or custom filters. Presets: my_notes, mentions_me, my_metadata, by_author, by_kind. For by_kind: specify 'kind' parameter. Optional: limit, timeout_secs, since (unix timestamp), until (unix timestamp), author_npub (for by_author)"
    )]
    pub async fn nostr_events_list(
        &self,
        Parameters(args): Parameters<EventsListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        nip01::validate_time_bounds(args.since, args.until)
            .map_err(core_error)?;
        nip01::validate_limit(args.limit)
            .map_err(core_error)?;
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;

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
                let pk = PublicKey::from_bech32(npub_ref)
                    .map_err(invalid_params)?;

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
                    let pk = PublicKey::from_bech32(npub_ref)
                        .map_err(invalid_params)?;
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
        description = "Post a new kind=1 text note to configured relays using the active key. The note will be signed with the currently active key. Returns the event ID and the pubkey that signed it for verification. Optional: pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_text(
        &self,
        Parameters(args): Parameters<PostTextArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_text_note(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=11 thread to configured relays using the active key. Threads are discussion topics that can be replied to with kind 1111 comments. Requires subject (thread title) and content. Returns the event ID and pubkey that signed it for verification. Optional: hashtags (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_thread(
        &self,
        Parameters(args): Parameters<PostThreadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_thread(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=9 group chat message using the active key (NIP-C7). Modern standard for group discussions in NIP-29 relay-based groups. Requires content and group_id. For replies, include reply_to_id (and optionally reply_to_relay, reply_to_pubkey). Returns the event ID and pubkey that signed it for verification. Optional: reply_to_id (hex), reply_to_relay (url), reply_to_pubkey (hex), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_group_chat(
        &self,
        Parameters(args): Parameters<PostGroupChatArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_group_chat(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=7 reaction event (like, emoji) to another event using the active key. Content defaults to '+' (like). Use event_id (hex) and event_pubkey (hex) to specify the target event. Returns the event ID and pubkey that signed it for verification. Optional: content (emoji or +/-), event_kind (u16), relay_hint (url), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_reaction(
        &self,
        Parameters(args): Parameters<PostReactionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_reaction(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a reply/comment using the active key. Automatically uses NIP-10 (kind 1 reply) for kind 1 text notes, or NIP-22 (kind 1111 comment) for all other content types. Use reply_to_id, reply_to_pubkey, and reply_to_kind to specify the target. For threaded replies to kind 1 notes, optionally provide root_event_id and root_event_pubkey. Returns the event ID and pubkey that signed it for verification. Optional: root_event_id (hex), root_event_pubkey (hex), mentioned_pubkeys (hex array), relay_hint (url), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_reply(
        &self,
        Parameters(args): Parameters<PostReplyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_reply(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=1111 comment event to another event using the active key. Comments support threaded discussions on any content. Use root_event_id, root_event_pubkey, and root_event_kind to specify the root content. For nested comments, also provide parent_event_id, parent_event_pubkey, and parent_event_kind. Returns the event ID and pubkey that signed it for verification. Optional: parent_event_id (hex), parent_event_pubkey (hex), parent_event_kind (u16), relay_hint (url), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_comment(
        &self,
        Parameters(args): Parameters<PostCommentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = post_comment(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Create a kind=1068 poll using the active key (NIP-88). Polls allow users to vote on questions with multiple options. Requires question, options array (each with option_id and label), and relay_urls array where responses should be published. Returns the event ID and pubkey that signed it for verification. Optional: poll_type ('singlechoice' or 'multiplechoice', default: 'singlechoice'), ends_at (unix timestamp), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_create_poll(
        &self,
        Parameters(args): Parameters<CreatePollArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = create_poll(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Vote on a kind=1068 poll using the active key (NIP-88). Creates a kind=1018 poll response event. Requires poll_event_id and option_ids array (single option for singlechoice, multiple for multiplechoice). Returns the event ID and pubkey that signed it for verification. Optional: pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_vote_poll(
        &self,
        Parameters(args): Parameters<VotePollArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = vote_poll(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Get results for a kind=1068 poll (NIP-88). Fetches the poll and all kind=1018 responses, counts votes (one per pubkey, most recent wins), and returns results with vote counts per option. Respects poll end time if set. Returns poll details, vote counts, and whether poll has ended. Optional: timeout_secs (default: 10)"
    )]
    pub async fn nostr_events_get_poll_results(
        &self,
        Parameters(args): Parameters<GetPollResultsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let results = get_poll_results(&ac.client, &args.poll_event_id, args.timeout_secs.unwrap_or(10))
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = put_user(&ac.client, args)
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = remove_user(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Edit group metadata using the active key (kind 9002, NIP-29). Moderation event requiring admin privileges. Supports partial updates - only include fields to change. Returns the event ID and pubkey that signed it for verification. Optional: name, picture, about, public (bool), open (bool), previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_edit_metadata(
        &self,
        Parameters(args): Parameters<EditGroupMetadataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = create_group(&ac.client, args)
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = delete_group(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Create an invite code for a group using the active key (kind 9009, NIP-29). Moderation event requiring admin privileges. Generated invite can be used with kind 9021 join requests. Returns the event ID and pubkey that signed it for verification. Optional: previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_create_invite(
        &self,
        Parameters(args): Parameters<CreateInviteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = create_invite(&ac.client, args)
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = join_group(&ac.client, args)
            .await
            .map_err(core_error)?;
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;
        let result = leave_group(&ac.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Set kind 0 metadata (profile) for the active key. All fields are optional. Set publish=true to broadcast to relays immediately using the active key (default: true). Returns the pubkey that signed the metadata event for verification"
    )]
    pub async fn nostr_metadata_set(
        &self,
        Parameters(args): Parameters<SetMetadataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let profile = args_to_profile(&args);

        let existing = ss.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|s| s.relays.clone())
                .unwrap_or_default(),
            metadata: Some(profile.clone()),
            follows: existing
                .as_ref()
                .map(|s| s.follows.clone())
                .unwrap_or_default(),
        };
        ss.save_settings(pubkey_hex.clone(), settings)
            .await
            .map_err(core_error)?;

        let result = if args.publish.unwrap_or(true) {
            let ac = ensure_client(ks, ss)
                .await
                .map_err(core_error)?;
            publish_metadata(&ac.client, &profile)
                .await
                .map_err(core_error)?
        } else {
            MetadataResult {
                saved: true,
                published: false,
                event_id: None,
                pubkey: None,
                success_relays: vec![],
                failed_relays: std::collections::HashMap::new(),
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let metadata = ss.get_settings(&pubkey_hex).await.and_then(|s| s.metadata);

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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks.clone(), ss)
            .await
            .map_err(core_error)?;

        let target_pubkey = if let Some(label) = args.label {
            let keys = ks.list().await;
            let entry = keys.iter().find(|k| k.label == label).ok_or_else(|| {
                ErrorData::invalid_params(format!("key with label '{}' not found", label), None)
            })?;
            PublicKey::from_bech32(&entry.public_key)
                .map_err(invalid_params)?
        } else {
            ac.active_pubkey
        };

        let metadata = fetch_metadata(&ac.client, &target_pubkey)
            .await
            .map_err(core_error)?;

        let content = Content::json(serde_json::json!({
            "pubkey": target_pubkey.to_bech32().unwrap(),
            "metadata": metadata
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Set kind 3 follow list for the active key. Replaces entire follow list. Set publish=true to broadcast to relays immediately (default: true). Each follow must have pubkey (hex), optional relay_url, and optional petname. Returns the event ID and pubkey that signed it for verification"
    )]
    pub async fn nostr_follows_set(
        &self,
        Parameters(args): Parameters<SetFollowsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let existing = ss.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|s| s.relays.clone())
                .unwrap_or_default(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: args.follows.clone(),
        };
        ss.save_settings(pubkey_hex.clone(), settings)
            .await
            .map_err(core_error)?;

        let result = if args.publish.unwrap_or(true) {
            let ac = ensure_client(ks, ss)
                .await
                .map_err(core_error)?;
            publish_follows(&ac.client, &args.follows)
                .await
                .map_err(core_error)?
        } else {
            PublishFollowsResult {
                saved: true,
                published: false,
                event_id: None,
                pubkey: None,
                success_relays: vec![],
                failed_relays: std::collections::HashMap::new(),
            }
        };

        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get kind 3 follow list for the active key from local settings")]
    pub async fn nostr_follows_get(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let follows = ss
            .get_settings(&pubkey_hex)
            .await
            .map(|s| s.follows)
            .unwrap_or_default();

        let content = Content::json(serde_json::json!({
            "pubkey": active.public_key,
            "follows": follows,
            "count": follows.len()
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;
        let ac = ensure_client(ks, ss.clone())
            .await
            .map_err(core_error)?;

        let follows = fetch_follows(&ac.client, &ac.active_pubkey)
            .await
            .map_err(core_error)?;

        let pubkey_hex = ac.active_pubkey.to_hex();
        let existing = ss.get_settings(&pubkey_hex).await;
        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|s| s.relays.clone())
                .unwrap_or_default(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: follows.clone(),
        };
        ss.save_settings(pubkey_hex, settings)
            .await
            .map_err(core_error)?;

        let content = Content::json(serde_json::json!({
            "pubkey": ac.active_pubkey.to_bech32().unwrap(),
            "follows": follows,
            "count": follows.len()
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let existing = ss.get_settings(&pubkey_hex).await;
        let mut follows = existing
            .as_ref()
            .map(|s| s.follows.clone())
            .unwrap_or_default();

        if follows.iter().any(|f| f.pubkey == args.pubkey) {
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

        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|s| s.relays.clone())
                .unwrap_or_default(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: follows.clone(),
        };
        ss.save_settings(pubkey_hex.clone(), settings)
            .await
            .map_err(core_error)?;

        let result = if args.publish.unwrap_or(true) {
            let ac = ensure_client(ks, ss)
                .await
                .map_err(core_error)?;
            publish_follows(&ac.client, &follows)
                .await
                .map_err(core_error)?
        } else {
            PublishFollowsResult {
                saved: true,
                published: false,
                event_id: None,
                pubkey: None,
                success_relays: vec![],
                failed_relays: std::collections::HashMap::new(),
            }
        };

        let content = Content::json(serde_json::json!({
            "follows": follows,
            "count": follows.len(),
            "result": result
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
        let ks = Self::keystore().await?;
        let ss = Self::settings_store().await?;

        let active = ks.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        let pubkey = PublicKey::from_bech32(&active.public_key)
            .map_err(invalid_params)?;
        let pubkey_hex = pubkey.to_hex();

        let existing = ss.get_settings(&pubkey_hex).await;
        let mut follows = existing
            .as_ref()
            .map(|s| s.follows.clone())
            .unwrap_or_default();

        let original_len = follows.len();
        follows.retain(|f| f.pubkey != args.pubkey);

        if follows.len() == original_len {
            return Err(ErrorData::invalid_params(
                format!("not following pubkey: {}", args.pubkey),
                None,
            ));
        }

        let settings = KeySettings {
            relays: existing
                .as_ref()
                .map(|s| s.relays.clone())
                .unwrap_or_default(),
            metadata: existing.as_ref().and_then(|s| s.metadata.clone()),
            follows: follows.clone(),
        };
        ss.save_settings(pubkey_hex.clone(), settings)
            .await
            .map_err(core_error)?;

        let result = if args.publish.unwrap_or(true) {
            let ac = ensure_client(ks, ss)
                .await
                .map_err(core_error)?;
            publish_follows(&ac.client, &follows)
                .await
                .map_err(core_error)?
        } else {
            PublishFollowsResult {
                saved: true,
                published: false,
                event_id: None,
                pubkey: None,
                success_relays: vec![],
                failed_relays: std::collections::HashMap::new(),
            }
        };

        let content = Content::json(serde_json::json!({
            "follows": follows,
            "count": follows.len(),
            "result": result
        }))?;
        Ok(CallToolResult::success(vec![content]))
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
                "Tools: nostr_keys_generate, nostr_keys_import, nostr_keys_export, nostr_keys_verify, nostr_keys_get_public_from_private, nostr_keys_remove, nostr_keys_list, nostr_keys_set_active, nostr_keys_active, nostr_keys_rename_label, nostr_config_dir, nostr_relays_set, nostr_relays_connect, nostr_relays_disconnect, nostr_relays_status, nostr_events_list, nostr_events_post_text, nostr_events_post_thread, nostr_events_post_group_chat, nostr_events_post_reaction, nostr_events_post_reply, nostr_events_post_comment, nostr_events_create_poll, nostr_events_vote_poll, nostr_events_get_poll_results, nostr_groups_put_user, nostr_groups_remove_user, nostr_groups_edit_metadata, nostr_groups_delete_event, nostr_groups_create_group, nostr_groups_delete_group, nostr_groups_create_invite, nostr_groups_join, nostr_groups_leave, nostr_metadata_set, nostr_metadata_get, nostr_metadata_fetch, nostr_follows_set, nostr_follows_get, nostr_follows_fetch, nostr_follows_add, nostr_follows_remove"
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
    info!("starting goostr MCP server (stdio)");
    loop {
        let service = NostrMcpServer::new().serve(stdio()).await?;
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
    use super::NostrMcpServer;
    use rmcp::ServerHandler;

    #[test]
    fn tool_router_registers_core_tools() {
        let server = NostrMcpServer::new();
        assert!(server.tool_router.has_route("nostr_keys_generate"));
        assert!(server.tool_router.has_route("nostr_relays_set"));
        assert!(server.tool_router.has_route("nostr_events_list"));
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
}
