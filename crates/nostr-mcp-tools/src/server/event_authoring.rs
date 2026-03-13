use super::{core_error, invalid_params, NostrMcpServer};
use nostr_mcp_core::client::ActiveClient;
use nostr_mcp_core::error::CoreError;
use nostr_mcp_core::polls::{create_poll, vote_poll, CreatePollArgs, VotePollArgs};
use nostr_mcp_core::publish::{
    create_text_event, delete_events, post_anonymous_note, post_group_chat, post_long_form,
    post_reaction, post_repost, post_text_note, post_thread, publish_signed_event,
    sign_unsigned_event, CreateTextArgs, DeleteEventsArgs, PostAnonymousArgs, PostGroupChatArgs,
    PostLongFormArgs, PostReactionArgs, PostRepostArgs, PostTextArgs, PostThreadArgs,
    PublishSignedEventArgs, SignEventArgs,
};
use nostr_mcp_core::replies::{post_comment, post_reply, PostCommentArgs, PostReplyArgs};
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

#[tool_router(router = event_authoring_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn authoring_client(&self) -> Result<ActiveClient, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        self.ensure_client_from(keystore, settings_store).await
    }

    async fn authoring_pubkey(&self) -> Result<PublicKey, ErrorData> {
        let keystore = self.keystore().await?;
        let active = keystore.get_active().await.ok_or_else(|| {
            ErrorData::invalid_params("no active key; set one with nostr_keys_set_active", None)
        })?;
        PublicKey::from_bech32(&active.public_key).map_err(invalid_params)
    }

    #[tool(
        description = "Create an unsigned kind=1 text note using the active key (NIP-01). Returns event JSON with computed id for signing or publishing. Optional: tags (array of tag arrays), created_at (unix timestamp)"
    )]
    pub async fn nostr_events_create_text(
        &self,
        Parameters(args): Parameters<CreateTextArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let pubkey = self.authoring_pubkey().await?;
        let result = create_text_event(pubkey, args).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Sign an unsigned Nostr event JSON using the active key. The unsigned event pubkey must match the active key. Returns signed event JSON."
    )]
    pub async fn nostr_events_sign(
        &self,
        Parameters(args): Parameters<SignEventArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let signer = active_client
            .client
            .signer()
            .await
            .map_err(|err| core_error(CoreError::Nostr(format!("get signer: {err}"))))?;

        let result = sign_unsigned_event(&signer, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a new kind=1 text note to configured relays using the active key. The note will be signed with the currently active key. Returns the event ID and the pubkey that signed it for verification. Optional: pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_text(
        &self,
        Parameters(args): Parameters<PostTextArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = post_text_note(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=1 text note using a one-time keypair (anonymous). Returns the event ID and pubkey used to sign it. Optional: tags (array of tag arrays), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_anonymous(
        &self,
        Parameters(args): Parameters<PostAnonymousArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = post_anonymous_note(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Repost a signed event (NIP-18). The target event JSON must be valid and signed. Optional: relay_hint (url), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_repost(
        &self,
        Parameters(args): Parameters<PostRepostArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = post_repost(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Delete events or coordinates (NIP-9). Provide event_ids (hex), coordinates (kind:pubkey:identifier), or both. Optional: reason, pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_delete(
        &self,
        Parameters(args): Parameters<DeleteEventsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = delete_events(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = post_thread(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a kind=30023 long-form note using the active key (NIP-23). Returns the event ID and pubkey that signed it for verification. Optional: title, summary, image, published_at (unix timestamp), identifier (d tag), hashtags, pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_long_form(
        &self,
        Parameters(args): Parameters<PostLongFormArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = post_long_form(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = post_group_chat(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = post_reaction(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Publish a fully signed Nostr event (NIP-01). Validates event structure and signature before publishing. Optional: to_relays (urls)"
    )]
    pub async fn nostr_events_publish_signed(
        &self,
        Parameters(args): Parameters<PublishSignedEventArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = publish_signed_event(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Post a reply/comment using the active key. Automatically uses NIP-10 (kind 1 reply) for kind 1 text notes, or NIP-22 (kind 1111 comment) for all other content types. Use reply_to_id, reply_to_pubkey, and reply_to_kind to specify the parent target. For kind 1 threads, optionally provide root_event_id and root_event_pubkey. For non-kind1 threaded comments where the root differs from the parent, also provide root_event_id, root_event_pubkey, and root_event_kind. Returns the event ID and pubkey that signed it for verification. Optional: root_event_id (hex), root_event_pubkey (hex), root_event_kind (u16), mentioned_pubkeys (hex array), relay_hint (url), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_events_post_reply(
        &self,
        Parameters(args): Parameters<PostReplyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.authoring_client().await?;
        let result = post_reply(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = post_comment(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = create_poll(&active_client.client, args)
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
        let active_client = self.authoring_client().await?;
        let result = vote_poll(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
