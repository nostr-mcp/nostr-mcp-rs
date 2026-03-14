use super::{NostrMcpServer, core_error};
use nostr_mcp_core::client::ActiveClient;
use nostr_mcp_core::groups::{
    create_group, create_invite, delete_group, delete_group_event, edit_group_metadata, join_group,
    leave_group, put_user, remove_user,
};
use nostr_mcp_policy::{AuthoringAction, CapabilityScope, SignerMethod};
use nostr_mcp_types::groups::{
    CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs, EditGroupMetadataArgs,
    JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

#[tool_router(router = group_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn group_client(&self) -> Result<ActiveClient, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        self.ensure_client_from(keystore, settings_store).await
    }

    #[tool(
        description = "Add or update a user in a group using the active key (kind 9000, NIP-29). Moderation event requiring admin privileges. Use pubkey (hex) to specify user and optional roles array (e.g., ['admin', 'moderator']). Returns the event ID and pubkey that signed it for verification. Optional: roles (array), previous_refs (array), pow (u8), to_relays (urls)"
    )]
    pub async fn nostr_groups_put_user(
        &self,
        Parameters(args): Parameters<PutUserArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9000),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = put_user(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9001),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = remove_user(&active_client.client, args)
            .await
            .map_err(core_error)?;
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9002),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = edit_group_metadata(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9005),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = delete_group_event(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9007),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = create_group(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9008),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = delete_group(&active_client.client, args)
            .await
            .map_err(core_error)?;
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9009),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = create_invite(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9021),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = join_group(&active_client.client, args)
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
        self.authorize_policy_request(self.authoring_request(
            CapabilityScope::ModerateGroups,
            AuthoringAction::Publish,
            Some(SignerMethod::SignEvent),
            Some(9022),
            args.to_relays.clone(),
        ))
        .await?;
        let active_client = self.group_client().await?;
        let result = leave_group(&active_client.client, args)
            .await
            .map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
