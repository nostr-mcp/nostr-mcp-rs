use crate::error::CoreError;
use nostr_mcp_types::groups::{
    CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs, EditGroupMetadataArgs,
    JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;

pub struct GroupModerationService;

impl GroupModerationService {
    pub async fn put_user(client: &Client, args: PutUserArgs) -> Result<SendResult, CoreError> {
        crate::groups::put_user(client, args).await
    }

    pub async fn remove_user(
        client: &Client,
        args: RemoveUserArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::remove_user(client, args).await
    }

    pub async fn edit_metadata(
        client: &Client,
        args: EditGroupMetadataArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::edit_group_metadata(client, args).await
    }

    pub async fn delete_event(
        client: &Client,
        args: DeleteEventArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::delete_group_event(client, args).await
    }

    pub async fn create_group(
        client: &Client,
        args: CreateGroupArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::create_group(client, args).await
    }

    pub async fn delete_group(
        client: &Client,
        args: DeleteGroupArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::delete_group(client, args).await
    }

    pub async fn create_invite(
        client: &Client,
        args: CreateInviteArgs,
    ) -> Result<SendResult, CoreError> {
        crate::groups::create_invite(client, args).await
    }

    pub async fn join(client: &Client, args: JoinGroupArgs) -> Result<SendResult, CoreError> {
        crate::groups::join_group(client, args).await
    }

    pub async fn leave(client: &Client, args: LeaveGroupArgs) -> Result<SendResult, CoreError> {
        crate::groups::leave_group(client, args).await
    }
}
