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

#[cfg(test)]
mod tests {
    use super::GroupModerationService;
    use nostr_mcp_types::groups::{
        CreateGroupArgs, CreateInviteArgs, DeleteEventArgs, DeleteGroupArgs, EditGroupMetadataArgs,
        JoinGroupArgs, LeaveGroupArgs, PutUserArgs, RemoveUserArgs,
    };
    use nostr_sdk::prelude::*;

    fn client() -> Client {
        Client::new(Keys::generate())
    }

    #[tokio::test]
    async fn service_put_user_rejects_invalid_group_id() {
        let err = GroupModerationService::put_user(
            &client(),
            PutUserArgs {
                content: "content".to_string(),
                group_id: " ".to_string(),
                pubkey: Keys::generate().public_key().to_hex(),
                roles: None,
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("group_id must not be empty"));
    }

    #[tokio::test]
    async fn service_remove_user_rejects_invalid_pubkey() {
        let err = GroupModerationService::remove_user(
            &client(),
            RemoveUserArgs {
                content: "content".to_string(),
                group_id: "group-1".to_string(),
                pubkey: "not-a-pubkey".to_string(),
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid public key"));
    }

    #[tokio::test]
    async fn service_edit_metadata_rejects_invalid_picture_url() {
        let err = GroupModerationService::edit_metadata(
            &client(),
            EditGroupMetadataArgs {
                content: "content".to_string(),
                group_id: "group-1".to_string(),
                name: None,
                picture: Some("not-a-url".to_string()),
                about: None,
                unrestricted: None,
                visible: None,
                public: None,
                open: None,
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid picture url"));
    }

    #[tokio::test]
    async fn service_delete_event_rejects_invalid_event_id() {
        let err = GroupModerationService::delete_event(
            &client(),
            DeleteEventArgs {
                content: "content".to_string(),
                group_id: "group-1".to_string(),
                event_id: "bad-id".to_string(),
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid event id"));
    }

    #[tokio::test]
    async fn service_create_group_rejects_invalid_group_id() {
        let err = GroupModerationService::create_group(
            &client(),
            CreateGroupArgs {
                content: "content".to_string(),
                group_id: "bad id".to_string(),
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );
    }

    #[tokio::test]
    async fn service_delete_group_rejects_invalid_group_id() {
        let err = GroupModerationService::delete_group(
            &client(),
            DeleteGroupArgs {
                content: "content".to_string(),
                group_id: "bad id".to_string(),
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );
    }

    #[tokio::test]
    async fn service_create_invite_rejects_empty_code() {
        let err = GroupModerationService::create_invite(
            &client(),
            CreateInviteArgs {
                content: "content".to_string(),
                group_id: "group-1".to_string(),
                code: Some("   ".to_string()),
                previous_refs: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("code must not be empty"));
    }

    #[tokio::test]
    async fn service_join_rejects_empty_invite_code() {
        let err = GroupModerationService::join(
            &client(),
            JoinGroupArgs {
                content: "content".to_string(),
                group_id: "group-1".to_string(),
                invite_code: Some("   ".to_string()),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invite_code must not be empty"));
    }

    #[tokio::test]
    async fn service_leave_rejects_invalid_group_id() {
        let err = GroupModerationService::leave(
            &client(),
            LeaveGroupArgs {
                content: "content".to_string(),
                group_id: "bad id".to_string(),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("group_id must contain only a-z, 0-9, '-' or '_'")
        );
    }
}
