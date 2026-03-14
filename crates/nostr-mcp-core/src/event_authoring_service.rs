use crate::error::CoreError;
use nostr_mcp_types::polls::{CreatePollArgs, VotePollArgs};
use nostr_mcp_types::publish::{
    CreateTextArgs, CreateTextResult, DeleteEventsArgs, PostAnonymousArgs, PostGroupChatArgs,
    PostLongFormArgs, PostReactionArgs, PostRepostArgs, PostTextArgs, PostThreadArgs,
    PublishSignedEventArgs, SendResult, SignEventArgs, SignEventResult,
};
use nostr_mcp_types::replies::{PostCommentArgs, PostReplyArgs};
use nostr_sdk::prelude::*;

pub struct EventAuthoringService;

impl EventAuthoringService {
    pub fn create_text(
        pubkey: PublicKey,
        args: CreateTextArgs,
    ) -> Result<CreateTextResult, CoreError> {
        crate::publish::create_text_event(pubkey, args)
    }

    pub async fn sign_unsigned<T>(
        signer: &T,
        args: SignEventArgs,
    ) -> Result<SignEventResult, CoreError>
    where
        T: NostrSigner,
    {
        crate::publish::sign_unsigned_event(signer, args).await
    }

    pub async fn post_text(client: &Client, args: PostTextArgs) -> Result<SendResult, CoreError> {
        crate::publish::post_text_note(client, args).await
    }

    pub async fn post_anonymous(
        client: &Client,
        args: PostAnonymousArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::post_anonymous_note(client, args).await
    }

    pub async fn repost(client: &Client, args: PostRepostArgs) -> Result<SendResult, CoreError> {
        crate::publish::post_repost(client, args).await
    }

    pub async fn delete(client: &Client, args: DeleteEventsArgs) -> Result<SendResult, CoreError> {
        crate::publish::delete_events(client, args).await
    }

    pub async fn post_thread(
        client: &Client,
        args: PostThreadArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::post_thread(client, args).await
    }

    pub async fn post_long_form(
        client: &Client,
        args: PostLongFormArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::post_long_form(client, args).await
    }

    pub async fn post_group_chat(
        client: &Client,
        args: PostGroupChatArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::post_group_chat(client, args).await
    }

    pub async fn post_reaction(
        client: &Client,
        args: PostReactionArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::post_reaction(client, args).await
    }

    pub async fn publish_signed(
        client: &Client,
        args: PublishSignedEventArgs,
    ) -> Result<SendResult, CoreError> {
        crate::publish::publish_signed_event(client, args).await
    }

    pub async fn post_reply(client: &Client, args: PostReplyArgs) -> Result<SendResult, CoreError> {
        crate::replies::post_reply(client, args).await
    }

    pub async fn post_comment(
        client: &Client,
        args: PostCommentArgs,
    ) -> Result<SendResult, CoreError> {
        crate::replies::post_comment(client, args).await
    }

    pub async fn create_poll(
        client: &Client,
        args: CreatePollArgs,
    ) -> Result<SendResult, CoreError> {
        crate::polls::create_poll(client, args).await
    }

    pub async fn vote_poll(client: &Client, args: VotePollArgs) -> Result<SendResult, CoreError> {
        crate::polls::vote_poll(client, args).await
    }
}

#[cfg(test)]
mod tests {
    use super::EventAuthoringService;
    use nostr_mcp_types::publish::{CreateTextArgs, SignEventArgs};
    use nostr_sdk::prelude::*;

    #[test]
    fn service_create_text_preserves_unsigned_shape() {
        let keys = Keys::generate();
        let result = EventAuthoringService::create_text(
            keys.public_key(),
            CreateTextArgs {
                content: "hello".to_string(),
                tags: None,
                created_at: Some(1_700_000_000),
            },
        )
        .unwrap();

        assert_eq!(result.pubkey, keys.public_key().to_hex());
        assert!(!result.event_id.is_empty());
        assert!(result.unsigned_event_json.contains("\"content\":\"hello\""));
    }

    #[tokio::test]
    async fn service_sign_unsigned_rejects_mismatched_pubkey() {
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let unsigned = EventBuilder::text_note("hello").build(keys_a.public_key());

        let err = EventAuthoringService::sign_unsigned(
            &keys_b,
            SignEventArgs {
                unsigned_event_json: unsigned.as_json(),
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("unsigned event pubkey does not match active key")
        );
    }
}
