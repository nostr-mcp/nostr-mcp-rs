use crate::error::CoreError;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct SendResult {
    pub id: String,
    pub success: Vec<String>,
    pub failed: HashMap<String, String>,
    pub pubkey: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostTextArgs {
    pub content: String,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostThreadArgs {
    pub content: String,
    pub subject: String,
    pub hashtags: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostGroupChatArgs {
    pub content: String,
    pub group_id: String,
    pub reply_to_id: Option<String>,
    pub reply_to_relay: Option<String>,
    pub reply_to_pubkey: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostReactionArgs {
    pub event_id: String,
    pub event_pubkey: String,
    pub content: Option<String>,
    pub event_kind: Option<u16>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublishSignedEventArgs {
    pub event_json: String,
    pub to_relays: Option<Vec<String>>,
}

pub async fn publish_event_builder(
    client: &Client,
    builder: EventBuilder,
    to_relays: Option<Vec<String>>,
) -> Result<SendResult, CoreError> {
    let out = if let Some(urls) = to_relays {
        client
            .send_event_builder_to(urls, builder)
            .await
            .map_err(|e| CoreError::Nostr(format!("send event: {e}")))?
    } else {
        client
            .send_event_builder(builder)
            .await
            .map_err(|e| CoreError::Nostr(format!("send event: {e}")))?
    };

    let pubkey = client
        .signer()
        .await
        .map_err(|e| CoreError::Nostr(format!("get signer: {e}")))?
        .get_public_key()
        .await
        .map_err(|e| CoreError::Nostr(format!("get signer pubkey: {e}")))?
        .to_hex();

    let id = out.id().to_string();
    let success = out.success.into_iter().map(|u| u.to_string()).collect();
    let failed = out
        .failed
        .into_iter()
        .map(|(u, e)| (u.to_string(), e.to_string()))
        .collect();

    Ok(SendResult {
        id,
        success,
        failed,
        pubkey,
    })
}

pub async fn publish_signed_event(
    client: &Client,
    args: PublishSignedEventArgs,
) -> Result<SendResult, CoreError> {
    let event = parse_signed_event(&args.event_json)?;
    let out = if let Some(urls) = args.to_relays {
        client
            .send_event_to(urls, &event)
            .await
            .map_err(|e| CoreError::Nostr(format!("send event: {e}")))?
    } else {
        client
            .send_event(&event)
            .await
            .map_err(|e| CoreError::Nostr(format!("send event: {e}")))?
    };

    let id = out.id().to_string();
    let success = out.success.into_iter().map(|u| u.to_string()).collect();
    let failed = out
        .failed
        .into_iter()
        .map(|(u, e)| (u.to_string(), e.to_string()))
        .collect();

    Ok(SendResult {
        id,
        success,
        failed,
        pubkey: event.pubkey.to_hex(),
    })
}

fn parse_signed_event(event_json: &str) -> Result<Event, CoreError> {
    let event =
        Event::from_json(event_json).map_err(|e| CoreError::invalid_input(format!("invalid event json: {e}")))?;
    event
        .verify()
        .map_err(|e| CoreError::invalid_input(format!("invalid event signature: {e}")))?;
    Ok(event)
}

pub async fn post_text_note(client: &Client, args: PostTextArgs) -> Result<SendResult, CoreError> {
    let mut builder = EventBuilder::text_note(args.content);
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }
    publish_event_builder(client, builder, args.to_relays).await
}

fn thread_tags(args: &PostThreadArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["subject".to_string(), args.subject.clone()])
            .map_err(|e| CoreError::Nostr(format!("subject tag: {e}")))?,
    );

    if let Some(hashtags) = &args.hashtags {
        for hashtag in hashtags {
            tags.push(
                Tag::parse(&["t".to_string(), hashtag.clone()])
                    .map_err(|e| CoreError::Nostr(format!("hashtag tag: {e}")))?,
            );
        }
    }

    Ok(tags)
}

pub async fn post_thread(
    client: &Client,
    args: PostThreadArgs,
) -> Result<SendResult, CoreError> {
    let tags = thread_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(11), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

fn group_chat_tags(args: &PostGroupChatArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(
        Tag::parse(&["h".to_string(), args.group_id.clone()])
            .map_err(|e| CoreError::Nostr(format!("group tag: {e}")))?,
    );

    if let Some(ref reply_id) = args.reply_to_id {
        let event_id = EventId::from_hex(reply_id)
            .map_err(|e| CoreError::invalid_input(format!("invalid event id {reply_id}: {e}")))?;

        let relay = args.reply_to_relay.as_deref().unwrap_or("");
        let pubkey = args.reply_to_pubkey.as_deref().unwrap_or("");

        tags.push(
            Tag::parse(&[
                "q".to_string(),
                event_id.to_hex(),
                relay.to_string(),
                pubkey.to_string(),
            ])
            .map_err(|e| CoreError::Nostr(format!("reply tag: {e}")))?,
        );
    }

    Ok(tags)
}

pub async fn post_group_chat(
    client: &Client,
    args: PostGroupChatArgs,
) -> Result<SendResult, CoreError> {
    let tags = group_chat_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(9), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn post_reaction(
    client: &Client,
    args: PostReactionArgs,
) -> Result<SendResult, CoreError> {
    let (target, content) = reaction_payload(&args)?;

    let mut builder = EventBuilder::reaction(target, content);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

fn reaction_payload(args: &PostReactionArgs) -> Result<(ReactionTarget, String), CoreError> {
    let event_id = EventId::from_hex(&args.event_id)
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {}: {e}", args.event_id)))?;
    let event_pubkey = PublicKey::from_hex(&args.event_pubkey).map_err(|e| {
        CoreError::invalid_input(format!("invalid event pubkey {}: {e}", args.event_pubkey))
    })?;

    let content = args.content.clone().unwrap_or_else(|| "+".to_string());
    let event_kind = args.event_kind.map(Kind::from);

    let relay_hint = if let Some(relay) = &args.relay_hint {
        Some(
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("invalid relay url: {e}")))?,
        )
    } else {
        None
    };

    let target = ReactionTarget {
        event_id,
        public_key: event_pubkey,
        coordinate: None,
        kind: event_kind,
        relay_hint,
    };

    Ok((target, content))
}

#[cfg(test)]
mod tests {
    use super::{
        group_chat_tags, parse_signed_event, reaction_payload, thread_tags, PostGroupChatArgs,
        PostReactionArgs, PostThreadArgs,
    };
    use nostr_sdk::prelude::*;

    #[test]
    fn thread_tags_include_subject_and_hashtags() {
        let args = PostThreadArgs {
            content: "content".to_string(),
            subject: "subject".to_string(),
            hashtags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
            pow: None,
            to_relays: None,
        };

        let tags = thread_tags(&args).unwrap();
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(as_vec.contains(&vec!["subject".to_string(), "subject".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "tag1".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "tag2".to_string()]));
    }

    #[test]
    fn group_chat_tags_include_group() {
        let args = PostGroupChatArgs {
            content: "content".to_string(),
            group_id: "group".to_string(),
            reply_to_id: None,
            reply_to_relay: None,
            reply_to_pubkey: None,
            pow: None,
            to_relays: None,
        };

        let tags = group_chat_tags(&args).unwrap();
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(as_vec.contains(&vec!["h".to_string(), "group".to_string()]));
    }

    #[test]
    fn reaction_defaults_to_plus() {
        let args = PostReactionArgs {
            event_id: "0".repeat(64),
            event_pubkey: "1".repeat(64),
            content: None,
            event_kind: None,
            relay_hint: None,
            pow: None,
            to_relays: None,
        };

        let (_target, content) = reaction_payload(&args).unwrap();
        assert_eq!(content, "+");
    }

    #[test]
    fn parse_signed_event_rejects_bad_signature() {
        let keys = Keys::generate();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let mut value = serde_json::to_value(&event).unwrap();
        if let Some(sig) = value.get_mut("sig") {
            *sig = serde_json::Value::String("0".repeat(128));
        }
        let json = serde_json::to_string(&value).unwrap();
        let err = parse_signed_event(&json).unwrap_err();
        assert!(err.to_string().contains("invalid event signature"));
    }

    #[test]
    fn parse_signed_event_accepts_valid_event() {
        let keys = Keys::generate();
        let event = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();
        let json = serde_json::to_string(&event).unwrap();
        parse_signed_event(&json).unwrap();
    }
}
