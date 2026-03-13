use std::borrow::Cow;

use crate::error::CoreError;
use nostr::nips::nip22::CommentTarget;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostReplyArgs {
    pub content: String,
    pub reply_to_id: String,
    pub reply_to_pubkey: String,
    pub reply_to_kind: u16,
    pub root_event_id: Option<String>,
    pub root_event_pubkey: Option<String>,
    pub root_event_kind: Option<u16>,
    pub mentioned_pubkeys: Option<Vec<String>>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostCommentArgs {
    pub content: String,
    pub root_event_id: String,
    pub root_event_pubkey: String,
    pub root_event_kind: u16,
    pub parent_event_id: Option<String>,
    pub parent_event_pubkey: Option<String>,
    pub parent_event_kind: Option<u16>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

fn parse_event_id(id: &str) -> Result<EventId, CoreError> {
    EventId::parse(id.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {id}: {e}")))
}

fn parse_pubkey(pk: &str) -> Result<PublicKey, CoreError> {
    PublicKey::parse(pk.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid public key {pk}: {e}")))
}

fn parse_relay_hint(hint: &Option<String>) -> Result<Option<RelayUrl>, CoreError> {
    hint.as_deref()
        .map(|value| {
            RelayUrl::parse(value.trim())
                .map_err(|e| CoreError::invalid_input(format!("invalid relay hint {value}: {e}")))
        })
        .transpose()
}

pub async fn post_reply(
    client: &Client,
    args: PostReplyArgs,
) -> Result<crate::publish::SendResult, CoreError> {
    if args.reply_to_kind == 1 {
        let (builder, to_relays) = nip10_reply_builder(args)?;
        crate::publish::publish_event_builder(client, builder, to_relays).await
    } else {
        let (builder, to_relays) = nip22_comment_builder(args)?;
        crate::publish::publish_event_builder(client, builder, to_relays).await
    }
}

fn nip10_tags(args: &PostReplyArgs) -> Result<Vec<Tag>, CoreError> {
    let reply_to_id = parse_event_id(&args.reply_to_id)?;
    let reply_to_pubkey = parse_pubkey(&args.reply_to_pubkey)?;

    let root_id = if let Some(ref root) = args.root_event_id {
        parse_event_id(root)?
    } else {
        reply_to_id
    };

    let root_pubkey = if let Some(ref root_pk) = args.root_event_pubkey {
        parse_pubkey(root_pk)?
    } else {
        reply_to_pubkey
    };

    let relay_hint = parse_relay_hint(&args.relay_hint)?
        .map(|value| value.to_string())
        .unwrap_or_default();

    let mut tags = Vec::new();

    if root_id == reply_to_id {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![
                root_id.to_hex(),
                relay_hint.clone(),
                "root".to_string(),
                root_pubkey.to_hex(),
            ],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![
                root_id.to_hex(),
                relay_hint.clone(),
                "root".to_string(),
                root_pubkey.to_hex(),
            ],
        ));

        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![
                reply_to_id.to_hex(),
                relay_hint.clone(),
                "reply".to_string(),
                reply_to_pubkey.to_hex(),
            ],
        ));
    }

    tags.push(Tag::custom(
        TagKind::single_letter(Alphabet::P, false),
        vec![reply_to_pubkey.to_hex()],
    ));

    if let Some(mentioned) = &args.mentioned_pubkeys {
        for pk_str in mentioned {
            let pk = parse_pubkey(pk_str)?;
            tags.push(Tag::custom(
                TagKind::single_letter(Alphabet::P, false),
                vec![pk.to_hex()],
            ));
        }
    }

    Ok(tags)
}

fn nip10_reply_builder(
    args: PostReplyArgs,
) -> Result<(EventBuilder, Option<Vec<String>>), CoreError> {
    let tags = nip10_tags(&args)?;
    let mut builder = EventBuilder::text_note(args.content).tags(tags);
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    Ok((builder, args.to_relays))
}

fn nip22_comment_builder(
    args: PostReplyArgs,
) -> Result<(EventBuilder, Option<Vec<String>>), CoreError> {
    let (root, parent) = reply_targets(&args)?;
    let mut builder = EventBuilder::comment(args.content, parent, Some(root));
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    Ok((builder, args.to_relays))
}

pub async fn post_comment(
    client: &Client,
    args: PostCommentArgs,
) -> Result<crate::publish::SendResult, CoreError> {
    let (builder, to_relays) = comment_builder(args)?;
    crate::publish::publish_event_builder(client, builder, to_relays).await
}

fn comment_builder(
    args: PostCommentArgs,
) -> Result<(EventBuilder, Option<Vec<String>>), CoreError> {
    let (root, parent) = comment_targets(&args)?;
    let mut builder = EventBuilder::comment(args.content, parent, Some(root));
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    Ok((builder, args.to_relays))
}

#[cfg(test)]
fn nip22_tags_from_reply(args: &PostReplyArgs) -> Result<Vec<Tag>, CoreError> {
    let (root, parent) = reply_targets(args)?;
    let mut tags = root.as_vec(true);
    tags.extend(parent.as_vec(false));
    Ok(tags)
}

#[cfg(test)]
fn comment_tags(args: &PostCommentArgs) -> Result<Vec<Tag>, CoreError> {
    let (root, parent) = comment_targets(args)?;
    let mut tags = root.as_vec(true);
    tags.extend(parent.as_vec(false));
    Ok(tags)
}

fn reply_targets(
    args: &PostReplyArgs,
) -> Result<(CommentTarget<'static>, CommentTarget<'static>), CoreError> {
    let relay_hint = parse_relay_hint(&args.relay_hint)?;
    let parent = comment_target(
        &args.reply_to_id,
        &args.reply_to_pubkey,
        args.reply_to_kind,
        relay_hint.clone(),
    )?;
    let root = match args.root_event_id.as_ref() {
        Some(root_event_id) => {
            let root_event_pubkey = args.root_event_pubkey.as_ref().ok_or_else(|| {
                CoreError::invalid_input("root_event_pubkey is required with root_event_id")
            })?;
            let root_event_kind = args.root_event_kind.ok_or_else(|| {
                CoreError::invalid_input("root_event_kind is required with root_event_id")
            })?;
            comment_target(
                root_event_id,
                root_event_pubkey,
                root_event_kind,
                relay_hint,
            )?
        }
        None => comment_target(
            &args.reply_to_id,
            &args.reply_to_pubkey,
            args.reply_to_kind,
            relay_hint,
        )?,
    };

    Ok((root, parent))
}

fn comment_targets(
    args: &PostCommentArgs,
) -> Result<(CommentTarget<'static>, CommentTarget<'static>), CoreError> {
    let relay_hint = parse_relay_hint(&args.relay_hint)?;
    let root = comment_target(
        &args.root_event_id,
        &args.root_event_pubkey,
        args.root_event_kind,
        relay_hint.clone(),
    )?;
    let parent = match args.parent_event_id.as_ref() {
        Some(parent_event_id) => comment_target(
            parent_event_id,
            args.parent_event_pubkey.as_ref().ok_or_else(|| {
                CoreError::invalid_input("parent_event_pubkey is required with parent_event_id")
            })?,
            args.parent_event_kind.ok_or_else(|| {
                CoreError::invalid_input("parent_event_kind is required with parent_event_id")
            })?,
            relay_hint,
        )?,
        None => comment_target(
            &args.root_event_id,
            &args.root_event_pubkey,
            args.root_event_kind,
            relay_hint,
        )?,
    };

    Ok((root, parent))
}

fn comment_target(
    event_id: &str,
    pubkey: &str,
    kind: u16,
    relay_hint: Option<RelayUrl>,
) -> Result<CommentTarget<'static>, CoreError> {
    let event_id = parse_event_id(event_id)?;
    let pubkey = parse_pubkey(pubkey)?;
    Ok(CommentTarget::event(
        event_id,
        Kind::from(kind),
        Some(pubkey),
        relay_hint.map(Cow::Owned),
    ))
}

#[cfg(test)]
mod tests {
    use super::{PostCommentArgs, PostReplyArgs, comment_tags, nip10_tags, nip22_tags_from_reply};

    #[test]
    fn nip10_reply_includes_root_tag() {
        let args = PostReplyArgs {
            content: "hi".to_string(),
            reply_to_id: "0".repeat(64),
            reply_to_pubkey: "1".repeat(64),
            reply_to_kind: 1,
            root_event_id: None,
            root_event_pubkey: None,
            root_event_kind: None,
            mentioned_pubkeys: None,
            relay_hint: Some("wss://relay.example".to_string()),
            pow: None,
            to_relays: None,
        };

        let tags = nip10_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.get(3).map(|v| v == "root").unwrap_or(false))
        );
    }

    #[test]
    fn comment_builder_sets_root_and_parent() {
        let args = PostCommentArgs {
            content: "hi".to_string(),
            root_event_id: "0".repeat(64),
            root_event_pubkey: "1".repeat(64),
            root_event_kind: 30023,
            parent_event_id: None,
            parent_event_pubkey: None,
            parent_event_kind: None,
            relay_hint: None,
            pow: None,
            to_relays: None,
        };

        let tags = comment_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "e").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "p").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "E").unwrap_or(false))
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.first().map(|v| v == "K").unwrap_or(false))
        );
    }

    #[test]
    fn reply_comment_uses_root_and_parent_kinds() {
        let args = PostReplyArgs {
            content: "hi".to_string(),
            reply_to_id: "1".repeat(64),
            reply_to_pubkey: "2".repeat(64),
            reply_to_kind: 1111,
            root_event_id: Some("0".repeat(64)),
            root_event_pubkey: Some("1".repeat(64)),
            root_event_kind: Some(30023),
            mentioned_pubkeys: None,
            relay_hint: Some("wss://relay.example".to_string()),
            pow: None,
            to_relays: None,
        };

        let tags = nip22_tags_from_reply(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(
            values
                .iter()
                .any(|tag| tag.len() >= 2 && tag[0] == "K" && tag[1] == "30023")
        );
        assert!(
            values
                .iter()
                .any(|tag| tag.len() >= 2 && tag[0] == "k" && tag[1] == "1111")
        );
    }
}
