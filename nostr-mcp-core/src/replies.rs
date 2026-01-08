use crate::error::CoreError;
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
    EventId::from_hex(id)
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {id}: {e}")))
}

fn parse_pubkey(pk: &str) -> Result<PublicKey, CoreError> {
    PublicKey::from_hex(pk)
        .map_err(|e| CoreError::invalid_input(format!("invalid public key {pk}: {e}")))
}

fn relay_hint_value(hint: &Option<String>) -> String {
    hint.as_deref().unwrap_or("").to_string()
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

    let relay_hint = relay_hint_value(&args.relay_hint);

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

fn nip10_reply_builder(args: PostReplyArgs) -> Result<(EventBuilder, Option<Vec<String>>), CoreError> {
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
    let tags = nip22_tags_from_reply(&args)?;

    let mut builder = EventBuilder::new(Kind::from(1111), args.content).tags(tags);
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
    let tags = comment_tags(&args)?;

    let mut builder = EventBuilder::new(Kind::from(1111), args.content).tags(tags);
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    Ok((builder, args.to_relays))
}

fn nip22_tags_from_reply(args: &PostReplyArgs) -> Result<Vec<Tag>, CoreError> {
    let root_event_id = parse_event_id(&args.reply_to_id)?;
    let root_pubkey = parse_pubkey(&args.reply_to_pubkey)?;
    let root_kind = Kind::from(args.reply_to_kind);

    let mut tags = Vec::new();

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, true),
            vec![root_event_id.to_hex(), relay.clone(), root_pubkey.to_hex()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, true),
            vec![root_event_id.to_hex(), String::new(), root_pubkey.to_hex()],
        ));
    }

    tags.push(Tag::custom(
        TagKind::single_letter(Alphabet::K, true),
        vec![root_kind.as_u16().to_string()],
    ));

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, true),
            vec![root_pubkey.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, true),
            vec![root_pubkey.to_hex()],
        ));
    }

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![root_event_id.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![root_event_id.to_hex()],
        ));
    }

    tags.push(Tag::custom(
        TagKind::Custom(std::borrow::Cow::Borrowed("k")),
        vec![root_kind.as_u16().to_string()],
    ));

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, false),
            vec![root_pubkey.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, false),
            vec![root_pubkey.to_hex()],
        ));
    }

    Ok(tags)
}

fn comment_tags(args: &PostCommentArgs) -> Result<Vec<Tag>, CoreError> {
    let root_event_id = parse_event_id(&args.root_event_id)?;
    let root_pubkey = parse_pubkey(&args.root_event_pubkey)?;
    let root_kind = Kind::from(args.root_event_kind);

    let parent_event_id = if let Some(ref parent_id) = args.parent_event_id {
        parse_event_id(parent_id)?
    } else {
        root_event_id
    };

    let parent_pubkey = if let Some(ref parent_pk) = args.parent_event_pubkey {
        parse_pubkey(parent_pk)?
    } else {
        root_pubkey
    };

    let parent_kind = if let Some(parent_k) = args.parent_event_kind {
        Kind::from(parent_k)
    } else {
        root_kind
    };

    let mut tags = Vec::new();

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, true),
            vec![root_event_id.to_hex(), relay.clone(), root_pubkey.to_hex()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, true),
            vec![root_event_id.to_hex(), String::new(), root_pubkey.to_hex()],
        ));
    }

    tags.push(Tag::custom(
        TagKind::single_letter(Alphabet::K, true),
        vec![root_kind.as_u16().to_string()],
    ));

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, true),
            vec![root_pubkey.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, true),
            vec![root_pubkey.to_hex()],
        ));
    }

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![parent_event_id.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::E, false),
            vec![parent_event_id.to_hex()],
        ));
    }

    tags.push(Tag::custom(
        TagKind::Custom(std::borrow::Cow::Borrowed("k")),
        vec![parent_kind.as_u16().to_string()],
    ));

    if let Some(ref relay) = args.relay_hint {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, false),
            vec![parent_pubkey.to_hex(), relay.clone()],
        ));
    } else {
        tags.push(Tag::custom(
            TagKind::single_letter(Alphabet::P, false),
            vec![parent_pubkey.to_hex()],
        ));
    }

    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::{comment_tags, nip10_tags, PostCommentArgs, PostReplyArgs};

    #[test]
    fn nip10_reply_includes_root_tag() {
        let args = PostReplyArgs {
            content: "hi".to_string(),
            reply_to_id: "0".repeat(64),
            reply_to_pubkey: "1".repeat(64),
            reply_to_kind: 1,
            root_event_id: None,
            root_event_pubkey: None,
            mentioned_pubkeys: None,
            relay_hint: Some("wss://relay.example".to_string()),
            pow: None,
            to_relays: None,
        };

        let tags = nip10_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(values.iter().any(|tag| tag.get(3).map(|v| v == "root").unwrap_or(false)));
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
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "e").unwrap_or(false)));
        assert!(values.iter().any(|tag| tag.get(0).map(|v| v == "p").unwrap_or(false)));
    }
}
