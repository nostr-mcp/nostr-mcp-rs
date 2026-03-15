use std::borrow::Cow;

use crate::error::CoreError;
use nostr::nips::nip22::CommentTarget;
use nostr_mcp_types::publish::SendResult;
use nostr_mcp_types::replies::{PostCommentArgs, PostReplyArgs};
use nostr_sdk::prelude::*;

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

pub async fn post_reply(client: &Client, args: PostReplyArgs) -> Result<SendResult, CoreError> {
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

pub async fn post_comment(client: &Client, args: PostCommentArgs) -> Result<SendResult, CoreError> {
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
    let reply_to_id = parse_event_id(&args.reply_to_id)?;
    let reply_to_pubkey = parse_pubkey(&args.reply_to_pubkey)?;
    let parent = comment_target_from_parsed(
        reply_to_id,
        reply_to_pubkey,
        args.reply_to_kind,
        relay_hint.clone(),
    );
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
        None => comment_target_from_parsed(reply_to_id, reply_to_pubkey, args.reply_to_kind, relay_hint),
    };

    Ok((root, parent))
}

fn comment_targets(
    args: &PostCommentArgs,
) -> Result<(CommentTarget<'static>, CommentTarget<'static>), CoreError> {
    let relay_hint = parse_relay_hint(&args.relay_hint)?;
    let root_event_id = parse_event_id(&args.root_event_id)?;
    let root_event_pubkey = parse_pubkey(&args.root_event_pubkey)?;
    let root = comment_target_from_parsed(
        root_event_id,
        root_event_pubkey,
        args.root_event_kind,
        relay_hint.clone(),
    );
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
        None => comment_target_from_parsed(root_event_id, root_event_pubkey, args.root_event_kind, relay_hint),
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
    Ok(comment_target_from_parsed(event_id, pubkey, kind, relay_hint))
}

fn comment_target_from_parsed(
    event_id: EventId,
    pubkey: PublicKey,
    kind: u16,
    relay_hint: Option<RelayUrl>,
) -> CommentTarget<'static> {
    CommentTarget::event(
        event_id,
        Kind::from(kind),
        Some(pubkey),
        relay_hint.map(Cow::Owned),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        comment_builder, comment_tags, nip10_reply_builder, nip10_tags, nip22_comment_builder,
        nip22_tags_from_reply, parse_event_id, parse_pubkey, parse_relay_hint, post_comment,
        post_reply, reply_targets,
    };
    use nostr_mcp_types::replies::{PostCommentArgs, PostReplyArgs};
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;
    use std::collections::HashSet;

    fn sample_reply_args() -> PostReplyArgs {
        PostReplyArgs {
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
        }
    }

    fn sample_comment_args() -> PostCommentArgs {
        PostCommentArgs {
            content: "hi".to_string(),
            root_event_id: "0".repeat(64),
            root_event_pubkey: "1".repeat(64),
            root_event_kind: 30023,
            parent_event_id: None,
            parent_event_pubkey: None,
            parent_event_kind: None,
            relay_hint: Some("wss://relay.example".to_string()),
            pow: None,
            to_relays: None,
        }
    }

    async fn connected_client(keys: Keys, url: &RelayUrl) -> Client {
        let client = Client::new(keys);
        client.add_relay(url).await.unwrap();
        client.connect().await;
        client
    }

    #[test]
    fn parse_event_id_accepts_trimmed_hex() {
        let event_id = parse_event_id(&format!(" {} ", "0".repeat(64))).unwrap();

        assert_eq!(event_id.to_hex(), "0".repeat(64));
    }

    #[test]
    fn parse_event_id_rejects_invalid_event_id() {
        let err = parse_event_id("bad").unwrap_err();

        assert!(err.to_string().contains("invalid event id bad"));
    }

    #[test]
    fn parse_pubkey_accepts_trimmed_hex() {
        let pubkey = parse_pubkey(&format!(" {} ", "1".repeat(64))).unwrap();

        assert_eq!(pubkey.to_hex(), "1".repeat(64));
    }

    #[test]
    fn parse_pubkey_rejects_invalid_pubkey() {
        let err = parse_pubkey("bad").unwrap_err();

        assert!(err.to_string().contains("invalid public key bad"));
    }

    #[test]
    fn parse_relay_hint_accepts_none_and_valid_url() {
        assert!(parse_relay_hint(&None).unwrap().is_none());
        assert_eq!(
            parse_relay_hint(&Some("wss://relay.example".to_string()))
                .unwrap()
                .unwrap()
                .to_string(),
            "wss://relay.example"
        );
    }

    #[test]
    fn parse_relay_hint_rejects_invalid_url() {
        let err = parse_relay_hint(&Some("not-a-relay".to_string())).unwrap_err();

        assert!(err.to_string().contains("invalid relay hint not-a-relay"));
    }

    #[test]
    fn nip10_reply_includes_root_tag() {
        let args = sample_reply_args();

        let tags = nip10_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        let mut root_count = 0;
        for tag in &values {
            if tag.get(3).map(String::as_str) == Some("root") {
                root_count += 1;
            }
        }
        assert_eq!(root_count, 1);
    }

    #[test]
    fn nip10_reply_with_explicit_root_and_mentions_includes_reply_and_all_pubkeys() {
        let mut args = sample_reply_args();
        args.reply_to_id = "2".repeat(64);
        args.reply_to_pubkey = "3".repeat(64);
        args.root_event_id = Some("0".repeat(64));
        args.root_event_pubkey = Some("1".repeat(64));
        args.mentioned_pubkeys = Some(vec!["4".repeat(64), "5".repeat(64)]);

        let values: Vec<Vec<String>> = nip10_tags(&args)
            .unwrap()
            .into_iter()
            .map(|tag| tag.to_vec())
            .collect();
        let tag_set: HashSet<_> = values.into_iter().collect();

        assert!(tag_set.contains(&vec![
            "e".to_string(),
            "0".repeat(64),
            "wss://relay.example".to_string(),
            "root".to_string(),
            "1".repeat(64),
        ]));
        assert!(tag_set.contains(&vec![
            "e".to_string(),
            "2".repeat(64),
            "wss://relay.example".to_string(),
            "reply".to_string(),
            "3".repeat(64),
        ]));
        assert!(tag_set.contains(&vec!["p".to_string(), "3".repeat(64)]));
        assert!(tag_set.contains(&vec!["p".to_string(), "4".repeat(64)]));
        assert!(tag_set.contains(&vec!["p".to_string(), "5".repeat(64)]));
    }

    #[test]
    fn nip10_reply_rejects_invalid_root_and_mention_inputs() {
        let mut invalid_reply_pubkey = sample_reply_args();
        invalid_reply_pubkey.reply_to_pubkey = "bad".to_string();
        let err = nip10_tags(&invalid_reply_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_root_id = sample_reply_args();
        invalid_root_id.root_event_id = Some("bad".to_string());
        invalid_root_id.root_event_pubkey = Some("1".repeat(64));
        let err = nip10_tags(&invalid_root_id).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        let mut invalid_root_pubkey = sample_reply_args();
        invalid_root_pubkey.root_event_id = Some("0".repeat(64));
        invalid_root_pubkey.root_event_pubkey = Some("bad".to_string());
        let err = nip10_tags(&invalid_root_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_mention = sample_reply_args();
        invalid_mention.mentioned_pubkeys = Some(vec!["bad".to_string()]);
        let err = nip10_tags(&invalid_mention).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_relay = sample_reply_args();
        invalid_relay.relay_hint = Some("not-a-relay".to_string());
        let err = nip10_tags(&invalid_relay).unwrap_err();
        assert!(err.to_string().contains("invalid relay hint not-a-relay"));
    }

    #[test]
    fn nip10_reply_builder_applies_pow() {
        let mut args = sample_reply_args();
        args.pow = Some(1);

        let (builder, to_relays) = nip10_reply_builder(args).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::TextNote);
        assert!(unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn nip10_reply_builder_without_pow_omits_nonce() {
        let (builder, to_relays) = nip10_reply_builder(sample_reply_args()).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::TextNote);
        assert!(!unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn reply_targets_reject_missing_root_fields() {
        let mut missing_root_pubkey = sample_reply_args();
        missing_root_pubkey.reply_to_kind = 1111;
        missing_root_pubkey.root_event_id = Some("0".repeat(64));

        let err = reply_targets(&missing_root_pubkey).err().unwrap();
        assert!(err
            .to_string()
            .contains("root_event_pubkey is required with root_event_id"));

        let mut missing_root_kind = sample_reply_args();
        missing_root_kind.reply_to_kind = 1111;
        missing_root_kind.root_event_id = Some("0".repeat(64));
        missing_root_kind.root_event_pubkey = Some("1".repeat(64));

        let err = reply_targets(&missing_root_kind).err().unwrap();
        assert!(err
            .to_string()
            .contains("root_event_kind is required with root_event_id"));
    }

    #[test]
    fn nip22_tags_from_reply_rejects_invalid_inputs() {
        let mut invalid_reply_id = sample_reply_args();
        invalid_reply_id.reply_to_kind = 1111;
        invalid_reply_id.reply_to_id = "bad".to_string();
        let err = nip22_tags_from_reply(&invalid_reply_id).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        let mut invalid_reply_pubkey = sample_reply_args();
        invalid_reply_pubkey.reply_to_kind = 1111;
        invalid_reply_pubkey.reply_to_pubkey = "bad".to_string();
        let err = nip22_tags_from_reply(&invalid_reply_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_root_id = sample_reply_args();
        invalid_root_id.reply_to_kind = 1111;
        invalid_root_id.root_event_id = Some("bad".to_string());
        invalid_root_id.root_event_pubkey = Some("1".repeat(64));
        invalid_root_id.root_event_kind = Some(30023);
        let err = nip22_tags_from_reply(&invalid_root_id).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        let mut invalid_root_pubkey = sample_reply_args();
        invalid_root_pubkey.reply_to_kind = 1111;
        invalid_root_pubkey.root_event_id = Some("0".repeat(64));
        invalid_root_pubkey.root_event_pubkey = Some("bad".to_string());
        invalid_root_pubkey.root_event_kind = Some(30023);
        let err = nip22_tags_from_reply(&invalid_root_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_relay = sample_reply_args();
        invalid_relay.reply_to_kind = 1111;
        invalid_relay.relay_hint = Some("not-a-relay".to_string());
        let err = nip22_tags_from_reply(&invalid_relay).unwrap_err();
        assert!(err.to_string().contains("invalid relay hint not-a-relay"));
    }

    #[test]
    fn comment_builder_sets_root_and_parent() {
        let mut args = sample_comment_args();
        args.relay_hint = None;

        let tags = comment_tags(&args).unwrap();
        let values: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        let kinds: HashSet<_> = values
            .into_iter()
            .filter_map(|tag| tag.first().cloned())
            .collect();
        assert!(kinds.contains("e"));
        assert!(kinds.contains("p"));
        assert!(kinds.contains("E"));
        assert!(kinds.contains("K"));
    }

    #[test]
    fn comment_tags_with_explicit_parent_uses_root_and_parent_values() {
        let mut args = sample_comment_args();
        args.parent_event_id = Some("2".repeat(64));
        args.parent_event_pubkey = Some("3".repeat(64));
        args.parent_event_kind = Some(1111);

        let values: Vec<Vec<String>> = comment_tags(&args)
            .unwrap()
            .into_iter()
            .map(|tag| tag.to_vec())
            .collect();
        let tag_set: HashSet<_> = values.into_iter().collect();

        assert!(tag_set.contains(&vec![
            "E".to_string(),
            "0".repeat(64),
            "wss://relay.example".to_string(),
            "1".repeat(64),
        ]));
        assert!(tag_set.contains(&vec![
            "e".to_string(),
            "2".repeat(64),
            "wss://relay.example".to_string(),
            "3".repeat(64),
        ]));
        assert!(tag_set.contains(&vec!["K".to_string(), "30023".to_string()]));
        assert!(tag_set.contains(&vec!["k".to_string(), "1111".to_string()]));
        assert!(tag_set.contains(&vec![
            "P".to_string(),
            "1".repeat(64),
            "wss://relay.example".to_string(),
        ]));
        assert!(tag_set.contains(&vec![
            "p".to_string(),
            "3".repeat(64),
            "wss://relay.example".to_string(),
        ]));
    }

    #[test]
    fn comment_tags_reject_missing_parent_fields_and_invalid_inputs() {
        let mut missing_parent_pubkey = sample_comment_args();
        missing_parent_pubkey.parent_event_id = Some("2".repeat(64));

        let err = comment_tags(&missing_parent_pubkey).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent_event_pubkey is required with parent_event_id"));

        let mut missing_parent_kind = sample_comment_args();
        missing_parent_kind.parent_event_id = Some("2".repeat(64));
        missing_parent_kind.parent_event_pubkey = Some("3".repeat(64));

        let err = comment_tags(&missing_parent_kind).unwrap_err();
        assert!(err
            .to_string()
            .contains("parent_event_kind is required with parent_event_id"));

        let mut invalid_root_pubkey = sample_comment_args();
        invalid_root_pubkey.root_event_pubkey = "bad".to_string();
        let err = comment_tags(&invalid_root_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));

        let mut invalid_relay = sample_comment_args();
        invalid_relay.relay_hint = Some("not-a-relay".to_string());
        let err = comment_tags(&invalid_relay).unwrap_err();
        assert!(err.to_string().contains("invalid relay hint not-a-relay"));
    }

    #[test]
    fn comment_tags_reject_invalid_event_identifiers() {
        let mut invalid_root_id = sample_comment_args();
        invalid_root_id.root_event_id = "bad".to_string();
        let err = comment_tags(&invalid_root_id).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        let mut invalid_parent_id = sample_comment_args();
        invalid_parent_id.parent_event_id = Some("bad".to_string());
        invalid_parent_id.parent_event_pubkey = Some("3".repeat(64));
        invalid_parent_id.parent_event_kind = Some(1111);
        let err = comment_tags(&invalid_parent_id).unwrap_err();
        assert!(err.to_string().contains("invalid event id bad"));

        let mut invalid_parent_pubkey = sample_comment_args();
        invalid_parent_pubkey.parent_event_id = Some("2".repeat(64));
        invalid_parent_pubkey.parent_event_pubkey = Some("bad".to_string());
        invalid_parent_pubkey.parent_event_kind = Some(1111);
        let err = comment_tags(&invalid_parent_pubkey).unwrap_err();
        assert!(err.to_string().contains("invalid public key bad"));
    }

    #[test]
    fn comment_builder_applies_pow() {
        let mut args = sample_comment_args();
        args.pow = Some(1);

        let (builder, to_relays) = comment_builder(args).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::from(1111));
        assert!(unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn comment_builder_without_pow_omits_nonce() {
        let (builder, to_relays) = comment_builder(sample_comment_args()).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::from(1111));
        assert!(!unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn reply_comment_uses_root_and_parent_kinds() {
        let mut args = sample_reply_args();
        args.reply_to_id = "1".repeat(64);
        args.reply_to_pubkey = "2".repeat(64);
        args.reply_to_kind = 1111;
        args.root_event_id = Some("0".repeat(64));
        args.root_event_pubkey = Some("1".repeat(64));
        args.root_event_kind = Some(30023);

        let tags = nip22_tags_from_reply(&args).unwrap();
        let values: HashSet<_> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(values.contains(&vec!["K".to_string(), "30023".to_string()]));
        assert!(values.contains(&vec!["k".to_string(), "1111".to_string()]));
    }

    #[test]
    fn nip22_reply_without_explicit_root_uses_parent_as_root() {
        let mut args = sample_reply_args();
        args.reply_to_kind = 1111;

        let tags: HashSet<_> = nip22_tags_from_reply(&args)
            .unwrap()
            .into_iter()
            .map(|tag| tag.to_vec())
            .collect();

        assert!(tags.contains(&vec![
            "E".to_string(),
            "0".repeat(64),
            "wss://relay.example".to_string(),
            "1".repeat(64),
        ]));
        assert!(tags.contains(&vec![
            "e".to_string(),
            "0".repeat(64),
            "wss://relay.example".to_string(),
            "1".repeat(64),
        ]));
        assert!(tags.contains(&vec!["K".to_string(), "1111".to_string()]));
        assert!(tags.contains(&vec!["k".to_string(), "1111".to_string()]));
        assert!(tags.contains(&vec![
            "P".to_string(),
            "1".repeat(64),
            "wss://relay.example".to_string(),
        ]));
        assert!(tags.contains(&vec![
            "p".to_string(),
            "1".repeat(64),
            "wss://relay.example".to_string(),
        ]));
    }

    #[test]
    fn nip22_comment_builder_applies_pow() {
        let mut args = sample_reply_args();
        args.reply_to_kind = 1111;
        args.pow = Some(1);

        let (builder, to_relays) = nip22_comment_builder(args).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::from(1111));
        assert!(unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn nip22_comment_builder_without_pow_omits_nonce() {
        let mut args = sample_reply_args();
        args.reply_to_kind = 1111;

        let (builder, to_relays) = nip22_comment_builder(args).unwrap();
        let unsigned = builder.build(Keys::generate().public_key());

        assert!(to_relays.is_none());
        assert_eq!(unsigned.kind, Kind::from(1111));
        assert!(!unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_reply_rejects_invalid_nip10_input_before_publish() {
        let client = Client::new(Keys::generate());
        let mut args = sample_reply_args();
        args.reply_to_id = "bad".to_string();

        let err = post_reply(&client, args).await.unwrap_err();

        assert!(err.to_string().contains("invalid event id bad"));
    }

    #[tokio::test]
    async fn post_reply_rejects_invalid_nip22_input_before_publish() {
        let client = Client::new(Keys::generate());
        let mut args = sample_reply_args();
        args.reply_to_kind = 1111;
        args.root_event_id = Some("0".repeat(64));

        let err = post_reply(&client, args).await.unwrap_err();

        assert!(err
            .to_string()
            .contains("root_event_pubkey is required with root_event_id"));
    }

    #[tokio::test]
    async fn post_comment_rejects_invalid_input_before_publish() {
        let client = Client::new(Keys::generate());
        let mut args = sample_comment_args();
        args.root_event_pubkey = "bad".to_string();

        let err = post_comment(&client, args).await.unwrap_err();

        assert!(err.to_string().contains("invalid public key bad"));
    }

    #[tokio::test]
    async fn post_reply_nip10_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_reply_args();
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_reply(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::TextNote)
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();
        let values: HashSet<_> = event
            .tags
            .iter()
            .cloned()
            .map(Tag::to_vec)
            .collect();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::TextNote);
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(values.contains(&vec![
            "e".to_string(),
            "0".repeat(64),
            "wss://relay.example".to_string(),
            "root".to_string(),
            "1".repeat(64),
        ]));
    }

    #[tokio::test]
    async fn post_reply_nip22_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_reply_args();
        args.reply_to_kind = 1111;
        args.root_event_id = Some("0".repeat(64));
        args.root_event_pubkey = Some("1".repeat(64));
        args.root_event_kind = Some(30023);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_reply(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(1111))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();
        let values: HashSet<_> = event
            .tags
            .iter()
            .cloned()
            .map(Tag::to_vec)
            .collect();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(1111));
        assert!(values.contains(&vec!["K".to_string(), "30023".to_string()]));
        assert!(values.contains(&vec!["k".to_string(), "1111".to_string()]));
    }

    #[tokio::test]
    async fn post_comment_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_comment_args();
        args.pow = Some(1);
        args.parent_event_id = Some("2".repeat(64));
        args.parent_event_pubkey = Some("3".repeat(64));
        args.parent_event_kind = Some(1111);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_comment(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(1111))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();
        let values: HashSet<_> = event
            .tags
            .iter()
            .cloned()
            .map(Tag::to_vec)
            .collect();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(1111));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(values.contains(&vec!["K".to_string(), "30023".to_string()]));
        assert!(values.contains(&vec!["k".to_string(), "1111".to_string()]));
    }
}
