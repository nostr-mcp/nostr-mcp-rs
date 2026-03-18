use crate::error::CoreError;
use nostr_mcp_types::publish::{
    CreateTextArgs, CreateTextResult, DeleteEventsArgs, PostAnonymousArgs, PostGroupChatArgs,
    PostLongFormArgs, PostReactionArgs, PostRepostArgs, PostTextArgs, PostThreadArgs,
    PublishSignedEventArgs, SendResult, SignEventArgs, SignEventResult,
};
use nostr_sdk::prelude::*;
use std::collections::HashMap;

pub async fn publish_event_builder(
    client: &Client,
    builder: EventBuilder,
    to_relays: Option<Vec<String>>,
) -> Result<SendResult, CoreError> {
    let pubkey = client
        .signer()
        .await
        .map_err(|e| CoreError::operation(format!("get signer: {e}")))?
        .get_public_key()
        .await
        .map_err(|e| CoreError::operation(format!("get signer pubkey: {e}")))?
        .to_hex();

    let out = if let Some(urls) = to_relays {
        client
            .send_event_builder_to(urls, builder)
            .await
            .map_err(|e| CoreError::operation(format!("send event: {e}")))?
    } else {
        client
            .send_event_builder(builder)
            .await
            .map_err(|e| CoreError::operation(format!("send event: {e}")))?
    };

    let id = out.id().to_string();
    let success = out.success.into_iter().map(|u| u.to_string()).collect();
    let failed = stringify_failed_relays(out.failed);

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
            .map_err(|e| CoreError::operation(format!("send event: {e}")))?
    } else {
        client
            .send_event(&event)
            .await
            .map_err(|e| CoreError::operation(format!("send event: {e}")))?
    };

    let id = out.id().to_string();
    let success = out.success.into_iter().map(|u| u.to_string()).collect();
    let failed = stringify_failed_relays(out.failed);

    Ok(SendResult {
        id,
        success,
        failed,
        pubkey: event.pubkey.to_hex(),
    })
}

fn parse_signed_event(event_json: &str) -> Result<Event, CoreError> {
    let event = Event::from_json(event_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid event json: {e}")))?;
    event
        .verify()
        .map_err(|e| CoreError::invalid_input(format!("invalid event signature: {e}")))?;
    Ok(event)
}

fn parse_unsigned_event(event_json: &str) -> Result<UnsignedEvent, CoreError> {
    let unsigned = UnsignedEvent::from_json(event_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid unsigned event json: {e}")))?;
    unsigned
        .verify_id()
        .map_err(|e| CoreError::invalid_input(format!("invalid unsigned event id: {e}")))?;
    Ok(unsigned)
}

fn parse_tags(raw_tags: Option<Vec<Vec<String>>>) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    if let Some(raw_tags) = raw_tags {
        for values in raw_tags {
            let tag = Tag::parse(&values)
                .map_err(|e| CoreError::invalid_input(format!("invalid tag: {e}")))?;
            tags.push(tag);
        }
    }

    Ok(tags)
}

fn stringify_failed_relays<I, E>(failed: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = (RelayUrl, E)>,
    E: ToString,
{
    failed
        .into_iter()
        .map(|(url, error)| (url.to_string(), error.to_string()))
        .collect()
}

pub fn create_text_event(
    pubkey: PublicKey,
    args: CreateTextArgs,
) -> Result<CreateTextResult, CoreError> {
    let tags = parse_tags(args.tags)?;
    let mut builder = EventBuilder::text_note(args.content)
        .tags(tags)
        .allow_self_tagging();

    if let Some(created_at) = args.created_at {
        builder = builder.custom_created_at(Timestamp::from(created_at));
    }

    let mut unsigned = builder.build(pubkey);
    let event_id = unsigned.id().to_string();
    let unsigned_event_json = unsigned.as_json();

    Ok(CreateTextResult {
        event_id,
        pubkey: pubkey.to_hex(),
        unsigned_event_json,
    })
}

pub async fn sign_unsigned_event<T>(
    signer: &T,
    args: SignEventArgs,
) -> Result<SignEventResult, CoreError>
where
    T: NostrSigner,
{
    let unsigned = parse_unsigned_event(&args.unsigned_event_json)?;
    let signer_pubkey = signer
        .get_public_key()
        .await
        .map_err(|e| CoreError::operation(format!("get signer pubkey: {e}")))?;

    if unsigned.pubkey != signer_pubkey {
        return Err(CoreError::invalid_input(
            "unsigned event pubkey does not match active key",
        ));
    }

    let event = unsigned
        .sign(signer)
        .await
        .map_err(|e| CoreError::operation(format!("sign event: {e}")))?;

    Ok(SignEventResult {
        event_id: event.id.to_string(),
        pubkey: event.pubkey.to_hex(),
        event_json: event.as_json(),
    })
}

pub async fn post_text_note(client: &Client, args: PostTextArgs) -> Result<SendResult, CoreError> {
    let mut builder = EventBuilder::text_note(args.content);
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }
    publish_event_builder(client, builder, args.to_relays).await
}

fn thread_tags(args: &PostThreadArgs) -> Vec<Tag> {
    let mut tags = Vec::new();

    tags.push(Tag::custom(
        TagKind::custom("subject"),
        [args.subject.clone()],
    ));

    if let Some(hashtags) = &args.hashtags {
        for hashtag in hashtags {
            tags.push(Tag::custom(TagKind::t(), [hashtag.clone()]));
        }
    }

    tags
}

pub async fn post_thread(client: &Client, args: PostThreadArgs) -> Result<SendResult, CoreError> {
    let tags = thread_tags(&args);
    let mut builder = EventBuilder::new(Kind::from(11), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn post_long_form(
    client: &Client,
    args: PostLongFormArgs,
) -> Result<SendResult, CoreError> {
    let tags = long_form_tags(&args)?;
    let mut builder = EventBuilder::new(Kind::from(30023), args.content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

fn repost_builder(
    event: &Event,
    relay_hint: Option<String>,
    pow: Option<u8>,
) -> Result<EventBuilder, CoreError> {
    let relay_url = match relay_hint {
        Some(value) => Some(
            RelayUrl::parse(&value)
                .map_err(|e| CoreError::invalid_input(format!("invalid relay url: {e}")))?,
        ),
        None => None,
    };

    let mut builder = EventBuilder::repost(event, relay_url).allow_self_tagging();
    if let Some(pow) = pow {
        builder = builder.pow(pow);
    }

    Ok(builder)
}

pub async fn post_repost(client: &Client, args: PostRepostArgs) -> Result<SendResult, CoreError> {
    let target = parse_signed_event(&args.event_json)?;
    let builder = repost_builder(&target, args.relay_hint, args.pow)?;
    publish_event_builder(client, builder, args.to_relays).await
}

fn parse_event_id(id: &str) -> Result<EventId, CoreError> {
    EventId::from_hex(id)
        .map_err(|e| CoreError::invalid_input(format!("invalid event id {id}: {e}")))
}

fn parse_coordinate(coordinate: &str) -> Result<Coordinate, CoreError> {
    Coordinate::parse(coordinate)
        .map_err(|e| CoreError::invalid_input(format!("invalid coordinate {coordinate}: {e}")))
}

pub async fn delete_events(
    client: &Client,
    args: DeleteEventsArgs,
) -> Result<SendResult, CoreError> {
    let mut request = EventDeletionRequest::new();
    let mut has_target = false;

    if let Some(ids) = args.event_ids {
        if ids.is_empty() {
            return Err(CoreError::invalid_input("event_ids must not be empty"));
        }
        let mut parsed_ids = Vec::with_capacity(ids.len());
        for id in ids {
            parsed_ids.push(parse_event_id(&id)?);
        }
        request = request.ids(parsed_ids);
        has_target = true;
    }

    if let Some(coords) = args.coordinates {
        if coords.is_empty() {
            return Err(CoreError::invalid_input("coordinates must not be empty"));
        }
        let mut parsed_coords = Vec::with_capacity(coords.len());
        for coord in coords {
            parsed_coords.push(parse_coordinate(&coord)?);
        }
        request = request.coordinates(parsed_coords);
        has_target = true;
    }

    if !has_target {
        return Err(CoreError::invalid_input(
            "event_ids or coordinates are required",
        ));
    }

    if let Some(reason) = args.reason {
        if reason.trim().is_empty() {
            return Err(CoreError::invalid_input("reason must not be empty"));
        }
        request = request.reason(reason);
    }

    let mut builder = EventBuilder::delete(request).allow_self_tagging();
    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

#[cfg(test)]
async fn sign_anonymous_builder<T>(signer: &T, builder: EventBuilder) -> Result<Event, CoreError>
where
    T: NostrSigner,
{
    let pubkey = signer
        .get_public_key()
        .await
        .map_err(|e| CoreError::operation(format!("get signer pubkey: {e}")))?;
    let unsigned = builder.build(pubkey);
    unsigned
        .sign(signer)
        .await
        .map_err(|e| CoreError::operation(format!("sign event: {e}")))
}

fn sign_anonymous_builder_with_generated_keys(keys: &Keys, builder: EventBuilder) -> Event {
    builder
        .sign_with_keys(keys)
        .expect("generated anonymous keys should sign a validated builder")
}

pub async fn post_anonymous_note(
    client: &Client,
    args: PostAnonymousArgs,
) -> Result<SendResult, CoreError> {
    let keys = Keys::generate();
    let tags = parse_tags(args.tags)?;
    let mut builder = EventBuilder::text_note(args.content)
        .tags(tags)
        .allow_self_tagging();

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    let event = sign_anonymous_builder_with_generated_keys(&keys, builder);

    publish_signed_event(
        client,
        PublishSignedEventArgs {
            event_json: event.as_json(),
            to_relays: args.to_relays,
        },
    )
    .await
}

fn long_form_tags(args: &PostLongFormArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    if let Some(title) = &args.title {
        tags.push(tag_pair(
            "title",
            ensure_tag_value("title", title)?,
        ));
    }

    if let Some(summary) = &args.summary {
        tags.push(tag_pair(
            "summary",
            ensure_tag_value("summary", summary)?,
        ));
    }

    if let Some(image) = &args.image {
        tags.push(tag_pair(
            "image",
            ensure_tag_value("image", image)?,
        ));
    }

    if let Some(published_at) = args.published_at {
        tags.push(tag_pair(
            "published_at",
            published_at.to_string(),
        ));
    }

    if let Some(identifier) = &args.identifier {
        tags.push(tag_pair(
            "d",
            ensure_tag_value("identifier", identifier)?,
        ));
    }

    if let Some(hashtags) = &args.hashtags {
        for hashtag in hashtags {
            tags.push(tag_pair(
                "t",
                ensure_tag_value("hashtag", hashtag)?,
            ));
        }
    }

    Ok(tags)
}

fn tag_pair(name: &str, value: String) -> Tag {
    match name {
        "d" => Tag::identifier(value),
        "t" => Tag::custom(TagKind::t(), [value]),
        _ => Tag::custom(TagKind::custom(name), [value]),
    }
}

fn ensure_tag_value(label: &str, value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

fn group_chat_tags(args: &PostGroupChatArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();

    tags.push(Tag::custom(TagKind::h(), [args.group_id.clone()]));

    if let Some(ref reply_id) = args.reply_to_id {
        let event_id = EventId::from_hex(reply_id)
            .map_err(|e| CoreError::invalid_input(format!("invalid event id {reply_id}: {e}")))?;

        let relay = args.reply_to_relay.as_deref().unwrap_or("");
        let pubkey = args.reply_to_pubkey.as_deref().unwrap_or("");

        tags.push(Tag::custom(
            TagKind::custom("q"),
            [
                event_id.to_hex(),
                relay.to_string(),
                pubkey.to_string(),
            ],
        ));
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
    let event_id = EventId::from_hex(&args.event_id).map_err(|e| {
        CoreError::invalid_input(format!("invalid event id {}: {e}", args.event_id))
    })?;
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
        create_text_event, delete_events, group_chat_tags, long_form_tags, parse_coordinate,
        parse_signed_event, parse_unsigned_event, post_anonymous_note, post_group_chat,
        post_long_form, post_reaction, post_repost, post_text_note, post_thread,
        publish_signed_event, reaction_payload, repost_builder, sign_anonymous_builder,
        sign_unsigned_event,
        stringify_failed_relays, thread_tags,
    };
    use nostr_mcp_types::publish::{
        CreateTextArgs, DeleteEventsArgs, PostGroupChatArgs, PostLongFormArgs, PostReactionArgs,
        PostAnonymousArgs, PostRepostArgs, PostTextArgs, PostThreadArgs,
        PublishSignedEventArgs, SignEventArgs,
    };
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::future::ready;

    fn sample_thread_args() -> PostThreadArgs {
        PostThreadArgs {
            content: "content".to_string(),
            subject: "subject".to_string(),
            hashtags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_long_form_args() -> PostLongFormArgs {
        PostLongFormArgs {
            content: "body".to_string(),
            title: Some("Title".to_string()),
            summary: Some("Summary".to_string()),
            image: Some("https://example.com/img.png".to_string()),
            published_at: Some(123),
            identifier: Some("article-1".to_string()),
            hashtags: Some(vec!["news".to_string(), "nostr".to_string()]),
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

    async fn find_authored_event_by_content(
        client: &Client,
        author: PublicKey,
        kind: Kind,
        content: &str,
    ) -> Event {
        client
            .fetch_events(
                Filter::new().kind(kind).author(author).limit(10),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap()
            .iter()
            .find(|event| event.content == content)
            .unwrap()
            .clone()
    }

    async fn find_latest_authored_event_by_kind(client: &Client, author: PublicKey, kind: Kind) -> Event {
        client
            .fetch_events(
                Filter::new().kind(kind).author(author).limit(10),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .clone()
    }

    fn signed_text_note(keys: &Keys, content: &str) -> Event {
        EventBuilder::text_note(content)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[derive(Debug, Clone)]
    struct PublicKeyErrorSigner(Keys);

    impl NostrSigner for PublicKeyErrorSigner {
        fn backend(&self) -> SignerBackend<'_> {
            SignerBackend::Custom(Cow::Borrowed("public-key-error"))
        }

        fn get_public_key(&self) -> BoxedFuture<'_, Result<PublicKey, SignerError>> {
            Box::pin(ready(Err(SignerError::from("public key boom"))))
        }

        fn sign_event(&self, unsigned: UnsignedEvent) -> BoxedFuture<'_, Result<Event, SignerError>> {
            self.0.sign_event(unsigned)
        }

        fn nip04_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip04_encrypt(public_key, content)
        }

        fn nip04_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            encrypted_content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip04_decrypt(public_key, encrypted_content)
        }

        fn nip44_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip44_encrypt(public_key, content)
        }

        fn nip44_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip44_decrypt(public_key, payload)
        }
    }

    #[derive(Debug, Clone)]
    struct SignEventErrorSigner(Keys);

    impl NostrSigner for SignEventErrorSigner {
        fn backend(&self) -> SignerBackend<'_> {
            SignerBackend::Custom(Cow::Borrowed("sign-event-error"))
        }

        fn get_public_key(&self) -> BoxedFuture<'_, Result<PublicKey, SignerError>> {
            self.0.get_public_key()
        }

        fn sign_event(&self, _unsigned: UnsignedEvent) -> BoxedFuture<'_, Result<Event, SignerError>> {
            Box::pin(ready(Err(SignerError::from("sign event boom"))))
        }

        fn nip04_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip04_encrypt(public_key, content)
        }

        fn nip04_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            encrypted_content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip04_decrypt(public_key, encrypted_content)
        }

        fn nip44_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip44_encrypt(public_key, content)
        }

        fn nip44_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> BoxedFuture<'a, Result<String, SignerError>> {
            self.0.nip44_decrypt(public_key, payload)
        }
    }

    #[test]
    fn thread_tags_include_subject_and_hashtags() {
        let args = sample_thread_args();

        let tags = thread_tags(&args);
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(as_vec.contains(&vec!["subject".to_string(), "subject".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "tag1".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "tag2".to_string()]));
    }

    #[test]
    fn thread_tags_accept_subject_without_hashtags() {
        let mut args = sample_thread_args();
        args.hashtags = None;

        let tags = thread_tags(&args);
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert_eq!(as_vec, vec![vec!["subject".to_string(), "subject".to_string()]]);
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
    fn group_chat_tags_include_reply_reference_and_reject_invalid_reply_id() {
        let keys = Keys::generate();
        let reply = signed_text_note(&keys, "reply");
        let args = PostGroupChatArgs {
            content: "content".to_string(),
            group_id: "group".to_string(),
            reply_to_id: Some(reply.id.to_hex()),
            reply_to_relay: Some("wss://relay.example.com".to_string()),
            reply_to_pubkey: Some(keys.public_key().to_hex()),
            pow: None,
            to_relays: None,
        };

        let tags = group_chat_tags(&args).unwrap();
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(as_vec.contains(&vec![
            "q".to_string(),
            reply.id.to_hex(),
            "wss://relay.example.com".to_string(),
            keys.public_key().to_hex(),
        ]));

        let mut invalid = args;
        invalid.reply_to_id = Some("nope".to_string());
        let err = group_chat_tags(&invalid).unwrap_err();
        assert!(err.to_string().contains("invalid event id"));
    }

    #[test]
    fn long_form_tags_include_fields() {
        let args = sample_long_form_args();

        let tags = long_form_tags(&args).unwrap();
        let as_vec: Vec<Vec<String>> = tags.into_iter().map(|t| t.to_vec()).collect();
        assert!(as_vec.contains(&vec!["title".to_string(), "Title".to_string()]));
        assert!(as_vec.contains(&vec!["summary".to_string(), "Summary".to_string()]));
        assert!(as_vec.contains(&vec![
            "image".to_string(),
            "https://example.com/img.png".to_string()
        ]));
        assert!(as_vec.contains(&vec!["published_at".to_string(), "123".to_string()]));
        assert!(as_vec.contains(&vec!["d".to_string(), "article-1".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "news".to_string()]));
        assert!(as_vec.contains(&vec!["t".to_string(), "nostr".to_string()]));
    }

    #[test]
    fn long_form_tags_rejects_empty_identifier() {
        let mut args = sample_long_form_args();
        args.title = None;
        args.summary = None;
        args.image = None;
        args.published_at = None;
        args.identifier = Some("   ".to_string());
        args.hashtags = None;

        let err = long_form_tags(&args).unwrap_err();
        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[test]
    fn long_form_tags_accept_minimal_and_reject_empty_optional_values() {
        let mut args = sample_long_form_args();
        args.title = None;
        args.summary = None;
        args.image = None;
        args.published_at = None;
        args.identifier = None;
        args.hashtags = None;

        assert!(long_form_tags(&args).unwrap().is_empty());

        let mut invalid_title = sample_long_form_args();
        invalid_title.title = Some(" ".to_string());
        let err = long_form_tags(&invalid_title).unwrap_err();
        assert!(err.to_string().contains("title must not be empty"));

        let mut invalid_summary = sample_long_form_args();
        invalid_summary.summary = Some(" ".to_string());
        let err = long_form_tags(&invalid_summary).unwrap_err();
        assert!(err.to_string().contains("summary must not be empty"));

        let mut invalid_image = sample_long_form_args();
        invalid_image.image = Some(" ".to_string());
        let err = long_form_tags(&invalid_image).unwrap_err();
        assert!(err.to_string().contains("image must not be empty"));

        let mut invalid_hashtag = sample_long_form_args();
        invalid_hashtag.hashtags = Some(vec![" ".to_string()]);
        let err = long_form_tags(&invalid_hashtag).unwrap_err();
        assert!(err.to_string().contains("hashtag must not be empty"));
    }

    #[test]
    fn create_text_event_emits_unsigned_json() {
        let keys = Keys::generate();
        let args = CreateTextArgs {
            content: "hello".to_string(),
            tags: Some(vec![vec!["t".to_string(), "nostr".to_string()]]),
            created_at: Some(10),
        };

        let result = create_text_event(keys.public_key(), args).unwrap();
        let unsigned = UnsignedEvent::from_json(&result.unsigned_event_json).unwrap();

        assert_eq!(result.pubkey, keys.public_key().to_hex());
        assert_eq!(unsigned.content, "hello");
        assert!(unsigned.id.is_some());
        assert!(unsigned.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "t" && values[1] == "nostr"
        }));
    }

    #[test]
    fn create_text_event_accepts_empty_tags_without_created_at() {
        let keys = Keys::generate();
        let result = create_text_event(
            keys.public_key(),
            CreateTextArgs {
                content: "hello".to_string(),
                tags: None,
                created_at: None,
            },
        )
        .unwrap();

        let unsigned = UnsignedEvent::from_json(&result.unsigned_event_json).unwrap();
        assert_eq!(unsigned.content, "hello");
        assert!(unsigned.tags.is_empty());
    }

    #[test]
    fn create_text_event_rejects_invalid_tag() {
        let keys = Keys::generate();
        let err = create_text_event(
            keys.public_key(),
            CreateTextArgs {
                content: "hello".to_string(),
                tags: Some(vec![vec![]]),
                created_at: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid tag"));
    }

    #[test]
    fn parse_signed_event_rejects_invalid_json() {
        let err = parse_signed_event("not json").unwrap_err();
        assert!(err.to_string().contains("invalid event json"));
    }

    #[test]
    fn parse_unsigned_event_rejects_invalid_json_and_id() {
        let err = parse_unsigned_event("not json").unwrap_err();
        assert!(err.to_string().contains("invalid unsigned event json"));

        let keys = Keys::generate();
        let unsigned = EventBuilder::text_note("hello").build(keys.public_key());
        let mut value = serde_json::to_value(&unsigned).unwrap();
        value["id"] = serde_json::Value::String("0".repeat(64));
        let err = parse_unsigned_event(&serde_json::to_string(&value).unwrap()).unwrap_err();
        assert!(err.to_string().contains("invalid unsigned event id"));
    }

    #[tokio::test]
    async fn sign_unsigned_event_rejects_mismatched_pubkey() {
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let unsigned = EventBuilder::text_note("hello").build(keys_a.public_key());
        let args = SignEventArgs {
            unsigned_event_json: unsigned.as_json(),
        };

        let err = sign_unsigned_event(&keys_b, args).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("unsigned event pubkey does not match")
        );
    }

    #[tokio::test]
    async fn sign_unsigned_event_accepts_matching_pubkey() {
        let keys = Keys::generate();
        let unsigned = EventBuilder::text_note("hello").build(keys.public_key());
        let args = SignEventArgs {
            unsigned_event_json: unsigned.as_json(),
        };

        let result = sign_unsigned_event(&keys, args).await.unwrap();
        let event = Event::from_json(&result.event_json).unwrap();
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(result.event_id, event.id.to_string());
    }

    #[tokio::test]
    async fn sign_unsigned_event_reports_public_key_and_sign_errors() {
        let keys = Keys::generate();
        let unsigned = EventBuilder::text_note("hello").build(keys.public_key());
        let args = SignEventArgs {
            unsigned_event_json: unsigned.as_json(),
        };

        let invalid_unsigned = sign_unsigned_event(
            &keys,
            SignEventArgs {
                unsigned_event_json: "not json".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_unsigned
            .to_string()
            .contains("invalid unsigned event json"));

        let public_key_err =
            sign_unsigned_event(&PublicKeyErrorSigner(keys.clone()), args).await.unwrap_err();
        assert!(public_key_err.to_string().contains("get signer pubkey"));

        let sign_err = sign_unsigned_event(
            &SignEventErrorSigner(keys),
            SignEventArgs {
                unsigned_event_json: unsigned.as_json(),
            },
        )
        .await
        .unwrap_err();
        assert!(sign_err.to_string().contains("sign event"));
    }

    #[tokio::test]
    async fn publish_signed_event_accepts_connected_default_and_explicit_relays() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let signer_keys = Keys::generate();
        let client = connected_client(signer_keys.clone(), &url).await;

        let first = signed_text_note(&Keys::generate(), "first");
        let result = publish_signed_event(
            &client,
            PublishSignedEventArgs {
                event_json: first.as_json(),
                to_relays: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.pubkey, first.pubkey.to_hex());
        assert_eq!(result.success, vec![url.to_string()]);

        let second = signed_text_note(&Keys::generate(), "second");
        let targeted = publish_signed_event(
            &client,
            PublishSignedEventArgs {
                event_json: second.as_json(),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(targeted.pubkey, second.pubkey.to_hex());
        assert_eq!(targeted.success, vec![url.to_string()]);
    }

    #[tokio::test]
    async fn publish_signed_event_rejects_invalid_json_and_send_errors() {
        let client = Client::new(Keys::generate());
        let err = publish_signed_event(
            &client,
            PublishSignedEventArgs {
                event_json: "not json".to_string(),
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid event json"));

        let event = signed_text_note(&Keys::generate(), "hello");
        let err = publish_signed_event(
            &client,
            PublishSignedEventArgs {
                event_json: event.as_json(),
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("send event"));

        let err = publish_signed_event(
            &client,
            PublishSignedEventArgs {
                event_json: event.as_json(),
                to_relays: Some(vec!["wss://relay.example.com".to_string()]),
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("send event"));
    }

    #[tokio::test]
    async fn post_text_note_covers_pow_and_relay_paths_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;

        let plain = post_text_note(
            &client,
            PostTextArgs {
                content: "plain".to_string(),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap();
        assert!(plain.failed.is_empty());
        let plain_event =
            find_authored_event_by_content(&client, keys.public_key(), Kind::TextNote, "plain")
                .await;
        assert!(!plain_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let pow = post_text_note(
            &client,
            PostTextArgs {
                content: "pow".to_string(),
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(pow.success, vec![url.to_string()]);
        let pow_event =
            find_authored_event_by_content(&client, keys.public_key(), Kind::TextNote, "pow").await;
        assert!(pow_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_text_note_reports_send_and_signer_errors() {
        let send_error = post_text_note(
            &Client::new(Keys::generate()),
            PostTextArgs {
                content: "hello".to_string(),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(send_error.to_string().contains("send event"));

        let explicit_relay_error = post_text_note(
            &Client::new(Keys::generate()),
            PostTextArgs {
                content: "hello".to_string(),
                pow: None,
                to_relays: Some(vec!["wss://relay.example.com".to_string()]),
            },
        )
        .await
        .unwrap_err();
        assert!(explicit_relay_error.to_string().contains("send event"));

        let missing_signer = post_text_note(
            &Client::builder().build(),
            PostTextArgs {
                content: "hello".to_string(),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(missing_signer.to_string().contains("get signer"));

        let public_key_error = post_text_note(
            &Client::builder()
                .signer(PublicKeyErrorSigner(Keys::generate()))
                .build(),
            PostTextArgs {
                content: "hello".to_string(),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(public_key_error.to_string().contains("get signer pubkey"));
    }

    #[tokio::test]
    async fn post_thread_covers_pow_and_relay_paths_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;

        let mut plain_args = sample_thread_args();
        plain_args.content = "thread plain".to_string();
        plain_args.hashtags = None;
        let plain = post_thread(&client, plain_args).await.unwrap();
        assert!(plain.failed.is_empty());
        let plain_event = find_authored_event_by_content(
            &client,
            keys.public_key(),
            Kind::from(11),
            "thread plain",
        )
        .await;
        assert!(!plain_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let mut pow_args = sample_thread_args();
        pow_args.content = "thread pow".to_string();
        pow_args.pow = Some(1);
        pow_args.to_relays = Some(vec![url.to_string()]);
        let pow = post_thread(&client, pow_args).await.unwrap();
        assert_eq!(pow.success, vec![url.to_string()]);
        let pow_event =
            find_authored_event_by_content(&client, keys.public_key(), Kind::from(11), "thread pow")
                .await;
        assert!(pow_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_long_form_covers_pow_and_relay_paths_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;

        let mut plain_args = sample_long_form_args();
        plain_args.content = "long plain".to_string();
        plain_args.title = None;
        plain_args.summary = None;
        plain_args.image = None;
        plain_args.published_at = None;
        plain_args.identifier = None;
        plain_args.hashtags = None;
        let plain_err = post_long_form(&Client::new(Keys::generate()), plain_args)
            .await
            .unwrap_err();
        assert!(plain_err.to_string().contains("send event"));

        let mut invalid_args = sample_long_form_args();
        invalid_args.title = Some(" ".to_string());
        let invalid_err = post_long_form(&client, invalid_args).await.unwrap_err();
        assert!(invalid_err.to_string().contains("title must not be empty"));

        let mut pow_args = sample_long_form_args();
        pow_args.content = "long pow".to_string();
        pow_args.pow = Some(1);
        pow_args.to_relays = Some(vec![url.to_string()]);
        let pow = post_long_form(&client, pow_args).await.unwrap();
        assert_eq!(pow.success, vec![url.to_string()]);
        let pow_event = find_authored_event_by_content(
            &client,
            keys.public_key(),
            Kind::from(30023),
            "long pow",
        )
        .await;
        assert!(pow_event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(pow_event.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "d" && values[1] == "article-1"
        }));
    }

    #[test]
    fn repost_builder_uses_kind_6_for_text_note() {
        let target_keys = Keys::generate();
        let target = EventBuilder::text_note("hello")
            .sign_with_keys(&target_keys)
            .unwrap();
        let reposter_keys = Keys::generate();

        let builder = repost_builder(&target, None, None).unwrap();
        let unsigned = builder.build(reposter_keys.public_key());

        assert_eq!(unsigned.kind, Kind::Repost);
    }

    #[test]
    fn repost_builder_uses_generic_for_non_text() {
        let target_keys = Keys::generate();
        let target = EventBuilder::new(Kind::from(30023), "long")
            .sign_with_keys(&target_keys)
            .unwrap();
        let reposter_keys = Keys::generate();

        let builder = repost_builder(&target, None, None).unwrap();
        let unsigned = builder.build(reposter_keys.public_key());

        assert_eq!(unsigned.kind, Kind::GenericRepost);
        assert!(unsigned.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "k" && values[1] == "30023"
        }));
    }

    #[test]
    fn repost_builder_preserves_self_tag() {
        let keys = Keys::generate();
        let target = EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();

        let builder = repost_builder(&target, None, None).unwrap();
        let unsigned = builder.build(keys.public_key());
        let pubkey_hex = keys.public_key().to_hex();

        assert!(unsigned.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "p" && values[1] == pubkey_hex
        }));
    }

    #[test]
    fn repost_builder_rejects_bad_relay() {
        let target_keys = Keys::generate();
        let target = EventBuilder::text_note("hello")
            .sign_with_keys(&target_keys)
            .unwrap();

        let err = repost_builder(&target, Some("not a url".to_string()), None).unwrap_err();
        assert!(err.to_string().contains("invalid relay url"));
    }

    #[test]
    fn repost_builder_applies_pow() {
        let target_keys = Keys::generate();
        let target = EventBuilder::text_note("hello")
            .sign_with_keys(&target_keys)
            .unwrap();
        let reposter_keys = Keys::generate();

        let builder = repost_builder(&target, None, Some(1)).unwrap();
        let unsigned = builder.build(reposter_keys.public_key());

        assert!(unsigned.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_repost_covers_success_and_error_paths() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let target = signed_text_note(&Keys::generate(), "repost-target");

        let result = post_repost(
            &client,
            PostRepostArgs {
                event_json: target.as_json(),
                relay_hint: None,
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.success, vec![url.to_string()]);
        let repost = find_latest_authored_event_by_kind(&client, keys.public_key(), Kind::Repost).await;
        assert!(repost.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let invalid_json = post_repost(
            &client,
            PostRepostArgs {
                event_json: "not json".to_string(),
                relay_hint: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_json.to_string().contains("invalid event json"));

        let invalid_relay = post_repost(
            &client,
            PostRepostArgs {
                event_json: target.as_json(),
                relay_hint: Some("bad".to_string()),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_relay.to_string().contains("invalid relay url"));

        let send_err = post_repost(
            &Client::new(Keys::generate()),
            PostRepostArgs {
                event_json: target.as_json(),
                relay_hint: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(send_err.to_string().contains("send event"));
    }

    #[test]
    fn parse_coordinate_accepts_valid_coordinate() {
        let keys = Keys::generate();
        let coordinate = Coordinate::new(Kind::from(30023), keys.public_key()).identifier("article-1");

        let parsed = parse_coordinate(&coordinate.to_string()).unwrap();
        assert_eq!(parsed.to_string(), coordinate.to_string());
    }

    #[tokio::test]
    async fn delete_events_rejects_missing_targets() {
        let client = Client::new(Keys::generate());
        let args = DeleteEventsArgs {
            event_ids: None,
            coordinates: None,
            reason: None,
            pow: None,
            to_relays: None,
        };

        let err = delete_events(&client, args).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("event_ids or coordinates are required")
        );
    }

    #[tokio::test]
    async fn delete_events_rejects_empty_reason() {
        let client = Client::new(Keys::generate());
        let args = DeleteEventsArgs {
            event_ids: Some(vec!["0".repeat(64)]),
            coordinates: None,
            reason: Some("   ".to_string()),
            pow: None,
            to_relays: None,
        };

        let err = delete_events(&client, args).await.unwrap_err();
        assert!(err.to_string().contains("reason must not be empty"));
    }

    #[tokio::test]
    async fn delete_events_rejects_invalid_id() {
        let client = Client::new(Keys::generate());
        let args = DeleteEventsArgs {
            event_ids: Some(vec!["nope".to_string()]),
            coordinates: None,
            reason: None,
            pow: None,
            to_relays: None,
        };

        let err = delete_events(&client, args).await.unwrap_err();
        assert!(err.to_string().contains("invalid event id"));
    }

    #[tokio::test]
    async fn delete_events_accepts_coordinates_and_pow_and_rejects_invalid_coordinates() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let coordinate = Coordinate::new(Kind::from(30023), keys.public_key()).identifier("article-1");

        let result = delete_events(
            &client,
            DeleteEventsArgs {
                event_ids: Some(vec!["0".repeat(64)]),
                coordinates: Some(vec![coordinate.to_string()]),
                reason: Some("cleanup".to_string()),
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.success, vec![url.to_string()]);
        let deletion =
            find_latest_authored_event_by_kind(&client, keys.public_key(), Kind::EventDeletion).await;
        assert!(deletion.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(deletion.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "a" && values[1] == coordinate.to_string()
        }));

        let event_only = delete_events(
            &client,
            DeleteEventsArgs {
                event_ids: Some(vec!["1".repeat(64)]),
                coordinates: None,
                reason: None,
                pow: None,
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(event_only.success, vec![url.to_string()]);

        let empty_event_ids = delete_events(
            &client,
            DeleteEventsArgs {
                event_ids: Some(vec![]),
                coordinates: None,
                reason: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(empty_event_ids
            .to_string()
            .contains("event_ids must not be empty"));

        let empty_coordinates = delete_events(
            &client,
            DeleteEventsArgs {
                event_ids: None,
                coordinates: Some(vec![]),
                reason: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(empty_coordinates
            .to_string()
            .contains("coordinates must not be empty"));

        let invalid_coordinate = delete_events(
            &client,
            DeleteEventsArgs {
                event_ids: None,
                coordinates: Some(vec!["bad-coordinate".to_string()]),
                reason: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_coordinate.to_string().contains("invalid coordinate"));
    }

    #[tokio::test]
    async fn post_anonymous_note_covers_success_and_error_paths() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let client = connected_client(Keys::generate(), &url).await;

        let result = post_anonymous_note(
            &client,
            PostAnonymousArgs {
                content: "anon".to_string(),
                tags: Some(vec![vec!["t".to_string(), "anon".to_string()]]),
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.success, vec![url.to_string()]);
        let author = PublicKey::from_hex(&result.pubkey).unwrap();
        let event = find_authored_event_by_content(&client, author, Kind::TextNote, "anon").await;
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let invalid_tag = post_anonymous_note(
            &client,
            PostAnonymousArgs {
                content: "anon".to_string(),
                tags: Some(vec![vec![]]),
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_tag.to_string().contains("invalid tag"));

        let send_err = post_anonymous_note(
            &Client::new(Keys::generate()),
            PostAnonymousArgs {
                content: "anon".to_string(),
                tags: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(send_err.to_string().contains("send event"));
    }

    #[tokio::test]
    async fn sign_anonymous_builder_reports_public_key_and_sign_errors() {
        let builder = EventBuilder::text_note("anon");

        let public_key_err = sign_anonymous_builder(
            &PublicKeyErrorSigner(Keys::generate()),
            builder.clone(),
        )
        .await
        .unwrap_err();
        assert!(public_key_err
            .to_string()
            .contains("get signer pubkey"));

        let sign_err = sign_anonymous_builder(&SignEventErrorSigner(Keys::generate()), builder)
            .await
            .unwrap_err();
        assert!(sign_err.to_string().contains("sign event"));
    }

    #[tokio::test]
    async fn post_group_chat_covers_success_and_error_paths() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let reply = signed_text_note(&Keys::generate(), "reply");

        let result = post_group_chat(
            &client,
            PostGroupChatArgs {
                content: "chat".to_string(),
                group_id: "group".to_string(),
                reply_to_id: Some(reply.id.to_hex()),
                reply_to_relay: Some(url.to_string()),
                reply_to_pubkey: Some(reply.pubkey.to_hex()),
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.success, vec![url.to_string()]);
        let event = find_authored_event_by_content(&client, keys.public_key(), Kind::from(9), "chat").await;
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
        assert!(event.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.len() == 2 && values[0] == "h" && values[1] == "group"
        }));

        let invalid_reply = post_group_chat(
            &client,
            PostGroupChatArgs {
                content: "chat".to_string(),
                group_id: "group".to_string(),
                reply_to_id: Some("nope".to_string()),
                reply_to_relay: None,
                reply_to_pubkey: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_reply.to_string().contains("invalid event id"));

        let send_err = post_group_chat(
            &Client::new(Keys::generate()),
            PostGroupChatArgs {
                content: "chat".to_string(),
                group_id: "group".to_string(),
                reply_to_id: None,
                reply_to_relay: None,
                reply_to_pubkey: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(send_err.to_string().contains("send event"));
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
    fn reaction_payload_accepts_explicit_fields_and_rejects_invalid_inputs() {
        let event_id = "0".repeat(64);
        let pubkey = Keys::generate().public_key().to_hex();
        let args = PostReactionArgs {
            event_id: event_id.clone(),
            event_pubkey: pubkey.clone(),
            content: Some("zap".to_string()),
            event_kind: Some(1),
            relay_hint: Some("wss://relay.example.com".to_string()),
            pow: None,
            to_relays: None,
        };

        let (target, content) = reaction_payload(&args).unwrap();
        assert_eq!(content, "zap");
        assert_eq!(target.event_id.to_hex(), event_id);
        assert_eq!(target.public_key.to_hex(), pubkey);
        assert_eq!(target.kind, Some(Kind::TextNote));
        assert_eq!(
            target.relay_hint.as_ref().map(ToString::to_string),
            Some("wss://relay.example.com".to_string())
        );

        let invalid_event = reaction_payload(&PostReactionArgs {
            event_id: "bad".to_string(),
            event_pubkey: pubkey.clone(),
            content: Some("zap".to_string()),
            event_kind: Some(1),
            relay_hint: Some("wss://relay.example.com".to_string()),
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(invalid_event.to_string().contains("invalid event id"));

        let invalid_pubkey = reaction_payload(&PostReactionArgs {
            event_id: event_id.clone(),
            event_pubkey: "bad".to_string(),
            content: Some("zap".to_string()),
            event_kind: Some(1),
            relay_hint: Some("wss://relay.example.com".to_string()),
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(invalid_pubkey.to_string().contains("invalid event pubkey"));

        let invalid_relay = reaction_payload(&PostReactionArgs {
            event_id,
            event_pubkey: pubkey,
            content: Some("zap".to_string()),
            event_kind: Some(1),
            relay_hint: Some("bad".to_string()),
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(invalid_relay.to_string().contains("invalid relay url"));
    }

    #[tokio::test]
    async fn post_reaction_covers_success_and_error_paths() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let target = signed_text_note(&Keys::generate(), "react-target");

        let result = post_reaction(
            &client,
            PostReactionArgs {
                event_id: target.id.to_hex(),
                event_pubkey: target.pubkey.to_hex(),
                content: Some("zap".to_string()),
                event_kind: Some(1),
                relay_hint: Some(url.to_string()),
                pow: Some(1),
                to_relays: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.success, vec![url.to_string()]);
        let event = find_latest_authored_event_by_kind(&client, keys.public_key(), Kind::Reaction).await;
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));

        let invalid_input = post_reaction(
            &client,
            PostReactionArgs {
                event_id: "bad".to_string(),
                event_pubkey: target.pubkey.to_hex(),
                content: None,
                event_kind: None,
                relay_hint: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(invalid_input.to_string().contains("invalid event id"));

        let send_err = post_reaction(
            &Client::new(Keys::generate()),
            PostReactionArgs {
                event_id: target.id.to_hex(),
                event_pubkey: target.pubkey.to_hex(),
                content: Some("zap".to_string()),
                event_kind: None,
                relay_hint: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();
        assert!(send_err.to_string().contains("send event"));
    }

    #[test]
    fn stringify_failed_relays_stringifies_relay_entries() {
        let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
        let failed = stringify_failed_relays([(relay.clone(), "boom")]);

        assert_eq!(
            failed,
            HashMap::from([(relay.to_string(), "boom".to_string())])
        );
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
