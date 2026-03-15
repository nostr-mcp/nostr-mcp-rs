use crate::error::CoreError;
use crate::publish::publish_event_builder;
use nostr_mcp_types::nip58::{
    Nip58BadgeAwardArgs, Nip58BadgeDefinitionArgs, Nip58BadgeImage, Nip58ProfileBadgesArgs,
};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;
use std::str::FromStr;

pub async fn post_badge_definition(
    client: &Client,
    args: Nip58BadgeDefinitionArgs,
) -> Result<SendResult, CoreError> {
    let tags = badge_definition_tags(&args)?;
    let content = args.content.unwrap_or_default();
    let mut builder = EventBuilder::new(Kind::from(30009), content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn post_badge_award(
    client: &Client,
    args: Nip58BadgeAwardArgs,
) -> Result<SendResult, CoreError> {
    let tags = badge_award_tags(&args)?;
    let content = args.content.unwrap_or_default();
    let mut builder = EventBuilder::new(Kind::from(8), content)
        .tags(tags)
        .allow_self_tagging();

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn post_profile_badges(
    client: &Client,
    args: Nip58ProfileBadgesArgs,
) -> Result<SendResult, CoreError> {
    let tags = profile_badges_tags(&args)?;
    let content = args.content.unwrap_or_default();
    let mut builder = EventBuilder::new(Kind::from(30008), content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

#[allow(clippy::collapsible_if, clippy::question_mark)]
fn badge_definition_tags(args: &Nip58BadgeDefinitionArgs) -> Result<Vec<Tag>, CoreError> {
    let identifier = args.identifier.trim();
    if identifier.is_empty() {
        return Err(CoreError::invalid_input("identifier must not be empty"));
    }

    let mut tags = vec![Tag::identifier(identifier)];

    if let Some(name) = args.name.as_ref() {
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::invalid_input("name must not be empty"));
        }
        tags.push(Tag::from_standardized_without_cell(TagStandard::Name(
            name.to_string(),
        )));
    }

    if let Some(description) = args.description.as_ref() {
        let description = description.trim();
        if description.is_empty() {
            return Err(CoreError::invalid_input("description must not be empty"));
        }
        tags.push(Tag::description(description.to_string()));
    }

    if let Some(image) = args.image.as_ref() {
        if let Err(error) = push_image_tag(&mut tags, "image", image) {
            return Err(error);
        }
    }

    if let Some(thumbs) = args.thumbs.as_ref() {
        for thumb in thumbs {
            if let Err(error) = push_image_tag(&mut tags, "thumb", thumb) {
                return Err(error);
            }
        }
    }

    Ok(tags)
}

#[allow(clippy::question_mark)]
fn badge_award_tags(args: &Nip58BadgeAwardArgs) -> Result<Vec<Tag>, CoreError> {
    if args.recipients.is_empty() {
        return Err(CoreError::invalid_input(
            "recipients must include at least one entry",
        ));
    }

    let coordinate = match parse_badge_coordinate(&args.badge) {
        Ok(coordinate) => coordinate,
        Err(error) => return Err(error),
    };
    let mut tags = Vec::new();

    let badge_relay = args
        .badge_relay
        .as_ref()
        .map(|relay| {
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("badge relay: {e}")))
        })
        .transpose()?;
    tags.push(Tag::coordinate(coordinate, badge_relay));

    for recipient in &args.recipients {
        let pubkey = PublicKey::parse(recipient.pubkey.trim())
            .map_err(|e| CoreError::invalid_input(format!("recipient pubkey: {e}")))?;
        let relay_url = recipient
            .relay
            .as_ref()
            .map(|relay| {
                RelayUrl::parse(relay)
                    .map_err(|e| CoreError::invalid_input(format!("recipient relay: {e}")))
            })
            .transpose()?;

        tags.push(Tag::from_standardized_without_cell(TagStandard::PublicKey {
            public_key: pubkey,
            relay_url,
            alias: None,
            uppercase: false,
        }));
    }

    Ok(tags)
}

fn profile_badges_tags(args: &Nip58ProfileBadgesArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = vec![Tag::identifier("profile_badges")];

    for badge in &args.badges {
        let coordinate = parse_badge_coordinate(&badge.badge)?;
        let badge_relay = badge
            .badge_relay
            .as_ref()
            .map(|relay| {
                RelayUrl::parse(relay)
                    .map_err(|e| CoreError::invalid_input(format!("badge relay: {e}")))
            })
            .transpose()?;
        tags.push(Tag::coordinate(coordinate, badge_relay));

        let event_id = EventId::parse(badge.award_event_id.trim())
            .map_err(|e| CoreError::invalid_input(format!("award event id: {e}")))?;
        let award_relay = badge
            .award_relay
            .as_ref()
            .map(|relay| {
                RelayUrl::parse(relay)
                    .map_err(|e| CoreError::invalid_input(format!("award relay: {e}")))
            })
            .transpose()?;
        tags.push(Tag::from_standardized_without_cell(TagStandard::Event {
            event_id,
            relay_url: award_relay,
            marker: None,
            public_key: None,
            uppercase: false,
        }));
    }

    Ok(tags)
}

fn push_image_tag(
    tags: &mut Vec<Tag>,
    kind: &str,
    image: &Nip58BadgeImage,
) -> Result<(), CoreError> {
    let url = image.url.trim();
    if url.is_empty() {
        return Err(CoreError::invalid_input("image url must not be empty"));
    }
    let url = Url::parse(url).map_err(|e| CoreError::invalid_input(format!("image url: {e}")))?;

    let dimensions = image
        .dimensions
        .as_ref()
        .map(|value| {
            ImageDimensions::from_str(value.trim())
                .map_err(|e| CoreError::invalid_input(format!("image dimensions: {e}")))
        })
        .transpose()?;

    let tag = match kind {
        "image" => Tag::image(url, dimensions),
        "thumb" => Tag::from_standardized_without_cell(TagStandard::Thumb(url, dimensions)),
        _ => return Err(CoreError::invalid_input(format!("unsupported image tag kind: {kind}"))),
    };

    tags.push(tag);
    Ok(())
}

fn parse_badge_coordinate(value: &str) -> Result<Coordinate, CoreError> {
    let coordinate = Coordinate::parse(value.trim())
        .map_err(|e| CoreError::invalid_input(format!("badge coordinate: {e}")))?;
    if coordinate.kind != Kind::from(30009) {
        return Err(CoreError::invalid_input(
            "badge coordinate must reference kind 30009",
        ));
    }
    Ok(coordinate)
}

#[cfg(test)]
mod tests {
    use super::{
        badge_award_tags, badge_definition_tags, parse_badge_coordinate, post_badge_award,
        post_badge_definition, post_profile_badges, profile_badges_tags, push_image_tag,
    };
    use nostr_mcp_types::nip58::{
        Nip58BadgeAwardArgs, Nip58BadgeDefinitionArgs, Nip58BadgeDisplay, Nip58BadgeImage,
        Nip58BadgeRecipient, Nip58ProfileBadgesArgs,
    };
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;

    fn sample_badge_coordinate() -> String {
        "30009:0000000000000000000000000000000000000000000000000000000000000000:bravery"
            .to_string()
    }

    fn sample_badge_definition_args() -> Nip58BadgeDefinitionArgs {
        Nip58BadgeDefinitionArgs {
            identifier: "bravery".to_string(),
            name: Some("Bravery".to_string()),
            description: Some("awarded for courage".to_string()),
            image: Some(Nip58BadgeImage {
                url: "https://example.com/badge.png".to_string(),
                dimensions: Some("64x64".to_string()),
            }),
            thumbs: Some(vec![Nip58BadgeImage {
                url: "https://example.com/thumb.png".to_string(),
                dimensions: Some("32x32".to_string()),
            }]),
            content: Some("badge definition".to_string()),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_badge_award_args(pubkey: &PublicKey) -> Nip58BadgeAwardArgs {
        Nip58BadgeAwardArgs {
            badge: sample_badge_coordinate(),
            badge_relay: Some("wss://relay.example.com".to_string()),
            recipients: vec![Nip58BadgeRecipient {
                pubkey: pubkey.to_hex(),
                relay: Some("wss://relay.example.com".to_string()),
            }],
            content: Some("badge award".to_string()),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_profile_badges_args() -> Nip58ProfileBadgesArgs {
        Nip58ProfileBadgesArgs {
            badges: vec![Nip58BadgeDisplay {
                badge: sample_badge_coordinate(),
                badge_relay: Some("wss://relay.example.com".to_string()),
                award_event_id:
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                award_relay: Some("wss://relay.example.com".to_string()),
            }],
            content: Some("profile badges".to_string()),
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
    fn badge_definition_requires_identifier() {
        let err = badge_definition_tags(&Nip58BadgeDefinitionArgs {
            identifier: " ".to_string(),
            name: None,
            description: None,
            image: None,
            thumbs: None,
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[test]
    fn badge_definition_accepts_all_optional_fields() {
        let tags = badge_definition_tags(&sample_badge_definition_args()).unwrap();

        assert_eq!(tags.len(), 5);
        assert_eq!(tags[0].as_slice()[0], "d");
        assert_eq!(tags[1].as_slice()[0], "name");
        assert_eq!(tags[2].as_slice()[0], "description");
        assert_eq!(tags[3].as_slice()[0], "image");
        assert_eq!(tags[4].as_slice()[0], "thumb");
    }

    #[test]
    fn badge_definition_accepts_minimal_required_fields() {
        let tags = badge_definition_tags(&Nip58BadgeDefinitionArgs {
            identifier: "bravery".to_string(),
            name: None,
            description: None,
            image: None,
            thumbs: None,
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].as_slice()[0], "d");
    }

    #[test]
    fn badge_definition_rejects_empty_name() {
        let mut args = sample_badge_definition_args();
        args.name = Some("   ".to_string());

        let err = badge_definition_tags(&args).unwrap_err();

        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn badge_definition_rejects_empty_description() {
        let mut args = sample_badge_definition_args();
        args.description = Some("   ".to_string());

        let err = badge_definition_tags(&args).unwrap_err();

        assert!(err.to_string().contains("description must not be empty"));
    }

    #[test]
    fn badge_definition_rejects_invalid_image_url() {
        let mut args = sample_badge_definition_args();
        args.image = Some(Nip58BadgeImage {
            url: "not-a-url".to_string(),
            dimensions: None,
        });

        let err = badge_definition_tags(&args).unwrap_err();

        assert!(err.to_string().contains("image url"));
    }

    #[test]
    fn badge_definition_rejects_invalid_thumb_dimensions() {
        let mut args = sample_badge_definition_args();
        args.thumbs = Some(vec![Nip58BadgeImage {
            url: "https://example.com/thumb.png".to_string(),
            dimensions: Some("bad".to_string()),
        }]);

        let err = badge_definition_tags(&args).unwrap_err();

        assert!(err.to_string().contains("image dimensions"));
    }

    #[test]
    fn push_image_tag_rejects_empty_url() {
        let mut tags = Vec::new();
        let err = push_image_tag(
            &mut tags,
            "image",
            &Nip58BadgeImage {
                url: "   ".to_string(),
                dimensions: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("image url must not be empty"));
    }

    #[test]
    fn push_image_tag_rejects_invalid_url() {
        let mut tags = Vec::new();
        let err = push_image_tag(
            &mut tags,
            "thumb",
            &Nip58BadgeImage {
                url: "not-a-url".to_string(),
                dimensions: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("image url"));
    }

    #[test]
    fn push_image_tag_rejects_invalid_dimensions() {
        let mut tags = Vec::new();
        let err = push_image_tag(
            &mut tags,
            "thumb",
            &Nip58BadgeImage {
                url: "https://example.com/thumb.png".to_string(),
                dimensions: Some("bad".to_string()),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("image dimensions"));
    }

    #[test]
    fn push_image_tag_accepts_thumb_without_dimensions() {
        let mut tags = Vec::new();

        push_image_tag(
            &mut tags,
            "thumb",
            &Nip58BadgeImage {
                url: "https://example.com/thumb.png".to_string(),
                dimensions: None,
            },
        )
        .unwrap();

        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].as_slice()[0], "thumb");
        assert_eq!(tags[0].as_slice().len(), 2);
    }

    #[test]
    fn push_image_tag_rejects_unsupported_kind() {
        let mut tags = Vec::new();
        let err = push_image_tag(
            &mut tags,
            "badge",
            &Nip58BadgeImage {
                url: "https://example.com/thumb.png".to_string(),
                dimensions: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("unsupported image tag kind"));
    }

    #[test]
    fn parse_badge_coordinate_accepts_valid_coordinate() {
        let coordinate = parse_badge_coordinate(&sample_badge_coordinate()).unwrap();

        assert_eq!(coordinate.kind, Kind::from(30009));
    }

    #[test]
    fn parse_badge_coordinate_rejects_invalid_coordinate() {
        let err = parse_badge_coordinate("not-a-coordinate").unwrap_err();

        assert!(err.to_string().contains("badge coordinate"));
    }

    #[test]
    fn badge_award_requires_recipients() {
        let err = badge_award_tags(&Nip58BadgeAwardArgs {
            badge: sample_badge_coordinate(),
            badge_relay: None,
            recipients: vec![],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("recipients must include"));
    }

    #[test]
    fn badge_award_accepts_relay_and_recipients() {
        let recipient = Keys::generate();
        let tags = badge_award_tags(&sample_badge_award_args(&recipient.public_key())).unwrap();

        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_slice()[0], "a");
        assert_eq!(tags[1].as_slice()[0], "p");
    }

    #[test]
    fn badge_award_accepts_without_optional_relays() {
        let recipient = Keys::generate();
        let tags = badge_award_tags(&Nip58BadgeAwardArgs {
            badge: sample_badge_coordinate(),
            badge_relay: None,
            recipients: vec![Nip58BadgeRecipient {
                pubkey: recipient.public_key().to_hex(),
                relay: None,
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_slice().len(), 2);
        assert_eq!(tags[1].as_slice().len(), 2);
    }

    #[test]
    fn badge_award_rejects_invalid_badge_relay() {
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.badge_relay = Some("not-a-relay".to_string());

        let err = badge_award_tags(&args).unwrap_err();

        assert!(err.to_string().contains("badge relay"));
    }

    #[test]
    fn badge_award_rejects_invalid_badge_coordinate() {
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.badge = "not-a-coordinate".to_string();

        let err = badge_award_tags(&args).unwrap_err();

        assert!(err.to_string().contains("badge coordinate"));
    }

    #[test]
    fn badge_award_rejects_invalid_recipient_pubkey() {
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.recipients[0].pubkey = "bad".to_string();

        let err = badge_award_tags(&args).unwrap_err();

        assert!(err.to_string().contains("recipient pubkey"));
    }

    #[test]
    fn badge_award_rejects_invalid_recipient_relay() {
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.recipients[0].relay = Some("not-a-relay".to_string());

        let err = badge_award_tags(&args).unwrap_err();

        assert!(err.to_string().contains("recipient relay"));
    }

    #[test]
    fn profile_badges_requires_valid_badge_coordinate() {
        let err = profile_badges_tags(&Nip58ProfileBadgesArgs {
            badges: vec![Nip58BadgeDisplay {
                badge: "1:0000000000000000000000000000000000000000000000000000000000000000:badge"
                    .to_string(),
                badge_relay: None,
                award_event_id: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                award_relay: None,
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("kind 30009"));
    }

    #[test]
    fn profile_badges_accepts_full_badge_display() {
        let tags = profile_badges_tags(&sample_profile_badges_args()).unwrap();

        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].as_slice()[0], "d");
        assert_eq!(tags[1].as_slice()[0], "a");
        assert_eq!(tags[2].as_slice()[0], "e");
    }

    #[test]
    fn profile_badges_accepts_without_optional_relays() {
        let tags = profile_badges_tags(&Nip58ProfileBadgesArgs {
            badges: vec![Nip58BadgeDisplay {
                badge: sample_badge_coordinate(),
                badge_relay: None,
                award_event_id:
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                award_relay: None,
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert_eq!(tags.len(), 3);
        assert_eq!(tags[1].as_slice().len(), 2);
        assert_eq!(tags[2].as_slice().len(), 2);
    }

    #[test]
    fn profile_badges_rejects_invalid_badge_relay() {
        let mut args = sample_profile_badges_args();
        args.badges[0].badge_relay = Some("not-a-relay".to_string());

        let err = profile_badges_tags(&args).unwrap_err();

        assert!(err.to_string().contains("badge relay"));
    }

    #[test]
    fn profile_badges_rejects_invalid_award_event_id() {
        let mut args = sample_profile_badges_args();
        args.badges[0].award_event_id = "bad".to_string();

        let err = profile_badges_tags(&args).unwrap_err();

        assert!(err.to_string().contains("award event id"));
    }

    #[test]
    fn profile_badges_rejects_invalid_award_relay() {
        let mut args = sample_profile_badges_args();
        args.badges[0].award_relay = Some("not-a-relay".to_string());

        let err = profile_badges_tags(&args).unwrap_err();

        assert!(err.to_string().contains("award relay"));
    }

    #[test]
    fn profile_badges_includes_profile_badges_tag() {
        let tags = profile_badges_tags(&Nip58ProfileBadgesArgs {
            badges: vec![],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(
            tags[0].as_slice(),
            &["d".to_string(), "profile_badges".to_string()]
        );
    }

    #[tokio::test]
    async fn post_badge_definition_rejects_invalid_input_before_publish() {
        let client = Client::new(Keys::generate());
        let err = post_badge_definition(
            &client,
            Nip58BadgeDefinitionArgs {
                identifier: "   ".to_string(),
                name: None,
                description: None,
                image: None,
                thumbs: None,
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[tokio::test]
    async fn post_badge_definition_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_badge_definition_args();
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_badge_definition(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(30009))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(30009));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_badge_definition_succeeds_without_pow_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_badge_definition_args();
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_badge_definition(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(30009))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(30009));
        assert!(!event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_badge_award_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_badge_award(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(8))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(8));
    }

    #[tokio::test]
    async fn post_badge_award_applies_pow_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_badge_award_args(&Keys::generate().public_key());
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_badge_award(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(8))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(8));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_profile_badges_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_profile_badges_args();
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_profile_badges(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(30008))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(30008));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_profile_badges_succeeds_without_pow_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_profile_badges_args();
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_profile_badges(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(30008))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(30008));
        assert!(!event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }
}
