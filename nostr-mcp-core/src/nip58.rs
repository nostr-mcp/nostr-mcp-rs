use crate::error::CoreError;
use crate::publish::{publish_event_builder, SendResult};
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeDefinitionArgs {
    pub identifier: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<Nip58BadgeImage>,
    pub thumbs: Option<Vec<Nip58BadgeImage>>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeImage {
    pub url: String,
    pub dimensions: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeAwardArgs {
    pub badge: String,
    pub badge_relay: Option<String>,
    pub recipients: Vec<Nip58BadgeRecipient>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeRecipient {
    pub pubkey: String,
    pub relay: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58ProfileBadgesArgs {
    pub badges: Vec<Nip58BadgeDisplay>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeDisplay {
    pub badge: String,
    pub badge_relay: Option<String>,
    pub award_event_id: String,
    pub award_relay: Option<String>,
}

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

fn badge_definition_tags(args: &Nip58BadgeDefinitionArgs) -> Result<Vec<Tag>, CoreError> {
    let identifier = args.identifier.trim();
    if identifier.is_empty() {
        return Err(CoreError::invalid_input("identifier must not be empty"));
    }

    let mut tags = Vec::new();
    tags.push(
        Tag::parse(&["d".to_string(), identifier.to_string()])
            .map_err(|e| CoreError::invalid_input(format!("d tag: {e}")))?,
    );

    if let Some(name) = args.name.as_ref() {
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::invalid_input("name must not be empty"));
        }
        tags.push(
            Tag::parse(&["name".to_string(), name.to_string()])
                .map_err(|e| CoreError::invalid_input(format!("name tag: {e}")))?,
        );
    }

    if let Some(description) = args.description.as_ref() {
        let description = description.trim();
        if description.is_empty() {
            return Err(CoreError::invalid_input("description must not be empty"));
        }
        tags.push(
            Tag::parse(&["description".to_string(), description.to_string()])
                .map_err(|e| CoreError::invalid_input(format!("description tag: {e}")))?,
        );
    }

    if let Some(image) = args.image.as_ref() {
        push_image_tag(&mut tags, "image", image)?;
    }

    if let Some(thumbs) = args.thumbs.as_ref() {
        for thumb in thumbs {
            push_image_tag(&mut tags, "thumb", thumb)?;
        }
    }

    Ok(tags)
}

fn badge_award_tags(args: &Nip58BadgeAwardArgs) -> Result<Vec<Tag>, CoreError> {
    if args.recipients.is_empty() {
        return Err(CoreError::invalid_input(
            "recipients must include at least one entry",
        ));
    }

    let coordinate = parse_badge_coordinate(&args.badge)?;
    let mut tags = Vec::new();

    let mut a_tag = vec!["a".to_string(), coordinate.to_string()];
    if let Some(relay) = args.badge_relay.as_ref() {
        RelayUrl::parse(relay)
            .map_err(|e| CoreError::invalid_input(format!("badge relay: {e}")))?;
        a_tag.push(relay.clone());
    }
    tags.push(
        Tag::parse(&a_tag).map_err(|e| CoreError::invalid_input(format!("a tag: {e}")))?,
    );

    for recipient in &args.recipients {
        let pubkey = PublicKey::parse(recipient.pubkey.trim())
            .map_err(|e| CoreError::invalid_input(format!("recipient pubkey: {e}")))?;
        let mut values = vec!["p".to_string(), pubkey.to_hex()];

        if let Some(relay) = recipient.relay.as_ref() {
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("recipient relay: {e}")))?;
            values.push(relay.clone());
        }

        tags.push(
            Tag::parse(&values).map_err(|e| CoreError::invalid_input(format!("p tag: {e}")))?,
        );
    }

    Ok(tags)
}

fn profile_badges_tags(args: &Nip58ProfileBadgesArgs) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::new();
    tags.push(
        Tag::parse(&["d".to_string(), "profile_badges".to_string()])
            .map_err(|e| CoreError::invalid_input(format!("d tag: {e}")))?,
    );

    for badge in &args.badges {
        let coordinate = parse_badge_coordinate(&badge.badge)?;
        let mut a_tag = vec!["a".to_string(), coordinate.to_string()];
        if let Some(relay) = badge.badge_relay.as_ref() {
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("badge relay: {e}")))?;
            a_tag.push(relay.clone());
        }
        tags.push(
            Tag::parse(&a_tag).map_err(|e| CoreError::invalid_input(format!("a tag: {e}")))?,
        );

        let event_id = EventId::parse(badge.award_event_id.trim())
            .map_err(|e| CoreError::invalid_input(format!("award event id: {e}")))?;
        let mut e_tag = vec!["e".to_string(), event_id.to_hex()];
        if let Some(relay) = badge.award_relay.as_ref() {
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("award relay: {e}")))?;
            e_tag.push(relay.clone());
        }
        tags.push(
            Tag::parse(&e_tag).map_err(|e| CoreError::invalid_input(format!("e tag: {e}")))?,
        );
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
    Url::parse(url).map_err(|e| CoreError::invalid_input(format!("image url: {e}")))?;

    let mut values = vec![kind.to_string(), url.to_string()];
    if let Some(dimensions) = image.dimensions.as_ref() {
        let dimensions = ImageDimensions::from_str(dimensions.trim())
            .map_err(|e| CoreError::invalid_input(format!("image dimensions: {e}")))?;
        values.push(dimensions.to_string());
    }

    tags.push(
        Tag::parse(&values).map_err(|e| CoreError::invalid_input(format!("{kind} tag: {e}")))?,
    );
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
        badge_award_tags, badge_definition_tags, profile_badges_tags, Nip58BadgeAwardArgs,
        Nip58BadgeDefinitionArgs, Nip58BadgeDisplay, Nip58ProfileBadgesArgs,
    };

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
    fn badge_award_requires_recipients() {
        let err = badge_award_tags(&Nip58BadgeAwardArgs {
            badge: "30009:0000000000000000000000000000000000000000000000000000000000000000:bravery"
                .to_string(),
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
    fn profile_badges_requires_valid_badge_coordinate() {
        let err = profile_badges_tags(&Nip58ProfileBadgesArgs {
            badges: vec![Nip58BadgeDisplay {
                badge: "1:0000000000000000000000000000000000000000000000000000000000000000:badge"
                    .to_string(),
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
        .unwrap_err();
        assert!(err.to_string().contains("kind 30009"));
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
        assert_eq!(tags[0].as_slice(), &["d".to_string(), "profile_badges".to_string()]);
    }
}
