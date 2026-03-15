use crate::error::CoreError;
use crate::publish::publish_event_builder;
use nostr_mcp_types::nip89::{Nip89HandlerInfoArgs, Nip89RecommendArgs};
use nostr_mcp_types::publish::SendResult;
use nostr_sdk::prelude::*;

pub async fn post_recommendation(
    client: &Client,
    args: Nip89RecommendArgs,
) -> Result<SendResult, CoreError> {
    let tags = recommendation_tags(&args)?;
    let content = args.content.unwrap_or_default();
    let mut builder = EventBuilder::new(Kind::from(31989), content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

pub async fn post_handler_info(
    client: &Client,
    args: Nip89HandlerInfoArgs,
) -> Result<SendResult, CoreError> {
    let tags = handler_info_tags(&args)?;
    let content = args.content.unwrap_or_default();
    let mut builder = EventBuilder::new(Kind::from(31990), content).tags(tags);

    if let Some(pow) = args.pow {
        builder = builder.pow(pow);
    }

    publish_event_builder(client, builder, args.to_relays).await
}

fn recommendation_tags(args: &Nip89RecommendArgs) -> Result<Vec<Tag>, CoreError> {
    if args.handlers.is_empty() {
        return Err(CoreError::invalid_input(
            "handlers must include at least one entry",
        ));
    }

    let mut tags = vec![Tag::identifier(args.supported_kind.to_string())];

    for handler in &args.handlers {
        if handler.platform.is_some() && handler.relay.is_none() {
            return Err(CoreError::invalid_input(
                "handler relay is required when platform is provided",
            ));
        }

        let coordinate = Coordinate::parse(handler.address.trim())
            .map_err(|e| CoreError::invalid_input(format!("handler address: {e}")))?;
        if coordinate.kind != Kind::from(31990) {
            return Err(CoreError::invalid_input(
                "handler address must reference kind 31990",
            ));
        }

        let mut values = vec![coordinate.to_string()];

        if let Some(relay_url) = handler
            .relay
            .as_ref()
            .map(|relay| {
                RelayUrl::parse(relay)
                    .map_err(|e| CoreError::invalid_input(format!("relay url: {e}")))
            })
            .transpose()?
        {
            values.push(relay_url.to_string());
        }

        if let Some(platform) = handler.platform.as_ref() {
            values.push(platform.clone());
        }

        tags.push(Tag::custom(TagKind::a(), values));
    }

    Ok(tags)
}

fn handler_info_tags(args: &Nip89HandlerInfoArgs) -> Result<Vec<Tag>, CoreError> {
    if args.identifier.trim().is_empty() {
        return Err(CoreError::invalid_input("identifier must not be empty"));
    }
    if args.kinds.is_empty() {
        return Err(CoreError::invalid_input(
            "kinds must include at least one entry",
        ));
    }

    let mut tags = vec![Tag::identifier(args.identifier.trim().to_string())];

    for kind in &args.kinds {
        tags.push(Tag::custom(TagKind::k(), [kind.to_string()]));
    }

    for link in &args.links {
        if link.platform.trim().is_empty() {
            return Err(CoreError::invalid_input("platform must not be empty"));
        }
        let url = Url::parse(link.url.trim())
            .map_err(|e| CoreError::invalid_input(format!("handler url: {e}")))?;

        if let Some(entity) = link.entity.as_ref()
            && !is_valid_entity(entity)
        {
            return Err(CoreError::invalid_input(format!(
                "invalid entity type: {entity}"
            )));
        }

        let mut values = vec![url.to_string()];
        if let Some(entity) = link.entity.as_ref() {
            values.push(entity.clone());
        }
        tags.push(Tag::custom(
            TagKind::custom(link.platform.trim().to_string()),
            values,
        ));
    }

    Ok(tags)
}

fn is_valid_entity(entity: &str) -> bool {
    matches!(
        entity,
        "npub" | "nprofile" | "note" | "nevent" | "naddr" | "nrelay"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        handler_info_tags, is_valid_entity, post_handler_info, post_recommendation,
        recommendation_tags,
    };
    use nostr_mcp_types::nip89::{
        Nip89HandlerInfoArgs, Nip89HandlerLink, Nip89HandlerRecommendation, Nip89RecommendArgs,
    };
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;

    fn sample_handler_address() -> String {
        "31990:0000000000000000000000000000000000000000000000000000000000000000:app"
            .to_string()
    }

    fn sample_recommend_args() -> Nip89RecommendArgs {
        Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![
                Nip89HandlerRecommendation {
                    address: sample_handler_address(),
                    relay: Some("wss://relay.example.com".to_string()),
                    platform: Some("web".to_string()),
                },
                Nip89HandlerRecommendation {
                    address: sample_handler_address(),
                    relay: None,
                    platform: None,
                },
            ],
            content: Some("recommendation".to_string()),
            pow: None,
            to_relays: None,
        }
    }

    fn sample_handler_info_args() -> Nip89HandlerInfoArgs {
        Nip89HandlerInfoArgs {
            identifier: "app".to_string(),
            kinds: vec![1, 30315],
            links: vec![
                Nip89HandlerLink {
                    platform: "web".to_string(),
                    url: "https://example.com".to_string(),
                    entity: Some("nevent".to_string()),
                },
                Nip89HandlerLink {
                    platform: "desktop".to_string(),
                    url: "https://example.com/desktop".to_string(),
                    entity: None,
                },
            ],
            content: Some("handler info".to_string()),
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
    fn recommendation_tags_require_handlers() {
        let err = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("handlers must include"));
    }

    #[test]
    fn recommendation_tags_accept_valid_handlers() {
        let tags = recommendation_tags(&sample_recommend_args()).unwrap();

        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].as_slice()[0], "d");
        assert_eq!(tags[1].as_slice()[0], "a");
        assert_eq!(tags[2].as_slice()[0], "a");
    }

    #[test]
    fn recommendation_tags_accept_relay_without_platform() {
        let tags = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![Nip89HandlerRecommendation {
                address: sample_handler_address(),
                relay: Some("wss://relay.example.com".to_string()),
                platform: None,
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert_eq!(tags.len(), 2);
        assert_eq!(tags[1].as_slice()[0], "a");
        assert_eq!(tags[1].as_slice().len(), 3);
    }

    #[test]
    fn recommendation_tags_rejects_invalid_address() {
        let mut args = sample_recommend_args();
        args.handlers[0].address = "not-a-coordinate".to_string();

        let err = recommendation_tags(&args).unwrap_err();

        assert!(err.to_string().contains("handler address"));
    }

    #[test]
    fn recommendation_tags_rejects_wrong_kind() {
        let err = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![Nip89HandlerRecommendation {
                address: "1:0000000000000000000000000000000000000000000000000000000000000000:abc"
                    .to_string(),
                relay: Some("wss://relay.example".to_string()),
                platform: Some("web".to_string()),
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("kind 31990"));
    }

    #[test]
    fn recommendation_tags_rejects_invalid_relay() {
        let mut args = sample_recommend_args();
        args.handlers[0].relay = Some("not-a-relay".to_string());

        let err = recommendation_tags(&args).unwrap_err();

        assert!(err.to_string().contains("relay url"));
    }

    #[test]
    fn recommendation_tags_rejects_platform_without_relay() {
        let err = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![Nip89HandlerRecommendation {
                address:
                    "31990:0000000000000000000000000000000000000000000000000000000000000000:abc"
                        .to_string(),
                relay: None,
                platform: Some("web".to_string()),
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("relay is required"));
    }

    #[test]
    fn handler_info_tags_rejects_empty_identifier() {
        let mut args = sample_handler_info_args();
        args.identifier = "   ".to_string();

        let err = handler_info_tags(&args).unwrap_err();

        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[test]
    fn handler_info_tags_rejects_empty_kinds() {
        let mut args = sample_handler_info_args();
        args.kinds = Vec::new();

        let err = handler_info_tags(&args).unwrap_err();

        assert!(err.to_string().contains("kinds must include"));
    }

    #[test]
    fn handler_info_tags_rejects_empty_platform() {
        let mut args = sample_handler_info_args();
        args.links[0].platform = "   ".to_string();

        let err = handler_info_tags(&args).unwrap_err();

        assert!(err.to_string().contains("platform must not be empty"));
    }

    #[test]
    fn handler_info_tags_rejects_invalid_url() {
        let mut args = sample_handler_info_args();
        args.links[0].url = "not-a-url".to_string();

        let err = handler_info_tags(&args).unwrap_err();

        assert!(err.to_string().contains("handler url"));
    }

    #[test]
    fn handler_info_tags_rejects_invalid_entity() {
        let err = handler_info_tags(&Nip89HandlerInfoArgs {
            identifier: "app".to_string(),
            kinds: vec![1],
            links: vec![Nip89HandlerLink {
                platform: "web".to_string(),
                url: "https://example.com".to_string(),
                entity: Some("bad".to_string()),
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid entity type"));
    }

    #[test]
    fn handler_info_tags_accepts_valid_link() {
        let tags = handler_info_tags(&sample_handler_info_args()).unwrap();

        assert!(
            tags.iter()
                .any(|tag| tag.as_slice().first().map(String::as_str) == Some("d"))
        );
        assert_eq!(
            tags.iter()
                .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("k"))
                .count(),
            2
        );
        assert!(
            tags.iter()
                .any(|tag| tag.as_slice().first().map(String::as_str) == Some("web"))
        );
        assert!(
            tags.iter()
                .any(|tag| tag.as_slice().first().map(String::as_str) == Some("desktop"))
        );
    }

    #[test]
    fn handler_info_tags_accepts_without_links() {
        let tags = handler_info_tags(&Nip89HandlerInfoArgs {
            identifier: "app".to_string(),
            kinds: vec![1, 30315],
            links: vec![],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].as_slice()[0], "d");
        assert_eq!(tags[1].as_slice()[0], "k");
        assert_eq!(tags[2].as_slice()[0], "k");
    }

    #[test]
    fn valid_entity_set_remains_stable() {
        for entity in ["npub", "nprofile", "note", "nevent", "naddr", "nrelay"] {
            assert!(is_valid_entity(entity));
        }
        assert!(!is_valid_entity("bad"));
    }

    #[tokio::test]
    async fn post_recommendation_rejects_invalid_input_before_publish() {
        let client = Client::new(Keys::generate());
        let err = post_recommendation(
            &client,
            Nip89RecommendArgs {
                supported_kind: 1,
                handlers: vec![],
                content: None,
                pow: None,
                to_relays: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("handlers must include"));
    }

    #[tokio::test]
    async fn post_recommendation_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_recommend_args();
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_recommendation(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(31989))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(31989));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_recommendation_succeeds_without_pow_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_recommend_args();
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_recommendation(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(31989))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(31989));
        assert!(!event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[tokio::test]
    async fn post_handler_info_rejects_invalid_input_before_publish() {
        let client = Client::new(Keys::generate());
        let err = post_handler_info(
            &client,
            Nip89HandlerInfoArgs {
                identifier: "   ".to_string(),
                kinds: vec![1],
                links: vec![],
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
    async fn post_handler_info_succeeds_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_handler_info_args();
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_handler_info(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(31990))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(31990));
    }

    #[tokio::test]
    async fn post_handler_info_applies_pow_against_mock_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = connected_client(keys.clone(), &url).await;
        let mut args = sample_handler_info_args();
        args.pow = Some(1);
        args.to_relays = Some(vec![url.to_string()]);

        let result = post_handler_info(&client, args).await.unwrap();
        let events = client
            .fetch_events(
                Filter::new()
                    .kind(Kind::from(31990))
                    .author(keys.public_key())
                    .limit(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        let event = events.first().unwrap();

        assert_eq!(result.success, vec![url.to_string()]);
        assert_eq!(event.kind, Kind::from(31990));
        assert!(event.tags.iter().any(|tag| tag.kind() == TagKind::Nonce));
    }

    #[test]
    fn handler_info_tags_produces_expected_tag_count() {
        let tags = handler_info_tags(&sample_handler_info_args()).unwrap();

        assert_eq!(tags.len(), 5);
    }
}
