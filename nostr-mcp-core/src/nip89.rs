use crate::error::CoreError;
use crate::publish::{publish_event_builder, SendResult};
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89RecommendArgs {
    pub supported_kind: u16,
    pub handlers: Vec<Nip89HandlerRecommendation>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerRecommendation {
    pub address: String,
    pub relay: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerInfoArgs {
    pub identifier: String,
    pub kinds: Vec<u16>,
    pub links: Vec<Nip89HandlerLink>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerLink {
    pub platform: String,
    pub url: String,
    pub entity: Option<String>,
}

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

    let mut tags = Vec::with_capacity(args.handlers.len() + 1);
    tags.push(Tag::parse(&["d".to_string(), args.supported_kind.to_string()]).map_err(
        |e| CoreError::invalid_input(format!("d tag: {e}")),
    )?);

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

        let mut values = vec!["a".to_string(), coordinate.to_string()];

        if let Some(relay) = handler.relay.as_ref() {
            RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("relay url: {e}")))?;
            values.push(relay.clone());
        }

        if let Some(platform) = handler.platform.as_ref() {
            values.push(platform.clone());
        }

        tags.push(
            Tag::parse(&values)
                .map_err(|e| CoreError::invalid_input(format!("a tag: {e}")))?,
        );
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

    let mut tags = Vec::new();
    tags.push(
        Tag::parse(&["d".to_string(), args.identifier.trim().to_string()])
            .map_err(|e| CoreError::invalid_input(format!("d tag: {e}")))?,
    );

    for kind in &args.kinds {
        tags.push(
            Tag::parse(&["k".to_string(), kind.to_string()])
                .map_err(|e| CoreError::invalid_input(format!("k tag: {e}")))?,
        );
    }

    for link in &args.links {
        if link.platform.trim().is_empty() {
            return Err(CoreError::invalid_input("platform must not be empty"));
        }
        Url::parse(link.url.trim())
            .map_err(|e| CoreError::invalid_input(format!("handler url: {e}")))?;

        if let Some(entity) = link.entity.as_ref() {
            if !is_valid_entity(entity) {
                return Err(CoreError::invalid_input(format!(
                    "invalid entity type: {entity}"
                )));
            }
        }

        let mut values = vec![link.platform.trim().to_string(), link.url.trim().to_string()];
        if let Some(entity) = link.entity.as_ref() {
            values.push(entity.clone());
        }
        tags.push(
            Tag::parse(&values)
                .map_err(|e| CoreError::invalid_input(format!("handler tag: {e}")))?,
        );
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
    use super::{handler_info_tags, recommendation_tags, Nip89HandlerInfoArgs, Nip89HandlerLink, Nip89HandlerRecommendation, Nip89RecommendArgs};

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
    fn recommendation_tags_rejects_wrong_kind() {
        let err = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![Nip89HandlerRecommendation {
                address: "1:0000000000000000000000000000000000000000000000000000000000000000:abc".to_string(),
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
    fn recommendation_tags_rejects_platform_without_relay() {
        let err = recommendation_tags(&Nip89RecommendArgs {
            supported_kind: 1,
            handlers: vec![Nip89HandlerRecommendation {
                address: "31990:0000000000000000000000000000000000000000000000000000000000000000:abc".to_string(),
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
        let tags = handler_info_tags(&Nip89HandlerInfoArgs {
            identifier: "app".to_string(),
            kinds: vec![1, 30315],
            links: vec![Nip89HandlerLink {
                platform: "web".to_string(),
                url: "https://example.com".to_string(),
                entity: Some("nevent".to_string()),
            }],
            content: None,
            pow: None,
            to_relays: None,
        })
        .unwrap();

        assert!(tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some("d")));
        assert!(tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some("k")));
        assert!(tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some("web")));
    }
}
