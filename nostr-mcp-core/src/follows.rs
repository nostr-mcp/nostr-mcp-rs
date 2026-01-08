use crate::error::CoreError;
use crate::settings::FollowEntry;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetFollowsArgs {
    pub follows: Vec<FollowEntry>,
    pub publish: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddFollowArgs {
    pub pubkey: String,
    pub relay_url: Option<String>,
    pub petname: Option<String>,
    pub publish: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveFollowArgs {
    pub pubkey: String,
    pub publish: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct FollowsResult {
    pub follows: Vec<FollowEntry>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct PublishFollowsResult {
    pub saved: bool,
    pub published: bool,
    pub event_id: Option<String>,
    pub pubkey: Option<String>,
    pub success_relays: Vec<String>,
    pub failed_relays: HashMap<String, String>,
}

fn follows_to_tags(follows: &[FollowEntry]) -> Result<Vec<Tag>, CoreError> {
    let mut tags = Vec::with_capacity(follows.len());
    for follow in follows {
        let mut tag_values = vec!["p".to_string(), follow.pubkey.clone()];
        if let Some(ref relay) = follow.relay_url {
            tag_values.push(relay.clone());
        } else {
            tag_values.push(String::new());
        }
        if let Some(ref petname) = follow.petname {
            tag_values.push(petname.clone());
        }
        let tag = Tag::parse(&tag_values)
            .map_err(|e| CoreError::Nostr(format!("invalid follow tag: {e}")))?;
        tags.push(tag);
    }
    Ok(tags)
}

fn tags_to_follows<'a, T>(tags: T) -> Vec<FollowEntry>
where
    T: IntoIterator<Item = &'a Tag>,
{
    let mut follows = Vec::new();
    for tag in tags {
        if tag.kind() == TagKind::p() {
            if let Some(pubkey_str) = tag.content() {
                let tag_vec = tag.clone().to_vec();
                let relay_url = tag_vec.get(2).cloned().filter(|s| !s.is_empty());
                let petname = tag_vec.get(3).cloned().filter(|s| !s.is_empty());
                follows.push(FollowEntry {
                    pubkey: pubkey_str.to_string(),
                    relay_url,
                    petname,
                });
            }
        }
    }
    follows
}

pub async fn fetch_follows(client: &Client, pubkey: &PublicKey) -> Result<Vec<FollowEntry>, CoreError> {
    let filter = Filter::new()
        .author(*pubkey)
        .kind(Kind::ContactList)
        .limit(1);

    let events = client
        .fetch_events(filter, std::time::Duration::from_secs(10))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch follows: {e}")))?;

    if let Some(event) = events.into_iter().next() {
        Ok(tags_to_follows(event.tags.iter()))
    } else {
        Ok(Vec::new())
    }
}

pub async fn publish_follows(
    client: &Client,
    follows: &[FollowEntry],
) -> Result<PublishFollowsResult, CoreError> {
    let tags = follows_to_tags(follows)?;
    let builder = EventBuilder::new(Kind::ContactList, "").tags(tags);

    let out = client
        .send_event_builder(builder)
        .await
        .map_err(|e| CoreError::Nostr(format!("publish follows: {e}")))?;
    let signer_pubkey = client
        .signer()
        .await
        .map_err(|e| CoreError::Nostr(format!("get signer: {e}")))?
        .get_public_key()
        .await
        .map_err(|e| CoreError::Nostr(format!("get signer pubkey: {e}")))?
        .to_hex();

    let event_id = out.id().to_string();
    let success = out.success.into_iter().map(|u| u.to_string()).collect();
    let failed = out
        .failed
        .into_iter()
        .map(|(u, e)| (u.to_string(), e.to_string()))
        .collect();

    Ok(PublishFollowsResult {
        saved: true,
        published: true,
        event_id: Some(event_id),
        pubkey: Some(signer_pubkey),
        success_relays: success,
        failed_relays: failed,
    })
}

pub async fn sync_follows(
    client: &Client,
    pubkey: &PublicKey,
    local_follows: Vec<FollowEntry>,
) -> Result<(Vec<FollowEntry>, bool), CoreError> {
    let relay_follows = fetch_follows(client, pubkey).await?;

    if local_follows != relay_follows {
        if !local_follows.is_empty() {
            publish_follows(client, &local_follows).await?;
            Ok((local_follows, true))
        } else {
            Ok((relay_follows, false))
        }
    } else {
        Ok((local_follows, false))
    }
}

#[cfg(test)]
mod tests {
    use super::{follows_to_tags, tags_to_follows};
    use crate::settings::FollowEntry;

    #[test]
    fn follows_tags_round_trip() {
        let follows = vec![
            FollowEntry {
                pubkey: "pubkey1".to_string(),
                relay_url: Some("wss://relay.example".to_string()),
                petname: Some("alice".to_string()),
            },
            FollowEntry {
                pubkey: "pubkey2".to_string(),
                relay_url: None,
                petname: None,
            },
        ];

        let tags = follows_to_tags(&follows).unwrap();
        let decoded = tags_to_follows(tags.iter());
        assert_eq!(decoded, follows);
    }
}
