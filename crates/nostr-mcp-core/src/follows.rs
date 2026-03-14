use crate::error::CoreError;
use nostr_mcp_types::follows::PublishFollowsResult;
use nostr_mcp_types::settings::FollowEntry;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

type FollowsFetchFuture =
    Pin<Box<dyn Future<Output = Result<Vec<Event>, CoreError>> + Send + 'static>>;
#[cfg(test)]
type FollowsSendFuture =
    Pin<Box<dyn Future<Output = Result<PublishedFollowsOutput, CoreError>> + Send + 'static>>;
#[cfg(test)]
type FollowsSignerFuture =
    Pin<Box<dyn Future<Output = Result<String, CoreError>> + Send + 'static>>;
type FollowsReadFuture =
    Pin<Box<dyn Future<Output = Result<Vec<FollowEntry>, CoreError>> + Send + 'static>>;
type FollowsWriteFuture = Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedFollowsOutput {
    event_id: String,
    success_relays: Vec<String>,
    failed_relays: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FollowSyncPlan {
    follows: Vec<FollowEntry>,
    published: bool,
    to_publish: Option<Vec<FollowEntry>>,
}

fn follows_to_tags(follows: &[FollowEntry]) -> Vec<Tag> {
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
        let tag = Tag::parse(&tag_values).expect("follow tags are never empty");
        tags.push(tag);
    }
    tags
}

fn tags_to_follows(tags: &[Tag]) -> Vec<FollowEntry> {
    let mut follows = Vec::new();
    for tag in tags {
        if tag.kind() == TagKind::p()
            && let Some(pubkey_str) = tag.content()
        {
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
    follows
}

fn follows_from_events<T>(events: T) -> Vec<FollowEntry>
where
    T: IntoIterator<Item = Event>,
{
    if let Some(event) = events.into_iter().next() {
        tags_to_follows(event.tags.as_slice())
    } else {
        Vec::new()
    }
}

fn collect_follow_events(events: Events) -> Vec<Event> {
    events.into_iter().collect()
}

async fn fetch_follows_with(
    pubkey: PublicKey,
    fetch: &mut (dyn FnMut(Filter, Duration) -> FollowsFetchFuture + Send),
) -> Result<Vec<FollowEntry>, CoreError> {
    let filter = Filter::new()
        .author(pubkey)
        .kind(Kind::ContactList)
        .limit(1);
    let events = fetch(filter, Duration::from_secs(10)).await?;
    Ok(follows_from_events(events))
}

pub async fn fetch_follows(
    client: &Client,
    pubkey: &PublicKey,
) -> Result<Vec<FollowEntry>, CoreError> {
    let client = client.clone();
    let mut fetch = move |filter, timeout| -> FollowsFetchFuture {
        let client = client.clone();
        Box::pin(async move {
            client
                .fetch_events(filter, timeout)
                .await
                .map(collect_follow_events)
                .map_err(|e| CoreError::operation(format!("fetch follows: {e}")))
        })
    };
    fetch_follows_with(*pubkey, &mut fetch).await
}

fn published_follows_output(out: Output<EventId>) -> PublishedFollowsOutput {
    PublishedFollowsOutput {
        event_id: out.id().to_string(),
        success_relays: out.success.into_iter().map(|u| u.to_string()).collect(),
        failed_relays: out
            .failed
            .into_iter()
            .map(|(u, e)| (u.to_string(), e))
            .collect(),
    }
}

fn publish_follows_result(
    output: PublishedFollowsOutput,
    signer_pubkey: String,
) -> PublishFollowsResult {
    PublishFollowsResult {
        saved: true,
        published: true,
        event_id: Some(output.event_id),
        pubkey: Some(signer_pubkey),
        success_relays: output.success_relays,
        failed_relays: output.failed_relays,
    }
}

#[cfg(test)]
async fn publish_follows_with(
    follows: &[FollowEntry],
    send: &mut (dyn FnMut(EventBuilder) -> FollowsSendFuture + Send),
    signer_pubkey: &mut (dyn FnMut() -> FollowsSignerFuture + Send),
) -> Result<PublishFollowsResult, CoreError> {
    let tags = follows_to_tags(follows);
    let builder = EventBuilder::new(Kind::ContactList, "").tags(tags);
    let output = send(builder).await?;
    let signer_pubkey = signer_pubkey().await?;
    Ok(publish_follows_result(output, signer_pubkey))
}

pub async fn publish_follows(
    client: &Client,
    follows: &[FollowEntry],
) -> Result<PublishFollowsResult, CoreError> {
    let tags = follows_to_tags(follows);
    let builder = EventBuilder::new(Kind::ContactList, "").tags(tags);
    let signer = match client.signer().await {
        Ok(signer) => signer,
        Err(e) => return Err(CoreError::operation(format!("get signer: {e}"))),
    };
    let signer_pubkey = match signer.get_public_key().await {
        Ok(pubkey) => pubkey.to_hex(),
        Err(e) => return Err(CoreError::operation(format!("get signer pubkey: {e}"))),
    };
    let output = match client.send_event_builder(builder).await {
        Ok(output) => output,
        Err(e) => return Err(CoreError::operation(format!("publish follows: {e}"))),
    };
    Ok(publish_follows_result(
        published_follows_output(output),
        signer_pubkey,
    ))
}

fn plan_follow_sync(
    local_follows: Vec<FollowEntry>,
    relay_follows: Vec<FollowEntry>,
) -> FollowSyncPlan {
    if local_follows != relay_follows {
        if !local_follows.is_empty() {
            FollowSyncPlan {
                follows: local_follows.clone(),
                published: true,
                to_publish: Some(local_follows),
            }
        } else {
            FollowSyncPlan {
                follows: relay_follows,
                published: false,
                to_publish: None,
            }
        }
    } else {
        FollowSyncPlan {
            follows: local_follows,
            published: false,
            to_publish: None,
        }
    }
}

async fn sync_follows_with(
    pubkey: PublicKey,
    local_follows: Vec<FollowEntry>,
    fetch: &mut (dyn FnMut(PublicKey) -> FollowsReadFuture + Send),
    publish: &mut (dyn FnMut(Vec<FollowEntry>) -> FollowsWriteFuture + Send),
) -> Result<(Vec<FollowEntry>, bool), CoreError> {
    let relay_follows = fetch(pubkey).await?;
    let plan = plan_follow_sync(local_follows, relay_follows);
    if let Some(follows) = plan.to_publish.clone() {
        publish(follows).await?;
    }
    Ok((plan.follows, plan.published))
}

fn client_publish_follows(client: Client, follows: Vec<FollowEntry>) -> FollowsWriteFuture {
    Box::pin(async move { publish_follows(&client, &follows).await.map(|_| ()) })
}

pub async fn sync_follows(
    client: &Client,
    pubkey: &PublicKey,
    local_follows: Vec<FollowEntry>,
) -> Result<(Vec<FollowEntry>, bool), CoreError> {
    let fetch_client = client.clone();
    let mut fetch = move |pubkey| -> FollowsReadFuture {
        let client = fetch_client.clone();
        Box::pin(async move { fetch_follows(&client, &pubkey).await })
    };
    let publish_client = client.clone();
    let mut publish = move |follows: Vec<FollowEntry>| -> FollowsWriteFuture {
        client_publish_follows(publish_client.clone(), follows)
    };
    sync_follows_with(*pubkey, local_follows, &mut fetch, &mut publish).await
}

#[cfg(test)]
mod tests;
