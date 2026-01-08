use crate::error::CoreError;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EventsListArgs {
    pub preset: String,
    pub limit: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub author_npub: Option<String>,
    pub kind: Option<u16>,
    pub since: Option<u64>,
    pub until: Option<u64>,
}

impl EventsListArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

pub async fn subscription_targets_my_notes(
    pk: PublicKey,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
) -> Filter {
    let default_since = Timestamp::now() - 86400 * 7;
    let mut filter = Filter::new()
        .author(pk)
        .kind(Kind::TextNote)
        .since(since.unwrap_or(default_since));

    if let Some(u) = until {
        filter = filter.until(u);
    }
    filter
}

pub async fn subscription_targets_mentions_me(
    pk: PublicKey,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
) -> Filter {
    let default_since = Timestamp::now() - 86400 * 7;
    let needle = pk.to_string();
    let mut filter = Filter::new()
        .kind(Kind::TextNote)
        .search(needle)
        .since(since.unwrap_or(default_since));

    if let Some(u) = until {
        filter = filter.until(u);
    }
    filter
}

pub async fn subscription_targets_my_metadata(pk: PublicKey) -> Filter {
    Filter::new().author(pk).kind(Kind::Metadata).limit(1)
}

pub async fn list_events(
    client: &Client,
    filter: Filter,
    timeout_secs: u64,
) -> Result<Vec<Event>, CoreError> {
    let events = client
        .fetch_events(filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::Nostr(format!("fetch events: {e}")))?;
    Ok(events.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::{
        subscription_targets_mentions_me, subscription_targets_my_metadata,
        subscription_targets_my_notes,
    };
    use nostr_sdk::prelude::*;

    #[tokio::test]
    async fn my_notes_sets_kind_and_author() {
        let pk = Keys::generate().public_key();
        let since = Timestamp::from(100);
        let until = Timestamp::from(200);
        let filter = subscription_targets_my_notes(pk, Some(since), Some(until)).await;

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.authors.as_ref().unwrap().contains(&pk));
        assert_eq!(filter.since, Some(since));
        assert_eq!(filter.until, Some(until));
    }

    #[tokio::test]
    async fn mentions_me_sets_search() {
        let pk = Keys::generate().public_key();
        let filter = subscription_targets_mentions_me(pk, None, None).await;
        assert_eq!(filter.search.as_deref(), Some(pk.to_string().as_str()));
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(filter.since.is_some());
    }

    #[tokio::test]
    async fn my_metadata_limits_to_one() {
        let pk = Keys::generate().public_key();
        let filter = subscription_targets_my_metadata(pk).await;
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::Metadata));
        assert_eq!(filter.limit, Some(1));
    }
}
