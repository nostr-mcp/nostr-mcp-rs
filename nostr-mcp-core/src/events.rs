use crate::error::CoreError;
use crate::nip01;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryEventsArgs {
    pub filters: Vec<Value>,
    pub timeout_secs: Option<u64>,
    pub limit: Option<u64>,
}

impl QueryEventsArgs {
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

pub async fn query_events(
    client: &Client,
    args: QueryEventsArgs,
) -> Result<Vec<Event>, CoreError> {
    let filters = parse_filters(&args)?;
    let timeout = std::time::Duration::from_secs(args.timeout());
    let mut out = Vec::new();
    let mut seen: HashSet<EventId> = HashSet::new();

    for filter in filters {
        let events = client
            .fetch_events(filter, timeout)
            .await
            .map_err(|e| CoreError::Nostr(format!("fetch events: {e}")))?;
        for event in events.into_iter() {
            if seen.insert(event.id) {
                out.push(event);
                if let Some(limit) = args.limit {
                    if out.len() >= limit as usize {
                        return Ok(out);
                    }
                }
            }
        }
    }

    Ok(out)
}

fn parse_filters(args: &QueryEventsArgs) -> Result<Vec<Filter>, CoreError> {
    if args.filters.is_empty() {
        return Err(CoreError::invalid_input("filters must not be empty"));
    }
    nip01::validate_limit(args.limit)?;

    let mut filters = Vec::with_capacity(args.filters.len());
    for value in &args.filters {
        let mut filter: Filter = serde_json::from_value(value.clone())
            .map_err(|e| CoreError::invalid_input(format!("invalid filter json: {e}")))?;
        if let Some(limit) = args.limit {
            filter.limit = Some(limit as usize);
        }
        validate_filter_bounds(&filter)?;
        filters.push(filter);
    }

    Ok(filters)
}

fn validate_filter_bounds(filter: &Filter) -> Result<(), CoreError> {
    let since = filter.since.map(|t| t.as_secs());
    let until = filter.until.map(|t| t.as_secs());
    nip01::validate_time_bounds(since, until)?;
    let limit = filter.limit.map(|v| v as u64);
    nip01::validate_limit(limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_filters, subscription_targets_mentions_me, subscription_targets_my_metadata,
        subscription_targets_my_notes, QueryEventsArgs,
    };
    use nostr_sdk::prelude::*;
    use serde_json::json;

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

    #[test]
    fn parse_filters_rejects_empty() {
        let args = QueryEventsArgs {
            filters: vec![],
            timeout_secs: None,
            limit: None,
        };
        let err = parse_filters(&args).unwrap_err();
        assert!(err.to_string().contains("filters must not be empty"));
    }

    #[test]
    fn parse_filters_rejects_invalid_time_bounds() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1],
                "since": 20,
                "until": 10
            })],
            timeout_secs: None,
            limit: None,
        };
        let err = parse_filters(&args).unwrap_err();
        assert!(err.to_string().contains("since must be"));
    }

    #[test]
    fn parse_filters_applies_limit_override() {
        let args = QueryEventsArgs {
            filters: vec![json!({
                "kinds": [1],
                "limit": 1
            })],
            timeout_secs: None,
            limit: Some(5),
        };
        let filters = parse_filters(&args).unwrap();
        assert_eq!(filters[0].limit, Some(5));
    }
}
