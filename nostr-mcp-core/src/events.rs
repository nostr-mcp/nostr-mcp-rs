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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LongFormListArgs {
    pub author_npub: Option<String>,
    pub identifier: Option<String>,
    pub hashtags: Option<Vec<String>>,
    pub limit: Option<u64>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub timeout_secs: Option<u64>,
}

impl LongFormListArgs {
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

pub async fn list_long_form_events(
    client: &Client,
    args: LongFormListArgs,
) -> Result<Vec<Event>, CoreError> {
    let filter = long_form_filter(&args)?;
    list_events(client, filter, args.timeout()).await
}

pub fn long_form_filter(args: &LongFormListArgs) -> Result<Filter, CoreError> {
    nip01::validate_time_bounds(args.since, args.until)?;
    nip01::validate_limit(args.limit)?;

    let mut filter = Filter::new().kind(Kind::from(30023));
    let mut has_constraint = false;

    if let Some(author_npub) = &args.author_npub {
        let pk = PublicKey::from_bech32(author_npub)
            .map_err(|e| CoreError::invalid_input(format!("invalid author npub: {e}")))?;
        filter = filter.author(pk);
        has_constraint = true;
    }

    if let Some(identifier) = &args.identifier {
        let value = ensure_non_empty("identifier", identifier)?;
        filter = filter.identifier(value);
        has_constraint = true;
    }

    if let Some(hashtags) = &args.hashtags {
        if hashtags.is_empty() {
            return Err(CoreError::invalid_input("hashtags must not be empty"));
        }

        let mut cleaned = Vec::with_capacity(hashtags.len());
        for hashtag in hashtags {
            cleaned.push(ensure_non_empty("hashtag", hashtag)?);
        }
        filter = filter.hashtags(cleaned);
        has_constraint = true;
    }

    if let Some(since) = args.since {
        filter = filter.since(Timestamp::from(since));
    }

    if let Some(until) = args.until {
        filter = filter.until(Timestamp::from(until));
    }

    if let Some(limit) = args.limit {
        filter = filter.limit(limit as usize);
    }

    if !has_constraint {
        return Err(CoreError::invalid_input(
            "at least one of author_npub, identifier, or hashtags is required",
        ));
    }

    Ok(filter)
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

fn ensure_non_empty(label: &str, value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
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
        long_form_filter, parse_filters, subscription_targets_mentions_me,
        subscription_targets_my_metadata, subscription_targets_my_notes, LongFormListArgs,
        QueryEventsArgs,
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

    #[test]
    fn long_form_filter_requires_constraint() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: None,
            hashtags: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = long_form_filter(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("at least one of author_npub, identifier, or hashtags is required"));
    }

    #[test]
    fn long_form_filter_includes_author_kind_and_tags() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();

        let args = LongFormListArgs {
            author_npub: Some(npub),
            identifier: Some("post-1".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: Some(5),
            since: Some(10),
            until: Some(20),
            timeout_secs: None,
        };

        let filter = long_form_filter(&args).unwrap();

        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert_eq!(filter.limit, Some(5));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
        assert!(filter.authors.as_ref().unwrap().contains(&keys.public_key()));

        let hashtag_tag = SingleLetterTag::lowercase(Alphabet::T);
        let identifier_tag = SingleLetterTag::lowercase(Alphabet::D);
        assert!(filter
            .generic_tags
            .get(&hashtag_tag)
            .unwrap()
            .contains("nostr"));
        assert!(filter
            .generic_tags
            .get(&identifier_tag)
            .unwrap()
            .contains("post-1"));
    }

    #[test]
    fn long_form_filter_rejects_empty_identifier() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("   ".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = long_form_filter(&args).unwrap_err();
        assert!(err.to_string().contains("identifier must not be empty"));
    }

    #[test]
    fn long_form_filter_rejects_empty_hashtag() {
        let args = LongFormListArgs {
            author_npub: None,
            identifier: Some("post-1".to_string()),
            hashtags: Some(vec![" ".to_string()]),
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        let err = long_form_filter(&args).unwrap_err();
        assert!(err.to_string().contains("hashtag must not be empty"));
    }
}
