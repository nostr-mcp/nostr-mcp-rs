use crate::error::CoreError;
use crate::event_filters::EventFilterService;
use nostr_mcp_types::events::{LongFormListArgs, QueryEventsArgs, SearchEventsArgs};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

type EventFetchFuture =
    Pin<Box<dyn Future<Output = Result<Vec<Event>, CoreError>> + Send + 'static>>;

async fn fetch_events_with(
    filter: Filter,
    timeout: Duration,
    fetch: &mut (dyn FnMut(Filter, Duration) -> EventFetchFuture + Send),
) -> Result<Vec<Event>, CoreError> {
    fetch(filter, timeout).await
}

fn collect_fetched_events<T>(events: T) -> Vec<Event>
where
    T: IntoIterator<Item = Event>,
{
    events.into_iter().collect()
}

async fn fetch_events(
    client: &Client,
    filter: Filter,
    timeout: Duration,
) -> Result<Vec<Event>, CoreError> {
    let client = client.clone();
    let mut fetch = move |filter, timeout| -> EventFetchFuture {
        let client = client.clone();
        Box::pin(async move {
            client
                .fetch_events(filter, timeout)
                .await
                .map(collect_fetched_events)
                .map_err(|e| CoreError::operation(format!("fetch events: {e}")))
        })
    };
    fetch_events_with(filter, timeout, &mut fetch).await
}

fn extend_unique_events(
    out: &mut Vec<Event>,
    seen: &mut HashSet<EventId>,
    events: Vec<Event>,
    limit: Option<usize>,
) -> bool {
    for event in events {
        if seen.insert(event.id) {
            out.push(event);
            if let Some(limit) = limit
                && out.len() >= limit
            {
                return true;
            }
        }
    }

    false
}

async fn query_events_with(
    args: QueryEventsArgs,
    fetch: &mut (dyn FnMut(Filter, Duration) -> EventFetchFuture + Send),
) -> Result<Vec<Event>, CoreError> {
    let filters = EventFilterService::query_filters(&args)?;
    let timeout = Duration::from_secs(args.timeout());
    let limit = args.limit.map(|value| value as usize);
    let mut out = Vec::new();
    let mut seen: HashSet<EventId> = HashSet::new();

    for filter in filters {
        let events = fetch(filter, timeout).await?;
        if extend_unique_events(&mut out, &mut seen, events, limit) {
            return Ok(out);
        }
    }

    Ok(out)
}

async fn search_events_with(
    args: SearchEventsArgs,
    list: &mut (dyn FnMut(Filter, u64) -> EventFetchFuture + Send),
) -> Result<Vec<Event>, CoreError> {
    let filter = EventFilterService::search_filter(&args)?;
    list(filter, args.timeout()).await
}

async fn list_long_form_events_with(
    args: LongFormListArgs,
    list: &mut (dyn FnMut(Filter, u64) -> EventFetchFuture + Send),
) -> Result<Vec<Event>, CoreError> {
    let filter = EventFilterService::long_form_filter(&args)?;
    list(filter, args.timeout()).await
}

pub async fn list_events(
    client: &Client,
    filter: Filter,
    timeout_secs: u64,
) -> Result<Vec<Event>, CoreError> {
    fetch_events(client, filter, Duration::from_secs(timeout_secs)).await
}

pub async fn query_events(client: &Client, args: QueryEventsArgs) -> Result<Vec<Event>, CoreError> {
    let client = client.clone();
    let mut fetch = move |filter, timeout| -> EventFetchFuture {
        let client = client.clone();
        Box::pin(async move { fetch_events(&client, filter, timeout).await })
    };
    query_events_with(args, &mut fetch).await
}

pub async fn search_events(
    client: &Client,
    args: SearchEventsArgs,
) -> Result<Vec<Event>, CoreError> {
    let client = client.clone();
    let mut list = move |filter, timeout| -> EventFetchFuture {
        let client = client.clone();
        Box::pin(async move { list_events(&client, filter, timeout).await })
    };
    search_events_with(args, &mut list).await
}

pub async fn list_long_form_events(
    client: &Client,
    args: LongFormListArgs,
) -> Result<Vec<Event>, CoreError> {
    let client = client.clone();
    let mut list = move |filter, timeout| -> EventFetchFuture {
        let client = client.clone();
        Box::pin(async move { list_events(&client, filter, timeout).await })
    };
    list_long_form_events_with(args, &mut list).await
}

#[cfg(test)]
mod tests {
    use super::{
        EventFetchFuture, collect_fetched_events, extend_unique_events, fetch_events_with,
        list_events, list_long_form_events, list_long_form_events_with, query_events,
        query_events_with, search_events, search_events_with,
    };
    use crate::error::CoreError;
    use nostr_mcp_types::events::{LongFormListArgs, QueryEventsArgs, SearchEventsArgs};
    use nostr_sdk::prelude::*;
    use serde_json::json;
    use std::collections::HashSet;
    use std::future::ready;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn test_event(content: &str) -> Event {
        let keys = Keys::generate();
        EventBuilder::text_note(content)
            .sign_with_keys(&keys)
            .unwrap()
    }

    #[test]
    fn extend_unique_events_respects_limit() {
        let first = test_event("first");
        let second = test_event("second");
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        let limited = extend_unique_events(
            &mut out,
            &mut seen,
            vec![first.clone(), first.clone(), second.clone()],
            Some(2),
        );

        assert!(limited);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, first.id);
        assert_eq!(out[1].id, second.id);
    }

    #[tokio::test]
    async fn list_events_reports_fetch_errors() {
        let client = Client::new(Keys::generate());
        let err = list_events(&client, Filter::new().kind(Kind::TextNote), 1)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("fetch events"));
    }

    #[tokio::test]
    async fn fetch_events_with_collects_events() {
        let first = test_event("first");
        let second = test_event("second");
        let expected_first = first.id;
        let expected_second = second.id;

        let mut fetch = move |_filter, timeout: Duration| -> EventFetchFuture {
            assert_eq!(timeout, Duration::from_secs(4));
            Box::pin(ready(Ok(vec![first.clone(), second.clone()])))
        };

        let events = fetch_events_with(Filter::new(), Duration::from_secs(4), &mut fetch)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, expected_first);
        assert_eq!(events[1].id, expected_second);
    }

    #[test]
    fn collect_fetched_events_accepts_event_collections() {
        let first = test_event("first");
        let second = test_event("second");
        let mut expected = vec![first.id, second.id];
        expected.sort();
        let events = vec![first, second].into_iter().collect::<Events>();
        let mut collected = collect_fetched_events(events)
            .into_iter()
            .map(|event| event.id)
            .collect::<Vec<_>>();
        collected.sort();

        assert_eq!(collected, expected);
    }

    #[tokio::test]
    async fn query_events_rejects_empty_filters() {
        let client = Client::new(Keys::generate());
        let err = query_events(
            &client,
            QueryEventsArgs {
                filters: vec![],
                timeout_secs: None,
                limit: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("filters must not be empty"));
    }

    #[tokio::test]
    async fn query_events_reports_fetch_errors() {
        let client = Client::new(Keys::generate());
        let err = query_events(
            &client,
            QueryEventsArgs {
                filters: vec![json!({ "kinds": [1] })],
                timeout_secs: Some(1),
                limit: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("fetch events"));
    }

    #[tokio::test]
    async fn query_events_with_deduplicates_across_filters() {
        let first = test_event("first");
        let second = test_event("second");
        let third = test_event("third");
        let responses = Arc::new(Mutex::new(vec![
            vec![first.clone(), second.clone()],
            vec![second.clone(), third.clone()],
        ]));
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        let args = QueryEventsArgs {
            filters: vec![json!({ "kinds": [1] }), json!({ "kinds": [1] })],
            timeout_secs: Some(7),
            limit: None,
        };

        let mut fetch = {
            let responses = Arc::clone(&responses);
            let timeouts = Arc::clone(&timeouts);
            move |_filter, timeout: Duration| {
                let responses = Arc::clone(&responses);
                let timeouts = Arc::clone(&timeouts);
                Box::pin(async move {
                    timeouts.lock().unwrap().push(timeout.as_secs());
                    Ok(responses.lock().unwrap().remove(0))
                }) as EventFetchFuture
            }
        };

        let events = query_events_with(args, &mut fetch).await.unwrap();

        let ids = events.into_iter().map(|event| event.id).collect::<Vec<_>>();
        assert_eq!(ids, vec![first.id, second.id, third.id]);
        assert_eq!(&*timeouts.lock().unwrap(), &[7, 7]);
    }

    #[tokio::test]
    async fn query_events_with_stops_once_limit_is_met() {
        let first = test_event("first");
        let second = test_event("second");
        let responses = Arc::new(Mutex::new(vec![vec![first.clone(), second.clone()]]));
        let call_count = Arc::new(Mutex::new(0usize));
        let args = QueryEventsArgs {
            filters: vec![json!({ "kinds": [1] }), json!({ "kinds": [1] })],
            timeout_secs: Some(5),
            limit: Some(2),
        };

        let mut fetch = {
            let responses = Arc::clone(&responses);
            let call_count = Arc::clone(&call_count);
            move |_filter, _timeout: Duration| {
                let responses = Arc::clone(&responses);
                let call_count = Arc::clone(&call_count);
                Box::pin(async move {
                    *call_count.lock().unwrap() += 1;
                    Ok(responses.lock().unwrap().remove(0))
                }) as EventFetchFuture
            }
        };

        let events = query_events_with(args, &mut fetch).await.unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn query_events_with_propagates_fetch_errors() {
        let args = QueryEventsArgs {
            filters: vec![json!({ "kinds": [1] })],
            timeout_secs: Some(3),
            limit: None,
        };

        let mut fetch = |_filter, _timeout: Duration| -> EventFetchFuture {
            Box::pin(async { Err(CoreError::operation("boom")) })
        };

        let err = query_events_with(args, &mut fetch).await.unwrap_err();

        assert_eq!(err.to_string(), "operation error: boom");
    }

    #[tokio::test]
    async fn search_events_rejects_empty_query() {
        let client = Client::new(Keys::generate());
        let err = search_events(
            &client,
            SearchEventsArgs {
                query: "   ".to_string(),
                kinds: None,
                author_npub: None,
                limit: None,
                since: None,
                until: None,
                timeout_secs: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("query must not be empty"));
    }

    #[tokio::test]
    async fn search_events_reports_fetch_errors() {
        let client = Client::new(Keys::generate());
        let err = search_events(
            &client,
            SearchEventsArgs {
                query: "nostr".to_string(),
                kinds: Some(vec![1]),
                author_npub: None,
                limit: Some(2),
                since: None,
                until: None,
                timeout_secs: Some(1),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("fetch events"));
    }

    #[tokio::test]
    async fn search_events_with_passes_filter_and_timeout() {
        let keys = Keys::generate();
        let observed = Arc::new(Mutex::new(None));
        let args = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: Some(vec![1]),
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            limit: Some(4),
            since: Some(10),
            until: Some(20),
            timeout_secs: Some(9),
        };

        let mut list = {
            let observed = Arc::clone(&observed);
            move |filter, timeout| -> EventFetchFuture {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    *observed.lock().unwrap() = Some((filter, timeout));
                    Ok(Vec::new())
                })
            }
        };

        let events = search_events_with(args, &mut list).await.unwrap();

        assert!(events.is_empty());
        let (filter, timeout) = observed.lock().unwrap().take().unwrap();
        assert_eq!(timeout, 9);
        assert_eq!(filter.limit, Some(4));
        assert_eq!(filter.since, Some(Timestamp::from(10)));
        assert_eq!(filter.until, Some(Timestamp::from(20)));
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::TextNote));
        assert!(
            filter
                .authors
                .as_ref()
                .unwrap()
                .contains(&keys.public_key())
        );
    }

    #[tokio::test]
    async fn list_long_form_events_requires_constraints() {
        let client = Client::new(Keys::generate());
        let err = list_long_form_events(
            &client,
            LongFormListArgs {
                author_npub: None,
                identifier: None,
                hashtags: None,
                limit: None,
                since: None,
                until: None,
                timeout_secs: None,
            },
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("at least one of author_npub, identifier, or hashtags is required")
        );
    }

    #[tokio::test]
    async fn list_long_form_events_reports_fetch_errors() {
        let client = Client::new(Keys::generate());
        let err = list_long_form_events(
            &client,
            LongFormListArgs {
                author_npub: Some(Keys::generate().public_key().to_bech32().unwrap()),
                identifier: None,
                hashtags: None,
                limit: Some(2),
                since: None,
                until: None,
                timeout_secs: Some(1),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("fetch events"));
    }

    #[tokio::test]
    async fn list_long_form_events_with_passes_filter_and_timeout() {
        let keys = Keys::generate();
        let observed = Arc::new(Mutex::new(None));
        let args = LongFormListArgs {
            author_npub: Some(keys.public_key().to_bech32().unwrap()),
            identifier: Some("essay-1".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: Some(6),
            since: Some(11),
            until: Some(22),
            timeout_secs: Some(8),
        };

        let mut list = {
            let observed = Arc::clone(&observed);
            move |filter, timeout| -> EventFetchFuture {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    *observed.lock().unwrap() = Some((filter, timeout));
                    Ok(Vec::new())
                })
            }
        };

        let events = list_long_form_events_with(args, &mut list).await.unwrap();

        assert!(events.is_empty());
        let (filter, timeout) = observed.lock().unwrap().take().unwrap();
        assert_eq!(timeout, 8);
        assert_eq!(filter.limit, Some(6));
        assert_eq!(filter.since, Some(Timestamp::from(11)));
        assert_eq!(filter.until, Some(Timestamp::from(22)));
        assert!(filter.kinds.as_ref().unwrap().contains(&Kind::from(30023)));
        assert!(
            filter
                .authors
                .as_ref()
                .unwrap()
                .contains(&keys.public_key())
        );
        let hashtag_tag = SingleLetterTag::lowercase(Alphabet::T);
        let identifier_tag = SingleLetterTag::lowercase(Alphabet::D);
        assert!(
            filter
                .generic_tags
                .get(&hashtag_tag)
                .unwrap()
                .contains("nostr")
        );
        assert!(
            filter
                .generic_tags
                .get(&identifier_tag)
                .unwrap()
                .contains("essay-1")
        );
    }
}
