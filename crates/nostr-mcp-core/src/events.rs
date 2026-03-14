use crate::error::CoreError;
use crate::event_filters::EventFilterService;
use nostr_mcp_types::events::{LongFormListArgs, QueryEventsArgs, SearchEventsArgs};
use nostr_sdk::prelude::*;
use std::collections::HashSet;

pub async fn list_events(
    client: &Client,
    filter: Filter,
    timeout_secs: u64,
) -> Result<Vec<Event>, CoreError> {
    let events = client
        .fetch_events(filter, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| CoreError::operation(format!("fetch events: {e}")))?;
    Ok(events.into_iter().collect())
}

pub async fn query_events(client: &Client, args: QueryEventsArgs) -> Result<Vec<Event>, CoreError> {
    let filters = EventFilterService::query_filters(&args)?;
    let timeout = std::time::Duration::from_secs(args.timeout());
    let mut out = Vec::new();
    let mut seen: HashSet<EventId> = HashSet::new();

    for filter in filters {
        let events = client
            .fetch_events(filter, timeout)
            .await
            .map_err(|e| CoreError::operation(format!("fetch events: {e}")))?;
        for event in events.into_iter() {
            if seen.insert(event.id) {
                out.push(event);
                if let Some(limit) = args.limit
                    && out.len() >= limit as usize
                {
                    return Ok(out);
                }
            }
        }
    }

    Ok(out)
}

pub async fn search_events(
    client: &Client,
    args: SearchEventsArgs,
) -> Result<Vec<Event>, CoreError> {
    let filter = EventFilterService::search_filter(&args)?;
    list_events(client, filter, args.timeout()).await
}

pub async fn list_long_form_events(
    client: &Client,
    args: LongFormListArgs,
) -> Result<Vec<Event>, CoreError> {
    let filter = EventFilterService::long_form_filter(&args)?;
    list_events(client, filter, args.timeout()).await
}
