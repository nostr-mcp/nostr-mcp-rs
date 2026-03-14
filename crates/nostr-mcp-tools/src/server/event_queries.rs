use super::{NostrMcpServer, core_error};
use nostr_mcp_core::event_filters::EventFilterService;
use nostr_mcp_core::events::{list_events, list_long_form_events, query_events, search_events};
use nostr_mcp_core::nip30::parse_nip30_emojis;
use nostr_mcp_core::polls::get_poll_results;
use nostr_mcp_core::reference_parser::ReferenceParser;
use nostr_mcp_server::host_runtime::client::ActiveClient;
use nostr_mcp_types::events::{
    EventItem, EventItemsResult, EventsListArgs, LongFormListArgs, QueryEventsArgs,
    SearchEventsArgs,
};
use nostr_mcp_types::nip30::Nip30ParseArgs;
use nostr_mcp_types::polls::GetPollResultsArgs;
use nostr_mcp_types::references::ParseReferencesArgs;
use nostr_sdk::prelude::*;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

fn event_item(event: Event) -> EventItem {
    EventItem {
        id: event.id.to_string(),
        kind: event.kind.as_u16(),
        pubkey: event.pubkey.to_string(),
        created_at: event.created_at.as_secs(),
        content: event.content,
        tags: event.tags.iter().cloned().map(|tag| tag.to_vec()).collect(),
    }
}

fn event_items_result(events: Vec<Event>) -> Result<CallToolResult, ErrorData> {
    let items: Vec<EventItem> = events.into_iter().map(event_item).collect();
    let count = items.len();
    let content = Content::json(serde_json::json!(EventItemsResult { items, count }))?;
    Ok(CallToolResult::success(vec![content]))
}

#[tool_router(router = event_query_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    async fn event_query_client(&self) -> Result<ActiveClient, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        self.ensure_client_from(keystore, settings_store).await
    }

    #[tool(description = "Parse NIP-30 emoji tags and shortcode mentions in content.")]
    pub async fn nostr_events_parse_emojis(
        &self,
        Parameters(args): Parameters<Nip30ParseArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = parse_nip30_emojis(args);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Fetch events using presets or custom filters. Presets: my_notes, mentions_me, my_metadata, by_author, by_kind. For by_kind: specify 'kind' parameter. Optional: limit, timeout_secs, since (unix timestamp), until (unix timestamp), author_npub (for by_author)"
    )]
    pub async fn nostr_events_list(
        &self,
        Parameters(args): Parameters<EventsListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.event_query_client().await?;
        let filter = EventFilterService::preset_filter(active_client.active_pubkey, &args)
            .map_err(core_error)?;

        let events = list_events(&active_client.client, filter, args.timeout())
            .await
            .map_err(core_error)?;
        event_items_result(events)
    }

    #[tool(
        description = "List kind 30023 long-form notes (NIP-23). Requires at least one of author_npub, identifier, hashtags. Optional: limit, since (unix timestamp), until (unix timestamp), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_list_long_form(
        &self,
        Parameters(args): Parameters<LongFormListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.event_query_client().await?;
        let events = list_long_form_events(&active_client.client, args)
            .await
            .map_err(core_error)?;
        event_items_result(events)
    }

    #[tool(
        description = "Parse nostr: references in text content (NIP-27). Returns decoded references with types and metadata."
    )]
    pub async fn nostr_events_parse_refs(
        &self,
        Parameters(args): Parameters<ParseReferencesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = ReferenceParser::parse(args);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Query events using one or more NIP-01 filters. Provide filters as an array of filter objects. Optional: limit (applies to all filters), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_query(
        &self,
        Parameters(args): Parameters<QueryEventsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.event_query_client().await?;
        let events = query_events(&active_client.client, args)
            .await
            .map_err(core_error)?;
        event_items_result(events)
    }

    #[tool(
        description = "Search events using NIP-50 search query. Requires query. Optional: kinds (array), author_npub, limit, since (unix timestamp), until (unix timestamp), timeout_secs (default: 10)."
    )]
    pub async fn nostr_events_search(
        &self,
        Parameters(args): Parameters<SearchEventsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.event_query_client().await?;
        let events = search_events(&active_client.client, args)
            .await
            .map_err(core_error)?;
        event_items_result(events)
    }

    #[tool(
        description = "Get results for a kind=1068 poll (NIP-88). Fetches the poll and all kind=1018 responses, counts votes (one per pubkey, most recent wins), and returns results with vote counts per option. Respects poll end time if set. Returns poll details, vote counts, and whether poll has ended. Optional: timeout_secs (default: 10)"
    )]
    pub async fn nostr_events_get_poll_results(
        &self,
        Parameters(args): Parameters<GetPollResultsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let active_client = self.event_query_client().await?;
        let results = get_poll_results(
            &active_client.client,
            &args.poll_event_id,
            args.timeout_secs.unwrap_or(10),
        )
        .await
        .map_err(core_error)?;
        let content = Content::json(serde_json::json!(results))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
