use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
pub struct SearchEventsArgs {
    pub query: String,
    pub kinds: Option<Vec<u16>>,
    pub author_npub: Option<String>,
    pub limit: Option<u64>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub timeout_secs: Option<u64>,
}

impl SearchEventsArgs {
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EventItem {
    pub id: String,
    pub kind: u16,
    pub pubkey: String,
    pub created_at: u64,
    pub content: String,
    pub tags: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EventItemsResult {
    pub items: Vec<EventItem>,
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::{EventsListArgs, LongFormListArgs, QueryEventsArgs, SearchEventsArgs};

    #[test]
    fn timeout_helpers_default_to_ten_seconds() {
        let events = EventsListArgs {
            preset: "global".to_string(),
            limit: None,
            timeout_secs: None,
            author_npub: None,
            kind: None,
            since: None,
            until: None,
        };
        let query = QueryEventsArgs {
            filters: Vec::new(),
            timeout_secs: None,
            limit: None,
        };
        let search = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: None,
            author_npub: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };
        let long_form = LongFormListArgs {
            author_npub: None,
            identifier: None,
            hashtags: None,
            limit: None,
            since: None,
            until: None,
            timeout_secs: None,
        };

        assert_eq!(events.timeout(), 10);
        assert_eq!(query.timeout(), 10);
        assert_eq!(search.timeout(), 10);
        assert_eq!(long_form.timeout(), 10);
    }

    #[test]
    fn timeout_helpers_use_explicit_values() {
        let events = EventsListArgs {
            preset: "global".to_string(),
            limit: Some(20),
            timeout_secs: Some(11),
            author_npub: Some("npub1example".to_string()),
            kind: Some(1),
            since: Some(1),
            until: Some(2),
        };
        let query = QueryEventsArgs {
            filters: Vec::new(),
            timeout_secs: Some(12),
            limit: Some(30),
        };
        let search = SearchEventsArgs {
            query: "nostr".to_string(),
            kinds: Some(vec![1, 30023]),
            author_npub: Some("npub1example".to_string()),
            limit: Some(40),
            since: Some(3),
            until: Some(4),
            timeout_secs: Some(13),
        };
        let long_form = LongFormListArgs {
            author_npub: Some("npub1example".to_string()),
            identifier: Some("article".to_string()),
            hashtags: Some(vec!["nostr".to_string()]),
            limit: Some(50),
            since: Some(5),
            until: Some(6),
            timeout_secs: Some(14),
        };

        assert_eq!(events.timeout(), 11);
        assert_eq!(query.timeout(), 12);
        assert_eq!(search.timeout(), 13);
        assert_eq!(long_form.timeout(), 14);
    }
}
