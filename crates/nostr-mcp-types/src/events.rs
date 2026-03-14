use schemars::JsonSchema;
use serde::Deserialize;
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
