use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PollOption {
    pub option_id: String,
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreatePollArgs {
    pub question: String,
    pub options: Vec<PollOption>,
    pub relay_urls: Vec<String>,
    pub poll_type: Option<String>,
    pub ends_at: Option<u64>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VotePollArgs {
    pub poll_event_id: String,
    pub option_ids: Vec<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPollResultsArgs {
    pub poll_event_id: String,
    pub timeout_secs: Option<u64>,
}
