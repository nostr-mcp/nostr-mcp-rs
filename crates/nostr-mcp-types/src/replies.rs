use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostReplyArgs {
    pub content: String,
    pub reply_to_id: String,
    pub reply_to_pubkey: String,
    pub reply_to_kind: u16,
    pub root_event_id: Option<String>,
    pub root_event_pubkey: Option<String>,
    pub root_event_kind: Option<u16>,
    pub mentioned_pubkeys: Option<Vec<String>>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostCommentArgs {
    pub content: String,
    pub root_event_id: String,
    pub root_event_pubkey: String,
    pub root_event_kind: u16,
    pub parent_event_id: Option<String>,
    pub parent_event_pubkey: Option<String>,
    pub parent_event_kind: Option<u16>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}
