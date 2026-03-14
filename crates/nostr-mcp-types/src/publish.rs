use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostTextArgs {
    pub content: String,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateTextArgs {
    pub content: String,
    pub tags: Option<Vec<Vec<String>>>,
    pub created_at: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostThreadArgs {
    pub content: String,
    pub subject: String,
    pub hashtags: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostLongFormArgs {
    pub content: String,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub image: Option<String>,
    pub published_at: Option<u64>,
    pub identifier: Option<String>,
    pub hashtags: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostGroupChatArgs {
    pub content: String,
    pub group_id: String,
    pub reply_to_id: Option<String>,
    pub reply_to_relay: Option<String>,
    pub reply_to_pubkey: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostReactionArgs {
    pub event_id: String,
    pub event_pubkey: String,
    pub content: Option<String>,
    pub event_kind: Option<u16>,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostRepostArgs {
    pub event_json: String,
    pub relay_hint: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteEventsArgs {
    pub event_ids: Option<Vec<String>>,
    pub coordinates: Option<Vec<String>>,
    pub reason: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostAnonymousArgs {
    pub content: String,
    pub tags: Option<Vec<Vec<String>>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublishSignedEventArgs {
    pub event_json: String,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignEventArgs {
    pub unsigned_event_json: String,
}
