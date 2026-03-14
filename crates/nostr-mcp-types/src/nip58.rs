use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeDefinitionArgs {
    pub identifier: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<Nip58BadgeImage>,
    pub thumbs: Option<Vec<Nip58BadgeImage>>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeImage {
    pub url: String,
    pub dimensions: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeAwardArgs {
    pub badge: String,
    pub badge_relay: Option<String>,
    pub recipients: Vec<Nip58BadgeRecipient>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeRecipient {
    pub pubkey: String,
    pub relay: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58ProfileBadgesArgs {
    pub badges: Vec<Nip58BadgeDisplay>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip58BadgeDisplay {
    pub badge: String,
    pub badge_relay: Option<String>,
    pub award_event_id: String,
    pub award_relay: Option<String>,
}
