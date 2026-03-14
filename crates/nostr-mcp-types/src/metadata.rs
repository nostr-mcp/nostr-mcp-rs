use nostr::Metadata;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::settings::ProfileMetadata;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetMetadataArgs {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub banner: Option<String>,
    pub nip05: Option<String>,
    pub lud06: Option<String>,
    pub lud16: Option<String>,
    pub website: Option<String>,
    pub publish: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchMetadataArgs {
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProfileGetArgs {
    pub pubkey: String,
    pub timeout_secs: Option<u64>,
}

impl ProfileGetArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MetadataResult {
    pub saved: bool,
    pub published: bool,
    pub event_id: Option<String>,
    pub pubkey: Option<String>,
    pub success_relays: Vec<String>,
    pub failed_relays: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StoredMetadataResult {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProfileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FetchedMetadataResult {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub metadata: Option<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileGetResult {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub metadata: Option<Metadata>,
}
