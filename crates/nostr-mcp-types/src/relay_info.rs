use nostr::nips::nip11::RelayInformationDocument;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelayInfoArgs {
    pub relay_url: String,
    pub timeout_secs: Option<u64>,
}

impl RelayInfoArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RelayInfoResult {
    pub relay_url: String,
    pub http_url: String,
    pub status: u16,
    #[schemars(with = "serde_json::Value")]
    pub document: RelayInformationDocument,
}
