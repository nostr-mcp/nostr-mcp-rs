use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FollowEntry {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub petname: Option<String>,
}
