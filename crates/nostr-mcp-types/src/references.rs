use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParseReferencesArgs {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ParseReferencesResult {
    pub references: Vec<TextReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    Npub,
    Nprofile,
    Note,
    Nevent,
    Naddr,
    Nsec,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct TextReference {
    pub raw: String,
    pub bech32: String,
    pub reference_type: ReferenceType,
    pub pubkey: Option<String>,
    pub event_id: Option<String>,
    pub kind: Option<u16>,
    pub identifier: Option<String>,
    pub relays: Option<Vec<String>>,
    pub error: Option<String>,
}
