use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip19DecodeArgs {
    pub input: String,
    pub allow_secret: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip19DecodeResult {
    pub input: String,
    pub input_type: Nip19EntityType,
    pub data: Nip19DecodedData,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Nip19EntityType {
    Npub,
    Nsec,
    Note,
    Nprofile,
    Nevent,
    Naddr,
    Hex,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Nip19EncodeTarget {
    Npub,
    Nsec,
    Note,
    Nprofile,
    Nevent,
    Naddr,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip19EncodeArgs {
    pub target: Nip19EncodeTarget,
    pub input: String,
    pub relays: Option<Vec<String>>,
    pub author: Option<String>,
    pub kind: Option<u16>,
    pub identifier: Option<String>,
    pub allow_secret: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip19EncodeResult {
    pub input: String,
    pub target: Nip19EncodeTarget,
    pub encoded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip19DecodedData {
    pub pubkey_hex: Option<String>,
    pub event_id_hex: Option<String>,
    pub relays: Option<Vec<String>>,
    pub author_hex: Option<String>,
    pub kind: Option<u16>,
    pub identifier: Option<String>,
    pub is_secret: bool,
}
