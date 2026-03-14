use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyArgs {
    pub key: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DerivePublicArgs {
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Npub,
    Nsec,
    Hex,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct VerifyResult {
    pub input: String,
    pub key_type: KeyType,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct DerivePublicResult {
    pub public_key_npub: String,
    pub public_key_hex: String,
}
