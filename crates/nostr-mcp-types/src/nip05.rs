use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip05ResolveArgs {
    pub identifier: String,
    pub timeout_secs: Option<u64>,
}

impl Nip05ResolveArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip05VerifyArgs {
    pub identifier: String,
    pub pubkey: String,
    pub timeout_secs: Option<u64>,
}

impl Nip05VerifyArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip05ResolveResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub pubkey_npub: String,
    pub relays: Vec<String>,
    pub nip46_relays: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip05VerifyResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub valid: bool,
}
