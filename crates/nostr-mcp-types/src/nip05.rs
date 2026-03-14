use schemars::JsonSchema;
use serde::Deserialize;

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
