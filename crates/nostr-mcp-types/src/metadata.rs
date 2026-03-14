use schemars::JsonSchema;
use serde::Deserialize;

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
