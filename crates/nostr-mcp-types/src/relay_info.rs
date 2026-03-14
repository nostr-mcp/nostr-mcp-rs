use schemars::JsonSchema;
use serde::Deserialize;

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
