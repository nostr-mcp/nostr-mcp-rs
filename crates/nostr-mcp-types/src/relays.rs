use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysSetArgs {
    pub urls: Vec<String>,
    pub read_write: Option<String>,
    pub autoconnect: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysConnectArgs {
    pub urls: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysDisconnectArgs {
    pub urls: Option<Vec<String>>,
    pub force_remove: Option<bool>,
}
