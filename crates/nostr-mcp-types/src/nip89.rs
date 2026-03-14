use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89RecommendArgs {
    pub supported_kind: u16,
    pub handlers: Vec<Nip89HandlerRecommendation>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerRecommendation {
    pub address: String,
    pub relay: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerInfoArgs {
    pub identifier: String,
    pub kinds: Vec<u16>,
    pub links: Vec<Nip89HandlerLink>,
    pub content: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip89HandlerLink {
    pub platform: String,
    pub url: String,
    pub entity: Option<String>,
}
