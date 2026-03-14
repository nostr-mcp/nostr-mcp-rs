use schemars::JsonSchema;
use serde::Deserialize;

use crate::settings::FollowEntry;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetFollowsArgs {
    pub follows: Vec<FollowEntry>,
    pub publish: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddFollowArgs {
    pub pubkey: String,
    pub relay_url: Option<String>,
    pub petname: Option<String>,
    pub publish: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveFollowArgs {
    pub pubkey: String,
    pub publish: Option<bool>,
}
