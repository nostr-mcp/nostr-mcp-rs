use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FollowsResult {
    pub follows: Vec<FollowEntry>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PublishFollowsResult {
    pub saved: bool,
    pub published: bool,
    pub event_id: Option<String>,
    pub pubkey: Option<String>,
    pub success_relays: Vec<String>,
    pub failed_relays: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FollowsLookupResult {
    pub pubkey: String,
    pub follows: Vec<FollowEntry>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FollowsMutationResult {
    pub follows: Vec<FollowEntry>,
    pub count: usize,
    pub result: PublishFollowsResult,
}
