use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutUserArgs {
    pub content: String,
    pub group_id: String,
    pub pubkey: String,
    pub roles: Option<Vec<String>>,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveUserArgs {
    pub content: String,
    pub group_id: String,
    pub pubkey: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EditGroupMetadataArgs {
    pub content: String,
    pub group_id: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub about: Option<String>,
    pub unrestricted: Option<bool>,
    pub visible: Option<bool>,
    pub public: Option<bool>,
    pub open: Option<bool>,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteEventArgs {
    pub content: String,
    pub group_id: String,
    pub event_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateGroupArgs {
    pub content: String,
    pub group_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteGroupArgs {
    pub content: String,
    pub group_id: String,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateInviteArgs {
    pub content: String,
    pub group_id: String,
    pub code: Option<String>,
    pub previous_refs: Option<Vec<String>>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JoinGroupArgs {
    pub content: String,
    pub group_id: String,
    pub invite_code: Option<String>,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LeaveGroupArgs {
    pub content: String,
    pub group_id: String,
    pub pow: Option<u8>,
    pub to_relays: Option<Vec<String>>,
}
