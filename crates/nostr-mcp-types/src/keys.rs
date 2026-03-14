use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyArgs {
    pub key: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DerivePublicArgs {
    pub private_key: String,
}
