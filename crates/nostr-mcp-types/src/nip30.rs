use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip30ParseArgs {
    pub content: String,
    pub tags: Option<Vec<Vec<String>>>,
    pub kind: Option<u16>,
}
