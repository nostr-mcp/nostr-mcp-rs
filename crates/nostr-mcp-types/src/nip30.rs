use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip30ParseArgs {
    pub content: String,
    pub tags: Option<Vec<Vec<String>>>,
    pub kind: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip30ParseResult {
    pub tags: Vec<Nip30EmojiTag>,
    pub mentions: Vec<Nip30EmojiMention>,
    pub kind: Option<u16>,
    pub kind_supported: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip30EmojiTag {
    pub shortcode: String,
    pub url: Option<String>,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip30EmojiMention {
    pub raw: String,
    pub shortcode: String,
    pub url: Option<String>,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
