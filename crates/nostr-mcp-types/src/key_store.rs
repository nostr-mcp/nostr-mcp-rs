use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateArgs {
    pub label: String,
    pub make_active: Option<bool>,
    pub persist_secret: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImportArgs {
    pub label: String,
    pub key_material: String,
    pub make_active: Option<bool>,
    pub persist_secret: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveArgs {
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetActiveArgs {
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameLabelArgs {
    pub from: Option<String>,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Bech32,
    Hex,
    Both,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportArgs {
    pub label: Option<String>,
    #[serde(default = "default_export_format")]
    pub format: ExportFormat,
    #[serde(default)]
    pub include_private: bool,
}

fn default_export_format() -> ExportFormat {
    ExportFormat::Bech32
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct KeyEntry {
    pub label: String,
    pub public_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct KeyRemovalResult {
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct KeysListResult {
    pub keys: Vec<KeyEntry>,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ExportResult {
    pub label: String,
    pub public_key_npub: String,
    pub public_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_nsec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}
