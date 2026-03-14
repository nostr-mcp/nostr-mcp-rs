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
