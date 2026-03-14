use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type JsonSchemaMap = Map<String, Value>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Stable,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolContract {
    pub name: String,
    pub status: ToolStatus,
    pub summary: String,
    #[serde(default)]
    pub nip: Vec<String>,
    #[serde(default)]
    pub input_schema: JsonSchemaMap,
    #[serde(default)]
    pub output_schema: JsonSchemaMap,
}

impl ToolContract {
    pub fn has_input_schema(&self) -> bool {
        !self.input_schema.is_empty()
    }

    pub fn has_output_schema(&self) -> bool {
        !self.output_schema.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolRegistry {
    pub spec_version: String,
    pub registry_version: String,
    pub tools: Vec<ToolContract>,
}

impl ToolRegistry {
    pub fn stable_tools(&self) -> impl Iterator<Item = &ToolContract> {
        self.tools
            .iter()
            .filter(|tool| matches!(tool.status, ToolStatus::Stable))
    }

    pub fn planned_tools(&self) -> impl Iterator<Item = &ToolContract> {
        self.tools
            .iter()
            .filter(|tool| matches!(tool.status, ToolStatus::Planned))
    }
}

#[cfg(test)]
mod tests {
    use super::ToolRegistry;

    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    fn registry_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/registry/tools.json")
    }

    #[test]
    fn registry_fixture_parses_into_canonical_types() {
        let raw = fs::read_to_string(registry_fixture_path()).expect("read registry fixture");
        let registry: ToolRegistry = serde_json::from_str(&raw).expect("parse registry fixture");
        let unique_names: BTreeSet<_> = registry
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();

        assert!(!registry.spec_version.trim().is_empty());
        assert!(!registry.registry_version.trim().is_empty());
        assert!(!registry.tools.is_empty());
        assert_eq!(unique_names.len(), registry.tools.len());
        assert!(registry.stable_tools().next().is_some());
        assert!(registry
            .tools
            .iter()
            .all(|tool| !tool.summary.trim().is_empty()));
    }

    #[test]
    fn registry_fixture_round_trips_through_canonical_types() {
        let raw = fs::read_to_string(registry_fixture_path()).expect("read registry fixture");
        let registry: ToolRegistry = serde_json::from_str(&raw).expect("parse registry fixture");
        let encoded = serde_json::to_string_pretty(&registry).expect("encode registry fixture");
        let decoded: ToolRegistry =
            serde_json::from_str(&encoded).expect("decode encoded registry");

        assert_eq!(decoded, registry);
    }
}
