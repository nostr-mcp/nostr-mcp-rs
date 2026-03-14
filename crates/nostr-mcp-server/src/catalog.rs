use nostr_mcp_types::registry::{ToolRegistry, ToolStatus, generated_tool_registry};

pub const HOST_LOCAL_TOOL_NAMES: [&str; 2] = ["nostr_config_dir_get", "nostr_config_dir_set"];

pub fn is_host_local_tool(name: &str) -> bool {
    HOST_LOCAL_TOOL_NAMES.contains(&name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrMcpServerCatalog {
    tool_names: Vec<String>,
}

impl NostrMcpServerCatalog {
    pub fn from_registry(registry: &ToolRegistry) -> Self {
        let tool_names = registry
            .tools
            .iter()
            .filter(|tool| tool.status == ToolStatus::Stable && !is_host_local_tool(&tool.name))
            .map(|tool| tool.name.clone())
            .collect();
        Self { tool_names }
    }

    pub fn generated() -> Self {
        Self::from_registry(&generated_tool_registry())
    }

    pub fn tool_names(&self) -> &[String] {
        &self.tool_names
    }

    pub fn instructions(&self) -> String {
        format!("Tools: {}", self.tool_names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use nostr_mcp_types::registry::{JsonSchemaMap, ToolContract, ToolRegistry, ToolStatus};

    use super::{HOST_LOCAL_TOOL_NAMES, NostrMcpServerCatalog, is_host_local_tool};

    #[test]
    fn generated_catalog_uses_stable_non_host_local_registry_surface() {
        let catalog = NostrMcpServerCatalog::generated();
        let unique: BTreeSet<_> = catalog.tool_names().iter().cloned().collect();

        assert_eq!(catalog.tool_names().len(), 64);
        assert_eq!(unique.len(), catalog.tool_names().len());
        assert!(
            HOST_LOCAL_TOOL_NAMES
                .iter()
                .all(|name| !catalog.tool_names().iter().any(|tool| tool == name))
        );
        assert!(
            !catalog
                .tool_names()
                .iter()
                .any(|tool| tool == "nostr_nip19_convert")
        );
    }

    #[test]
    fn catalog_from_registry_preserves_registry_order_after_filtering() {
        let registry = ToolRegistry {
            spec_version: "0.1.12".to_string(),
            registry_version: "0.1.12".to_string(),
            tools: vec![
                ToolContract {
                    name: "nostr_config_dir_get".to_string(),
                    status: ToolStatus::Stable,
                    summary: "host local".to_string(),
                    nip: Vec::new(),
                    input_schema: JsonSchemaMap::new(),
                    output_schema: JsonSchemaMap::new(),
                },
                ToolContract {
                    name: "nostr_keys_generate".to_string(),
                    status: ToolStatus::Stable,
                    summary: "generate".to_string(),
                    nip: Vec::new(),
                    input_schema: JsonSchemaMap::new(),
                    output_schema: JsonSchemaMap::new(),
                },
                ToolContract {
                    name: "nostr_nip19_convert".to_string(),
                    status: ToolStatus::Planned,
                    summary: "planned".to_string(),
                    nip: Vec::new(),
                    input_schema: JsonSchemaMap::new(),
                    output_schema: JsonSchemaMap::new(),
                },
                ToolContract {
                    name: "nostr_follows_remove".to_string(),
                    status: ToolStatus::Stable,
                    summary: "remove follow".to_string(),
                    nip: Vec::new(),
                    input_schema: JsonSchemaMap::new(),
                    output_schema: JsonSchemaMap::new(),
                },
                ToolContract {
                    name: "nostr_events_repost".to_string(),
                    status: ToolStatus::Stable,
                    summary: "repost".to_string(),
                    nip: Vec::new(),
                    input_schema: JsonSchemaMap::new(),
                    output_schema: JsonSchemaMap::new(),
                },
            ],
        };
        let catalog = NostrMcpServerCatalog::from_registry(&registry);

        assert_eq!(
            catalog.instructions(),
            format!("Tools: {}", catalog.tool_names().join(", "))
        );
        assert_eq!(
            catalog.tool_names(),
            &[
                "nostr_keys_generate".to_string(),
                "nostr_follows_remove".to_string(),
                "nostr_events_repost".to_string(),
            ]
        );
    }

    #[test]
    fn host_local_tool_classification_is_explicit() {
        assert!(is_host_local_tool("nostr_config_dir_get"));
        assert!(is_host_local_tool("nostr_config_dir_set"));
        assert!(!is_host_local_tool("nostr_keys_list"));
    }
}
