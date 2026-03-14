use nostr_mcp_types::registry::write_generated_registry_artifact;

fn main() {
    let path = write_generated_registry_artifact().expect("write generated tool registry");
    println!("{}", path.display());
}

#[cfg(test)]
mod tests {
    use super::main;
    use nostr_mcp_types::registry::{
        generated_registry_artifact_path, generated_tool_registry, read_generated_registry_artifact,
    };

    #[test]
    fn main_writes_generated_registry_artifact() {
        main();

        assert!(generated_registry_artifact_path().exists());
        assert_eq!(
            read_generated_registry_artifact(),
            generated_tool_registry()
        );
    }
}
