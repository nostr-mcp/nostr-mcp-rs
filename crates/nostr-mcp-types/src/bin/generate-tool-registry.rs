use nostr_mcp_types::registry::write_generated_registry_artifact;

fn main() {
    let path = write_generated_registry_artifact().expect("write generated tool registry");
    println!("{}", path.display());
}
