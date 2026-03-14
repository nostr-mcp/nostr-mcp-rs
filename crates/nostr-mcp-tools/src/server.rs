mod event_authoring;
mod event_queries;
mod follows;
mod groups;
mod keys;
mod metadata;
mod protocol_publishing;
mod protocol_utils;
mod relays;

use crate::runtime::{NostrMcpPaths, NostrMcpRuntime};
use crate::util;
use nostr_mcp_core::client::{ActiveClient, ClientStore};
use nostr_mcp_core::error::CoreError;
use nostr_mcp_core::key_store::KeyStore;
#[cfg(not(feature = "keyring"))]
use nostr_mcp_core::secrets::InMemorySecretStore;
#[cfg(feature = "keyring")]
use nostr_mcp_core::secrets::KeyringSecretStore;
use nostr_mcp_core::secrets::SecretStore;
use nostr_mcp_core::settings::SettingsStore;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::router::tool::ToolRouter,
    model::{ErrorData, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
    transport::stdio,
};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tokio::time::{Duration, sleep};
use tracing::info;

fn secret_store(runtime: &NostrMcpRuntime) -> Arc<dyn SecretStore> {
    #[cfg(feature = "keyring")]
    {
        Arc::new(KeyringSecretStore::new(&runtime.keyring_service))
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = runtime;
        Arc::new(InMemorySecretStore::new())
    }
}

async fn load_or_init_keystore(
    paths: &NostrMcpPaths,
    runtime: &NostrMcpRuntime,
) -> Result<KeyStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    KeyStore::load_or_init(paths.index_path.clone(), pass, secret_store(runtime)).await
}

async fn load_or_init_settings(paths: &NostrMcpPaths) -> Result<SettingsStore, CoreError> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    SettingsStore::load_or_init(paths.settings_path.clone(), pass).await
}

fn core_error(err: CoreError) -> ErrorData {
    match err {
        CoreError::InvalidInput(msg) => ErrorData::invalid_params(msg, None),
        _ => ErrorData::internal_error(err.to_string(), None),
    }
}

fn invalid_params<E: ToString>(err: E) -> ErrorData {
    ErrorData::invalid_params(err.to_string(), None)
}

struct ServerStores {
    keystore: Arc<KeyStore>,
    settings_store: Arc<SettingsStore>,
}

struct ServerContext {
    runtime: NostrMcpRuntime,
    stores: OnceCell<ServerStores>,
    client_store: ClientStore,
}

impl ServerContext {
    fn new(runtime: NostrMcpRuntime) -> Self {
        Self {
            runtime,
            stores: OnceCell::const_new(),
            client_store: ClientStore::new(),
        }
    }

    async fn stores(&self) -> Result<&ServerStores, CoreError> {
        let runtime = self.runtime.clone();
        self.stores
            .get_or_try_init(move || {
                let runtime = runtime.clone();
                async move {
                    let keystore = Arc::new(load_or_init_keystore(&runtime.paths, &runtime).await?);
                    let settings_store = Arc::new(load_or_init_settings(&runtime.paths).await?);
                    Ok(ServerStores {
                        keystore,
                        settings_store,
                    })
                }
            })
            .await
    }
}

#[derive(Clone)]
pub struct NostrMcpServer {
    tool_router: ToolRouter<Self>,
    context: Arc<ServerContext>,
}

impl NostrMcpServer {
    async fn initialize(&self) -> Result<(), CoreError> {
        self.context.stores().await?;
        Ok(())
    }

    async fn keystore(&self) -> Result<Arc<KeyStore>, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        Ok(stores.keystore.clone())
    }

    async fn settings_store(&self) -> Result<Arc<SettingsStore>, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        Ok(stores.settings_store.clone())
    }

    async fn ensure_client_from(
        &self,
        keystore: Arc<KeyStore>,
        settings_store: Arc<SettingsStore>,
    ) -> Result<ActiveClient, ErrorData> {
        self.context
            .client_store
            .ensure_client(keystore, settings_store)
            .await
            .map_err(core_error)
    }

    async fn reset_client(&self) -> Result<(), ErrorData> {
        self.context.client_store.reset().await.map_err(core_error)
    }

    #[cfg(test)]
    async fn client(&self) -> Result<ActiveClient, ErrorData> {
        let stores = self.context.stores().await.map_err(core_error)?;
        self.ensure_client_from(stores.keystore.clone(), stores.settings_store.clone())
            .await
    }
}

#[tool_router]
impl NostrMcpServer {
    pub fn new() -> Self {
        Self::with_runtime(NostrMcpRuntime::default())
    }

    pub fn with_runtime(runtime: NostrMcpRuntime) -> Self {
        Self {
            tool_router: Self::tool_router()
                + Self::event_authoring_tool_router()
                + Self::event_query_tool_router()
                + Self::follow_tool_router()
                + Self::group_tool_router()
                + Self::key_tool_router()
                + Self::relay_tool_router()
                + Self::protocol_publishing_tool_router()
                + Self::protocol_utility_tool_router()
                + Self::metadata_tool_router(),
            context: Arc::new(ServerContext::new(runtime)),
        }
    }
}

impl Default for NostrMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for NostrMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Tools: nostr_keys_generate, nostr_keys_import, nostr_keys_export, nostr_keys_verify, nostr_keys_derive_public, nostr_keys_remove, nostr_keys_list, nostr_keys_set_active, nostr_keys_get_active, nostr_keys_rename_label, nostr_relays_set, nostr_relays_connect, nostr_relays_disconnect, nostr_relays_status, nostr_relays_get_info, nostr_nip05_resolve, nostr_nip05_verify, nostr_nip44_encrypt, nostr_nip44_decrypt, nostr_handlers_recommend, nostr_handlers_register, nostr_badges_define, nostr_badges_award, nostr_badges_set_profile, nostr_events_parse_emojis, nostr_events_list, nostr_events_list_long_form, nostr_events_parse_refs, nostr_events_query, nostr_events_search, nostr_events_create_text, nostr_events_sign, nostr_events_post_text, nostr_events_post_thread, nostr_events_post_long_form, nostr_events_post_anonymous, nostr_events_repost, nostr_events_delete, nostr_events_post_group_chat, nostr_events_post_reaction, nostr_events_publish_signed, nostr_events_post_reply, nostr_events_post_comment, nostr_events_create_poll, nostr_events_vote_poll, nostr_events_get_poll_results, nostr_groups_put_user, nostr_groups_remove_user, nostr_groups_edit_metadata, nostr_groups_delete_event, nostr_groups_create_group, nostr_groups_delete_group, nostr_groups_create_invite, nostr_groups_join, nostr_groups_leave, nostr_metadata_set, nostr_metadata_get, nostr_metadata_fetch, nostr_profiles_get, nostr_follows_set, nostr_follows_get, nostr_follows_fetch, nostr_follows_add, nostr_follows_remove"
                    .to_string(),
            ),
        }
    }
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("signal");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn start_stdio_server() -> anyhow::Result<()> {
    start_stdio_server_with_runtime(NostrMcpRuntime::default()).await
}

pub async fn start_stdio_server_with_runtime(
    runtime_config: NostrMcpRuntime,
) -> anyhow::Result<()> {
    let server_name = runtime_config.server_name.clone();
    let server = NostrMcpServer::with_runtime(runtime_config);
    server.initialize().await?;
    info!("starting {server_name} MCP server (stdio)");
    loop {
        let service = server.clone().serve(stdio()).await?;
        info!("server ready (stdio)");
        tokio::select! {
            _ = service.waiting() => {
                info!("stdio input closed; restarting");
                sleep(Duration::from_millis(200)).await;
                continue;
            }
            _ = wait_for_shutdown() => {
                info!("shutdown signal received");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NostrMcpRuntime, NostrMcpServer};
    use nostr_mcp_core::follows::{AddFollowArgs, RemoveFollowArgs, SetFollowsArgs};
    use nostr_mcp_core::key_store::{
        EmptyArgs, ExportArgs, ExportFormat, ImportArgs, RemoveArgs, RenameLabelArgs, SetActiveArgs,
    };
    use nostr_mcp_core::keys::{DerivePublicArgs, VerifyArgs};
    use nostr_mcp_core::metadata::SetMetadataArgs;
    use nostr_mcp_core::nip30::Nip30ParseArgs;
    use nostr_mcp_core::publish::{CreateTextArgs, SignEventArgs};
    use nostr_mcp_core::references::ParseReferencesArgs;
    use nostr_mcp_core::settings::FollowEntry;
    use rmcp::ServerHandler;
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::model::CallToolResult;
    use serde::Deserialize;
    use serde_json::{Map, Value};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    const CHARACTERIZED_STABLE_TOOL_COUNT: usize = 66;
    const CHARACTERIZED_GENERIC_STABLE_TOOL_COUNT: usize = 64;
    const CHARACTERIZED_PLANNED_TOOLS: [&str; 7] = [
        "nostr_nip19_convert",
        "nostr_nip19_analyze",
        "nostr_zaps_get_received",
        "nostr_zaps_get_sent",
        "nostr_zaps_get_all",
        "nostr_zaps_prepare_anonymous",
        "nostr_zaps_validate_receipt",
    ];
    const HOST_LOCAL_TOOLS: [&str; 2] = ["nostr_config_dir_get", "nostr_config_dir_set"];
    const GOLDEN_READ_ONLY_TOOL_COUNT: usize = 9;
    const GOLDEN_READ_ONLY_TOOLS: [&str; GOLDEN_READ_ONLY_TOOL_COUNT] = [
        "nostr_events_parse_emojis",
        "nostr_events_parse_refs",
        "nostr_follows_get",
        "nostr_keys_derive_public",
        "nostr_keys_export",
        "nostr_keys_get_active",
        "nostr_keys_list",
        "nostr_keys_verify",
        "nostr_metadata_get",
    ];
    const GOLDEN_WRITE_TOOL_COUNT: usize = 10;
    const GOLDEN_WRITE_TOOLS: [&str; GOLDEN_WRITE_TOOL_COUNT] = [
        "nostr_events_create_text",
        "nostr_events_sign",
        "nostr_follows_add",
        "nostr_follows_remove",
        "nostr_follows_set",
        "nostr_keys_import",
        "nostr_keys_remove",
        "nostr_keys_rename_label",
        "nostr_keys_set_active",
        "nostr_metadata_set",
    ];
    const FIXTURE_PRIMARY_LABEL: &str = "primary";
    const FIXTURE_SECONDARY_LABEL: &str = "secondary";
    const FIXTURE_PRIMARY_NSEC: &str =
        "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp";
    const FIXTURE_PRIMARY_NPUB: &str =
        "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";
    const FIXTURE_SECONDARY_NPUB: &str =
        "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h";
    const FIXTURE_SECONDARY_PUBKEY_HEX: &str =
        "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573";
    const FIXTURE_VERIFY_INVALID_KEY: &str = "not-a-key";
    const REDACTED_SIGNATURE: &str = "<redacted_signature>";
    const REDACTED_TIMESTAMP: &str = "<redacted_timestamp>";

    #[derive(Deserialize)]
    struct ToolRegistry {
        tools: Vec<ToolEntry>,
    }

    #[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    enum ToolStatus {
        Stable,
        Planned,
    }

    #[derive(Deserialize)]
    struct ToolEntry {
        name: String,
        status: ToolStatus,
        summary: String,
        #[serde(default)]
        input_schema: Map<String, Value>,
        #[serde(default)]
        output_schema: Map<String, Value>,
    }

    fn load_tool_registry() -> ToolRegistry {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/registry/tools.json");
        let data = std::fs::read_to_string(&path).expect("read tools registry");
        serde_json::from_str(&data).expect("parse tools registry")
    }

    fn characterized_live_registry_tool_names(registry: &ToolRegistry) -> BTreeSet<String> {
        registry
            .tools
            .iter()
            .filter(|tool| {
                tool.status == ToolStatus::Stable && !HOST_LOCAL_TOOLS.contains(&tool.name.as_str())
            })
            .map(|tool| tool.name.clone())
            .collect()
    }

    fn characterized_live_registry_tools(registry: &ToolRegistry) -> Vec<&ToolEntry> {
        registry
            .tools
            .iter()
            .filter(|tool| {
                tool.status == ToolStatus::Stable && !HOST_LOCAL_TOOLS.contains(&tool.name.as_str())
            })
            .collect()
    }

    fn assert_registry_characterization(registry: &ToolRegistry) {
        let names: BTreeSet<String> = registry
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect();
        let planned: BTreeSet<String> = registry
            .tools
            .iter()
            .filter(|tool| tool.status == ToolStatus::Planned)
            .map(|tool| tool.name.clone())
            .collect();
        let stable_count = registry
            .tools
            .iter()
            .filter(|tool| tool.status == ToolStatus::Stable)
            .count();

        assert_eq!(
            names.len(),
            registry.tools.len(),
            "duplicate tool name in registry"
        );
        assert!(
            registry
                .tools
                .iter()
                .all(|tool| !tool.summary.trim().is_empty()),
            "registry tool summary must not be empty"
        );
        assert_eq!(stable_count, CHARACTERIZED_STABLE_TOOL_COUNT);
        assert_eq!(
            characterized_live_registry_tool_names(registry).len(),
            CHARACTERIZED_GENERIC_STABLE_TOOL_COUNT
        );
        assert_eq!(
            planned,
            CHARACTERIZED_PLANNED_TOOLS
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    fn assert_live_router_matches_registry(server: &NostrMcpServer, registry: &ToolRegistry) {
        assert_eq!(
            live_tool_names(server),
            characterized_live_registry_tool_names(registry)
        );
    }

    fn assert_server_instructions_match_registry(server: &NostrMcpServer, registry: &ToolRegistry) {
        assert_eq!(
            advertised_tool_names(server),
            characterized_live_registry_tool_names(registry)
        );
    }

    fn assert_stable_registry_schemas(registry: &ToolRegistry) {
        let stable_tools = characterized_live_registry_tools(registry);
        let missing_input_schema: Vec<_> = stable_tools
            .iter()
            .filter(|tool| tool.input_schema.is_empty())
            .map(|tool| tool.name.clone())
            .collect();
        let missing_output_schema: Vec<_> = stable_tools
            .iter()
            .filter(|tool| tool.output_schema.is_empty())
            .map(|tool| tool.name.clone())
            .collect();

        assert!(
            missing_input_schema.is_empty(),
            "stable registry tools missing input schema: {missing_input_schema:?}"
        );
        assert!(
            missing_output_schema.is_empty(),
            "stable registry tools missing output schema: {missing_output_schema:?}"
        );
    }

    fn assert_stable_live_route_metadata(server: &NostrMcpServer, registry: &ToolRegistry) {
        let mut missing_description = Vec::new();
        let mut missing_input_schema = Vec::new();

        for tool_name in characterized_live_registry_tool_names(registry) {
            let route = server
                .tool_router
                .map
                .get(tool_name.as_str())
                .expect("characterized tool route");
            if route
                .attr
                .description
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                missing_description.push(tool_name.clone());
            }
            if route.attr.input_schema.is_empty() {
                missing_input_schema.push(tool_name.clone());
            }
        }

        assert!(
            missing_description.is_empty(),
            "stable live routes missing descriptions: {missing_description:?}"
        );
        assert!(
            missing_input_schema.is_empty(),
            "stable live routes missing input schema: {missing_input_schema:?}"
        );
    }

    fn assert_stable_live_route_output_schema_posture(
        server: &NostrMcpServer,
        registry: &ToolRegistry,
    ) {
        let characterized_tools: Vec<_> = characterized_live_registry_tool_names(registry)
            .into_iter()
            .collect();
        let missing_output_schema: Vec<_> = characterized_tools
            .iter()
            .filter_map(|tool_name| {
                let route = server
                    .tool_router
                    .map
                    .get(tool_name.as_str())
                    .expect("characterized tool route");
                route
                    .attr
                    .output_schema
                    .as_ref()
                    .is_none_or(|schema| schema.is_empty())
                    .then(|| tool_name.clone())
            })
            .collect();

        assert!(
            missing_output_schema == characterized_tools,
            "stable live route output schema posture changed: {missing_output_schema:?}"
        );
    }

    fn assert_golden_read_only_tool_cohort(registry: &ToolRegistry) {
        let live_tools = characterized_live_registry_tool_names(registry);
        let golden_tools: BTreeSet<_> = GOLDEN_READ_ONLY_TOOLS
            .into_iter()
            .map(str::to_string)
            .collect();

        assert_eq!(golden_tools.len(), GOLDEN_READ_ONLY_TOOL_COUNT);
        assert!(
            golden_tools.is_subset(&live_tools),
            "golden read-only tool cohort drifted: {golden_tools:?}"
        );
    }

    fn assert_golden_write_tool_cohort(registry: &ToolRegistry) {
        let live_tools = characterized_live_registry_tool_names(registry);
        let golden_tools: BTreeSet<_> =
            GOLDEN_WRITE_TOOLS.into_iter().map(str::to_string).collect();

        assert_eq!(golden_tools.len(), GOLDEN_WRITE_TOOL_COUNT);
        assert!(
            golden_tools.is_subset(&live_tools),
            "golden write tool cohort drifted: {golden_tools:?}"
        );
    }

    fn assert_registry_surface_guard() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_registry_characterization(&registry);
        assert_live_router_matches_registry(&server, &registry);
        assert_server_instructions_match_registry(&server, &registry);
        assert_stable_registry_schemas(&registry);
        assert_stable_live_route_metadata(&server, &registry);
        assert_stable_live_route_output_schema_posture(&server, &registry);
        assert_golden_read_only_tool_cohort(&registry);
        assert_golden_write_tool_cohort(&registry);
    }

    fn golden_fixture_path(category: &str, name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(category)
            .join(format!("{name}.json"))
    }

    fn tool_result_json(result: CallToolResult) -> Value {
        result
            .into_typed::<Value>()
            .expect("json call tool result content")
    }

    fn redact_json_pointer(value: &mut Value, pointer: &str, replacement: &str) {
        let target = value.pointer_mut(pointer).expect("redaction pointer");
        *target = Value::String(replacement.to_string());
    }

    fn redact_embedded_json_pointer(
        value: &mut Value,
        outer_pointer: &str,
        inner_pointer: &str,
        replacement: &str,
    ) {
        let raw = value
            .pointer(outer_pointer)
            .and_then(Value::as_str)
            .expect("embedded json pointer");
        let mut embedded: Value = serde_json::from_str(raw).expect("parse embedded json");
        redact_json_pointer(&mut embedded, inner_pointer, replacement);
        let target = value
            .pointer_mut(outer_pointer)
            .expect("embedded outer pointer");
        *target = Value::String(embedded.to_string());
    }

    fn normalize_embedded_json_pointer(value: &mut Value, outer_pointer: &str) {
        let raw = value
            .pointer(outer_pointer)
            .and_then(Value::as_str)
            .expect("embedded json pointer");
        let embedded: Value = serde_json::from_str(raw).expect("parse embedded json");
        let target = value
            .pointer_mut(outer_pointer)
            .expect("embedded outer pointer");
        *target = embedded;
    }

    fn assert_tool_result_matches_golden(
        category: &str,
        name: &str,
        result: CallToolResult,
        redactions: &[(&str, &str)],
    ) {
        let mut actual = tool_result_json(result);
        for (pointer, replacement) in redactions {
            redact_json_pointer(&mut actual, pointer, replacement);
        }
        let path = golden_fixture_path(category, name);
        let expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read golden fixture"))
                .expect("parse golden fixture");
        assert_eq!(actual, expected, "golden mismatch for {}", path.display());
    }

    fn assert_tool_result_matches_golden_with_embedded_redactions(
        category: &str,
        name: &str,
        result: CallToolResult,
        redactions: &[(&str, &str)],
        embedded_redactions: &[(&str, &str, &str)],
    ) {
        let mut actual = tool_result_json(result);
        for (pointer, replacement) in redactions {
            redact_json_pointer(&mut actual, pointer, replacement);
        }
        for (outer_pointer, inner_pointer, replacement) in embedded_redactions {
            redact_embedded_json_pointer(&mut actual, outer_pointer, inner_pointer, replacement);
        }
        let path = golden_fixture_path(category, name);
        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read golden fixture"))
                .expect("parse golden fixture");
        for (outer_pointer, _, _) in embedded_redactions {
            normalize_embedded_json_pointer(&mut actual, outer_pointer);
            normalize_embedded_json_pointer(&mut expected, outer_pointer);
        }
        assert_eq!(actual, expected, "golden mismatch for {}", path.display());
    }

    fn golden_server(name: &str) -> (tempfile::TempDir, NostrMcpServer) {
        let dir = tempdir().unwrap();
        let runtime = NostrMcpRuntime::new(
            format!("golden-{name}"),
            format!("golden-service-{name}"),
            dir.path().to_path_buf(),
        );
        (dir, NostrMcpServer::with_runtime(runtime))
    }

    async fn import_fixture_key(
        server: &NostrMcpServer,
        label: &str,
        key_material: &str,
        persist_secret: bool,
    ) -> CallToolResult {
        server
            .nostr_keys_import(Parameters(ImportArgs {
                label: label.to_string(),
                key_material: key_material.to_string(),
                make_active: Some(true),
                persist_secret: Some(persist_secret),
            }))
            .await
            .expect("import fixture key")
    }

    async fn import_primary_watch_only_key(server: &NostrMcpServer) {
        import_fixture_key(server, FIXTURE_PRIMARY_LABEL, FIXTURE_PRIMARY_NPUB, false).await;
    }

    async fn import_primary_signing_key(server: &NostrMcpServer) {
        import_fixture_key(server, FIXTURE_PRIMARY_LABEL, FIXTURE_PRIMARY_NSEC, true).await;
    }

    async fn import_secondary_watch_only_key(server: &NostrMcpServer) {
        import_fixture_key(
            server,
            FIXTURE_SECONDARY_LABEL,
            FIXTURE_SECONDARY_NPUB,
            false,
        )
        .await;
    }

    fn live_tool_names(server: &NostrMcpServer) -> BTreeSet<String> {
        server
            .tool_router
            .map
            .keys()
            .map(|name| name.to_string())
            .collect()
    }

    fn advertised_tool_names(server: &NostrMcpServer) -> BTreeSet<String> {
        let info = ServerHandler::get_info(server);
        let instructions = info.instructions.expect("server instructions");
        let raw = instructions
            .strip_prefix("Tools: ")
            .expect("tools prefix in instructions");
        let advertised: Vec<String> = raw.split(',').map(|item| item.trim().to_string()).collect();
        let unique: BTreeSet<String> = advertised.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            advertised.len(),
            "duplicate tool name in server instructions"
        );
        unique
    }

    #[test]
    fn tool_registry_matches_characterized_surface() {
        let registry = load_tool_registry();
        assert_registry_characterization(&registry);
    }

    #[test]
    fn live_tool_router_matches_characterized_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_live_router_matches_registry(&server, &registry);
    }

    #[test]
    fn server_instructions_match_characterized_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_server_instructions_match_registry(&server, &registry);
    }

    #[test]
    fn stable_registry_tools_define_input_and_output_schemas() {
        let registry = load_tool_registry();
        assert_stable_registry_schemas(&registry);
    }

    #[test]
    fn stable_live_tool_routes_define_descriptions_and_input_schemas() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_stable_live_route_metadata(&server, &registry);
    }

    #[test]
    fn stable_live_tool_routes_do_not_yet_define_output_schemas() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_stable_live_route_output_schema_posture(&server, &registry);
    }

    #[test]
    fn golden_read_only_tool_cohort_is_characterized() {
        let registry = load_tool_registry();
        assert_golden_read_only_tool_cohort(&registry);
    }

    #[test]
    fn golden_write_tool_cohort_is_characterized() {
        let registry = load_tool_registry();
        assert_golden_write_tool_cohort(&registry);
    }

    #[test]
    fn registry_surface_guard_blocks_drift() {
        assert_registry_surface_guard();
    }

    #[test]
    fn server_info_advertises_tools() {
        let server = NostrMcpServer::new();
        let info = ServerHandler::get_info(&server);
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn golden_keys_verify_valid_nsec() {
        let (_dir, server) = golden_server("keys-verify-valid-nsec");
        let result = server
            .nostr_keys_verify(Parameters(VerifyArgs {
                key: FIXTURE_PRIMARY_NSEC.to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "keys_verify_valid_nsec", result, &[]);
    }

    #[tokio::test]
    async fn golden_keys_verify_invalid() {
        let (_dir, server) = golden_server("keys-verify-invalid");
        let result = server
            .nostr_keys_verify(Parameters(VerifyArgs {
                key: FIXTURE_VERIFY_INVALID_KEY.to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "keys_verify_invalid", result, &[]);
    }

    #[tokio::test]
    async fn golden_keys_derive_public() {
        let (_dir, server) = golden_server("keys-derive-public");
        let result = server
            .nostr_keys_derive_public(Parameters(DerivePublicArgs {
                private_key: FIXTURE_PRIMARY_NSEC.to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "keys_derive_public", result, &[]);
    }

    #[tokio::test]
    async fn golden_keys_export_watch_only_bech32() {
        let (_dir, server) = golden_server("keys-export-watch-only");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_export(Parameters(ExportArgs {
                label: None,
                format: ExportFormat::Bech32,
                include_private: false,
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden(
            "read_only",
            "keys_export_watch_only_bech32",
            result,
            &[],
        );
    }

    #[tokio::test]
    async fn golden_keys_get_active_watch_only() {
        let (_dir, server) = golden_server("keys-get-active");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_get_active(Parameters(EmptyArgs::default()))
            .await
            .unwrap();
        assert_tool_result_matches_golden(
            "read_only",
            "keys_get_active_watch_only",
            result,
            &[("/created_at", REDACTED_TIMESTAMP)],
        );
    }

    #[tokio::test]
    async fn golden_keys_list_watch_only() {
        let (_dir, server) = golden_server("keys-list");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_list(Parameters(EmptyArgs::default()))
            .await
            .unwrap();
        assert_tool_result_matches_golden(
            "read_only",
            "keys_list_watch_only",
            result,
            &[("/keys/0/created_at", REDACTED_TIMESTAMP)],
        );
    }

    #[tokio::test]
    async fn golden_metadata_get_local_settings() {
        let (_dir, server) = golden_server("metadata-get");
        import_primary_watch_only_key(&server).await;
        server
            .nostr_metadata_set(Parameters(SetMetadataArgs {
                name: Some("alice".to_string()),
                display_name: Some("Alice Example".to_string()),
                about: Some("Grows citrus and coffee".to_string()),
                picture: Some("https://example.com/alice.png".to_string()),
                banner: None,
                nip05: Some("alice@example.com".to_string()),
                lud06: None,
                lud16: Some("alice@ln.example.com".to_string()),
                website: Some("https://example.com/alice".to_string()),
                publish: Some(false),
            }))
            .await
            .unwrap();
        let result = server
            .nostr_metadata_get(Parameters(EmptyArgs::default()))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "metadata_get_local_settings", result, &[]);
    }

    #[tokio::test]
    async fn golden_follows_get_local_settings() {
        let (_dir, server) = golden_server("follows-get");
        import_primary_watch_only_key(&server).await;
        server
            .nostr_follows_set(Parameters(SetFollowsArgs {
                follows: vec![
                    FollowEntry {
                        pubkey: FIXTURE_SECONDARY_PUBKEY_HEX.to_string(),
                        relay_url: Some("wss://relay.example.com".to_string()),
                        petname: Some("bob".to_string()),
                    },
                    FollowEntry {
                        pubkey: "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
                            .to_string(),
                        relay_url: None,
                        petname: None,
                    },
                ],
                publish: Some(false),
            }))
            .await
            .unwrap();
        let result = server
            .nostr_follows_get(Parameters(EmptyArgs::default()))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "follows_get_local_settings", result, &[]);
    }

    #[tokio::test]
    async fn golden_events_parse_emojis() {
        let (_dir, server) = golden_server("events-parse-emojis");
        let result = server
            .nostr_events_parse_emojis(Parameters(Nip30ParseArgs {
                content: "farm time :tractor: :missing: :bad-emoji:".to_string(),
                tags: Some(vec![
                    vec![
                        "emoji".to_string(),
                        "tractor".to_string(),
                        "https://example.com/tractor.png".to_string(),
                    ],
                    vec![
                        "emoji".to_string(),
                        "bad-emoji".to_string(),
                        "https://example.com/bad.png".to_string(),
                    ],
                ]),
                kind: Some(1),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "events_parse_emojis", result, &[]);
    }

    #[tokio::test]
    async fn golden_events_parse_refs() {
        let (_dir, server) = golden_server("events-parse-refs");
        let result = server
            .nostr_events_parse_refs(Parameters(ParseReferencesArgs {
                content: format!(
                    "see nostr:{FIXTURE_PRIMARY_NPUB} and nostr:{FIXTURE_PRIMARY_NSEC}"
                ),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("read_only", "events_parse_refs", result, &[]);
    }

    #[tokio::test]
    async fn golden_keys_import_watch_only() {
        let (_dir, server) = golden_server("keys-import-watch-only");
        let result =
            import_fixture_key(&server, FIXTURE_PRIMARY_LABEL, FIXTURE_PRIMARY_NPUB, false).await;
        assert_tool_result_matches_golden(
            "write_capable",
            "keys_import_watch_only",
            result,
            &[("/created_at", REDACTED_TIMESTAMP)],
        );
    }

    #[tokio::test]
    async fn golden_keys_set_active() {
        let (_dir, server) = golden_server("keys-set-active");
        import_primary_watch_only_key(&server).await;
        import_secondary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_set_active(Parameters(SetActiveArgs {
                label: FIXTURE_PRIMARY_LABEL.to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden(
            "write_capable",
            "keys_set_active",
            result,
            &[("/created_at", REDACTED_TIMESTAMP)],
        );
    }

    #[tokio::test]
    async fn golden_keys_rename_label() {
        let (_dir, server) = golden_server("keys-rename-label");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_rename_label(Parameters(RenameLabelArgs {
                from: None,
                to: "orchard".to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden(
            "write_capable",
            "keys_rename_label",
            result,
            &[("/created_at", REDACTED_TIMESTAMP)],
        );
    }

    #[tokio::test]
    async fn golden_keys_remove() {
        let (_dir, server) = golden_server("keys-remove");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_keys_remove(Parameters(RemoveArgs {
                label: FIXTURE_PRIMARY_LABEL.to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "keys_remove", result, &[]);
    }

    #[tokio::test]
    async fn golden_metadata_set_local() {
        let (_dir, server) = golden_server("metadata-set-local");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_metadata_set(Parameters(SetMetadataArgs {
                name: Some("alice".to_string()),
                display_name: Some("Alice Example".to_string()),
                about: Some("Grows citrus and coffee".to_string()),
                picture: Some("https://example.com/alice.png".to_string()),
                banner: None,
                nip05: Some("alice@example.com".to_string()),
                lud06: None,
                lud16: Some("alice@ln.example.com".to_string()),
                website: Some("https://example.com/alice".to_string()),
                publish: Some(false),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "metadata_set_local", result, &[]);
    }

    #[tokio::test]
    async fn golden_follows_set_local() {
        let (_dir, server) = golden_server("follows-set-local");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_follows_set(Parameters(SetFollowsArgs {
                follows: vec![
                    FollowEntry {
                        pubkey: FIXTURE_SECONDARY_PUBKEY_HEX.to_string(),
                        relay_url: Some("wss://relay.example.com".to_string()),
                        petname: Some("bob".to_string()),
                    },
                    FollowEntry {
                        pubkey: "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
                            .to_string(),
                        relay_url: None,
                        petname: None,
                    },
                ],
                publish: Some(false),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "follows_set_local", result, &[]);
    }

    #[tokio::test]
    async fn golden_follows_add_local() {
        let (_dir, server) = golden_server("follows-add-local");
        import_primary_watch_only_key(&server).await;
        server
            .nostr_follows_set(Parameters(SetFollowsArgs {
                follows: vec![FollowEntry {
                    pubkey: FIXTURE_SECONDARY_PUBKEY_HEX.to_string(),
                    relay_url: Some("wss://relay.example.com".to_string()),
                    petname: Some("bob".to_string()),
                }],
                publish: Some(false),
            }))
            .await
            .unwrap();
        let result = server
            .nostr_follows_add(Parameters(AddFollowArgs {
                pubkey: "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
                    .to_string(),
                relay_url: None,
                petname: Some("carol".to_string()),
                publish: Some(false),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "follows_add_local", result, &[]);
    }

    #[tokio::test]
    async fn golden_follows_remove_local() {
        let (_dir, server) = golden_server("follows-remove-local");
        import_primary_watch_only_key(&server).await;
        server
            .nostr_follows_set(Parameters(SetFollowsArgs {
                follows: vec![
                    FollowEntry {
                        pubkey: FIXTURE_SECONDARY_PUBKEY_HEX.to_string(),
                        relay_url: Some("wss://relay.example.com".to_string()),
                        petname: Some("bob".to_string()),
                    },
                    FollowEntry {
                        pubkey: "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
                            .to_string(),
                        relay_url: None,
                        petname: Some("carol".to_string()),
                    },
                ],
                publish: Some(false),
            }))
            .await
            .unwrap();
        let result = server
            .nostr_follows_remove(Parameters(RemoveFollowArgs {
                pubkey: FIXTURE_SECONDARY_PUBKEY_HEX.to_string(),
                publish: Some(false),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "follows_remove_local", result, &[]);
    }

    #[tokio::test]
    async fn golden_events_create_text() {
        let (_dir, server) = golden_server("events-create-text");
        import_primary_watch_only_key(&server).await;
        let result = server
            .nostr_events_create_text(Parameters(CreateTextArgs {
                content: "hello orchard".to_string(),
                tags: Some(vec![
                    vec!["t".to_string(), "orchard".to_string()],
                    vec!["subject".to_string(), "field-note".to_string()],
                ]),
                created_at: Some(1_700_000_000),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden("write_capable", "events_create_text", result, &[]);
    }

    #[tokio::test]
    async fn golden_events_sign() {
        let (_dir, server) = golden_server("events-sign");
        import_primary_signing_key(&server).await;
        let unsigned = tool_result_json(
            server
                .nostr_events_create_text(Parameters(CreateTextArgs {
                    content: "hello orchard".to_string(),
                    tags: Some(vec![
                        vec!["t".to_string(), "orchard".to_string()],
                        vec!["subject".to_string(), "field-note".to_string()],
                    ]),
                    created_at: Some(1_700_000_000),
                }))
                .await
                .unwrap(),
        );
        let result = server
            .nostr_events_sign(Parameters(SignEventArgs {
                unsigned_event_json: unsigned["unsigned_event_json"]
                    .as_str()
                    .expect("unsigned event json")
                    .to_string(),
            }))
            .await
            .unwrap();
        assert_tool_result_matches_golden_with_embedded_redactions(
            "write_capable",
            "events_sign",
            result,
            &[],
            &[("/event_json", "/sig", REDACTED_SIGNATURE)],
        );
    }

    #[tokio::test]
    async fn server_state_is_scoped_per_instance() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let server_a = NostrMcpServer::with_runtime(NostrMcpRuntime::new(
            "nostr-a",
            "service-a",
            dir_a.path().to_path_buf(),
        ));
        let server_b = NostrMcpServer::with_runtime(NostrMcpRuntime::new(
            "nostr-b",
            "service-b",
            dir_b.path().to_path_buf(),
        ));

        let keystore_a = server_a.keystore().await.unwrap();
        let settings_a = server_a.settings_store().await.unwrap();
        let keystore_b = server_b.keystore().await.unwrap();
        let settings_b = server_b.settings_store().await.unwrap();
        keystore_a
            .generate("default".into(), true, false)
            .await
            .unwrap();
        keystore_b
            .generate("default".into(), true, false)
            .await
            .unwrap();
        let client_a = server_a.client().await.unwrap();
        let client_b = server_b.client().await.unwrap();

        assert_eq!(server_a.context.runtime.server_name, "nostr-a");
        assert_eq!(server_b.context.runtime.server_name, "nostr-b");
        assert_eq!(
            server_a.context.runtime.paths.config_root,
            dir_a.path().to_path_buf()
        );
        assert_eq!(
            server_b.context.runtime.paths.config_root,
            dir_b.path().to_path_buf()
        );
        assert!(dir_a.path().join("keystore.secret").exists());
        assert!(dir_b.path().join("keystore.secret").exists());
        assert!(Arc::ptr_eq(
            &keystore_a,
            &server_a.keystore().await.unwrap()
        ));
        assert!(Arc::ptr_eq(
            &settings_a,
            &server_a.settings_store().await.unwrap()
        ));
        assert!(!Arc::ptr_eq(&keystore_a, &keystore_b));
        assert!(!Arc::ptr_eq(&settings_a, &settings_b));
        assert_eq!(client_a.active_label, "default");
        assert_eq!(client_b.active_label, "default");
        assert_ne!(client_a.active_pubkey, client_b.active_pubkey);
    }
}
