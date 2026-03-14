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
    use rmcp::ServerHandler;
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
            characterized_live_registry_tool_names(&registry).len(),
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

    #[test]
    fn live_tool_router_matches_characterized_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_eq!(
            live_tool_names(&server),
            characterized_live_registry_tool_names(&registry)
        );
    }

    #[test]
    fn server_instructions_match_characterized_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        assert_eq!(
            advertised_tool_names(&server),
            characterized_live_registry_tool_names(&registry)
        );
    }

    #[test]
    fn stable_registry_tools_define_input_and_output_schemas() {
        let registry = load_tool_registry();
        let stable_tools = characterized_live_registry_tools(&registry);
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

    #[test]
    fn stable_live_tool_routes_define_descriptions_and_input_schemas() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        let mut missing_description = Vec::new();
        let mut missing_input_schema = Vec::new();

        for tool_name in characterized_live_registry_tool_names(&registry) {
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

    #[test]
    fn stable_live_tool_routes_do_not_yet_define_output_schemas() {
        let server = NostrMcpServer::new();
        let registry = load_tool_registry();
        let characterized_tools: Vec<_> = characterized_live_registry_tool_names(&registry)
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

    #[test]
    fn server_info_advertises_tools() {
        let server = NostrMcpServer::new();
        let info = ServerHandler::get_info(&server);
        assert!(info.capabilities.tools.is_some());
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
