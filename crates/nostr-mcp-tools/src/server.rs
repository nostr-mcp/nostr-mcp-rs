mod event_authoring;
mod event_queries;
mod follows;
mod groups;
mod keys;
mod metadata;
mod protocol_publishing;
mod protocol_utils;
mod relays;

use nostr_mcp_core::error::CoreError;
use nostr_mcp_policy::{
    AuthoringAction, CapabilityScope, PolicyDecision, PolicyDecisionEffect, PolicyRequest,
    SignerMethod,
};
use nostr_mcp_server::{
    NostrMcpRuntime, NostrMcpServerCatalog, NostrMcpServerServices,
    host_runtime::{
        client::ActiveClient,
        error::{HostRuntimeError, HostRuntimeResult},
        key_store::KeyStore,
        settings::SettingsStore,
    },
    service::NostrMcpServerServiceError,
};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::router::tool::ToolRouter,
    model::{ErrorData, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool_handler, tool_router,
    transport::stdio,
};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::info;

fn core_error(err: CoreError) -> ErrorData {
    if let CoreError::InvalidInput(msg) = err {
        return ErrorData::invalid_params(msg, None);
    }
    ErrorData::internal_error(err.to_string(), None)
}

fn host_runtime_error(err: HostRuntimeError) -> ErrorData {
    match err {
        HostRuntimeError::InvalidInput(msg) => ErrorData::invalid_params(msg, None),
        HostRuntimeError::OperationDenied(msg) => ErrorData::invalid_request(msg, None),
        err => ErrorData::internal_error(err.to_string(), None),
    }
}

fn invalid_params<E: ToString>(err: E) -> ErrorData {
    ErrorData::invalid_params(err.to_string(), None)
}

fn policy_reason_name(decision: &PolicyDecision) -> String {
    serde_json::to_value(decision.reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "policy_violation".to_string())
}

fn policy_error(decision: PolicyDecision) -> ErrorData {
    let reason = policy_reason_name(&decision);
    let message = match decision.effect {
        PolicyDecisionEffect::Allow => "policy allowed request".to_string(),
        PolicyDecisionEffect::Deny => format!("policy denied request: {reason}"),
        PolicyDecisionEffect::Escalate => format!("policy requires approval: {reason}"),
    };
    let data = serde_json::to_value(&decision).ok();
    ErrorData::invalid_request(message, data)
}

fn server_service_error(err: NostrMcpServerServiceError) -> ErrorData {
    match err {
        NostrMcpServerServiceError::HostRuntime(err) => host_runtime_error(err),
        NostrMcpServerServiceError::PolicyDecision(decision) => policy_error(decision),
    }
}

#[derive(Clone)]
pub struct NostrMcpServer {
    tool_router: ToolRouter<Self>,
    services: Arc<NostrMcpServerServices>,
}

impl NostrMcpServer {
    #[cfg_attr(not(test), allow(dead_code))]
    fn runtime(&self) -> &NostrMcpRuntime {
        self.services.runtime()
    }

    async fn initialize(&self) -> HostRuntimeResult<()> {
        self.services.initialize().await
    }

    fn capability_request(&self, capability_scope: CapabilityScope) -> PolicyRequest {
        self.services.capability_request(capability_scope)
    }

    fn raw_secret_request(
        &self,
        capability_scope: CapabilityScope,
        signer_method: Option<SignerMethod>,
    ) -> PolicyRequest {
        self.services
            .raw_secret_request(capability_scope, signer_method)
    }

    fn authoring_request(
        &self,
        capability_scope: CapabilityScope,
        authoring_action: AuthoringAction,
        signer_method: Option<SignerMethod>,
        event_kind: Option<u16>,
        relay_targets: Option<Vec<String>>,
    ) -> PolicyRequest {
        self.services.authoring_request(
            capability_scope,
            authoring_action,
            signer_method,
            event_kind,
            relay_targets,
        )
    }

    async fn authorize_policy_request(&self, request: PolicyRequest) -> Result<(), ErrorData> {
        self.services
            .authorize_policy_request(request)
            .await
            .map_err(server_service_error)
    }

    async fn keystore(&self) -> Result<Arc<KeyStore>, ErrorData> {
        self.services.keystore().await.map_err(host_runtime_error)
    }

    fn ensure_local_key_test_support(&self) -> Result<(), ErrorData> {
        self.services
            .ensure_local_key_test_support()
            .map_err(host_runtime_error)
    }

    async fn settings_store(&self) -> Result<Arc<SettingsStore>, ErrorData> {
        self.services
            .settings_store()
            .await
            .map_err(host_runtime_error)
    }

    async fn ensure_client_from(
        &self,
        keystore: Arc<KeyStore>,
        settings_store: Arc<SettingsStore>,
    ) -> Result<ActiveClient, ErrorData> {
        self.services
            .ensure_client_from(keystore, settings_store)
            .await
            .map_err(host_runtime_error)
    }

    async fn reset_client(&self) -> Result<(), ErrorData> {
        self.services
            .reset_client()
            .await
            .map_err(host_runtime_error)
    }

    #[cfg(test)]
    async fn client(&self) -> Result<ActiveClient, ErrorData> {
        let keystore = self.keystore().await?;
        let settings_store = self.settings_store().await?;
        self.ensure_client_from(keystore, settings_store).await
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
            services: Arc::new(NostrMcpServerServices::new(runtime)),
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
            instructions: Some(NostrMcpServerCatalog::generated().instructions()),
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
    use super::{NostrMcpRuntime, NostrMcpServer, core_error, host_runtime_error};
    use nostr_mcp_core::CoreError;
    use nostr_mcp_policy::{
        CapabilityScope, RelayTargetScope, SignerBackend, SignerPolicy, default_signer_policy,
    };
    use nostr_mcp_server::{default_runtime_signer_policy, host_runtime::error::HostRuntimeError};
    use nostr_mcp_types::common::EmptyArgs;
    use nostr_mcp_types::follows::{AddFollowArgs, RemoveFollowArgs, SetFollowsArgs};
    use nostr_mcp_types::key_store::{
        ExportArgs, ExportFormat, GenerateArgs, ImportArgs, RemoveArgs, RenameLabelArgs,
        SetActiveArgs,
    };
    use nostr_mcp_types::keys::{DerivePublicArgs, VerifyArgs};
    use nostr_mcp_types::metadata::SetMetadataArgs;
    use nostr_mcp_types::nip30::Nip30ParseArgs;
    use nostr_mcp_types::nip44::{Nip44DecryptArgs, Nip44EncryptArgs};
    use nostr_mcp_types::publish::{CreateTextArgs, PostTextArgs, SignEventArgs};
    use nostr_mcp_types::references::ParseReferencesArgs;
    use nostr_mcp_types::registry::{
        ToolContract, ToolRegistry, ToolStatus, generated_tool_registry,
        read_generated_registry_artifact,
    };
    use nostr_mcp_types::settings::FollowEntry;
    use rmcp::ServerHandler;
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::model::{CallToolResult, ErrorCode, ErrorData};
    use serde_json::Value;
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

    fn canonical_tool_registry() -> ToolRegistry {
        let artifact = read_generated_registry_artifact();
        let generated = generated_tool_registry();
        assert_eq!(
            artifact, generated,
            "generated registry artifact drifted from runtime contract generation"
        );
        artifact
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

    fn characterized_live_registry_tools(registry: &ToolRegistry) -> Vec<&ToolContract> {
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
        let registry = canonical_tool_registry();
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
        )
        .with_local_key_test_support(true);
        (dir, NostrMcpServer::with_runtime(runtime))
    }

    fn production_server(name: &str) -> (tempfile::TempDir, NostrMcpServer) {
        let dir = tempdir().unwrap();
        let runtime = NostrMcpRuntime::new(
            format!("production-{name}"),
            format!("production-service-{name}"),
            dir.path().to_path_buf(),
        );
        (dir, NostrMcpServer::with_runtime(runtime))
    }

    fn server_with_policy(
        name: &str,
        config_root: PathBuf,
        signer_policy: SignerPolicy,
    ) -> NostrMcpServer {
        let runtime = NostrMcpRuntime::new(
            format!("policy-{name}"),
            format!("policy-service-{name}"),
            config_root,
        )
        .with_signer_policy(signer_policy)
        .with_local_key_test_support(true);
        NostrMcpServer::with_runtime(runtime)
    }

    fn policy_reason(err: &ErrorData) -> Option<&str> {
        err.data.as_ref()?.get("reason")?.as_str()
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
    fn generated_registry_matches_characterized_surface() {
        let registry = canonical_tool_registry();
        assert_registry_characterization(&registry);
    }

    #[test]
    fn generated_registry_artifact_matches_runtime_generation() {
        let registry = canonical_tool_registry();
        assert_eq!(registry, generated_tool_registry());
    }

    #[test]
    fn live_tool_router_matches_characterized_generated_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = canonical_tool_registry();
        assert_live_router_matches_registry(&server, &registry);
    }

    #[test]
    fn server_instructions_match_characterized_generated_registry_surface() {
        let server = NostrMcpServer::new();
        let registry = canonical_tool_registry();
        assert_server_instructions_match_registry(&server, &registry);
    }

    #[test]
    fn stable_generated_registry_tools_define_input_and_output_schemas() {
        let registry = canonical_tool_registry();
        assert_stable_registry_schemas(&registry);
    }

    #[test]
    fn stable_live_tool_routes_define_descriptions_and_input_schemas() {
        let server = NostrMcpServer::new();
        let registry = canonical_tool_registry();
        assert_stable_live_route_metadata(&server, &registry);
    }

    #[test]
    fn stable_live_tool_routes_do_not_yet_define_output_schemas() {
        let server = NostrMcpServer::new();
        let registry = canonical_tool_registry();
        assert_stable_live_route_output_schema_posture(&server, &registry);
    }

    #[test]
    fn golden_read_only_tool_cohort_is_characterized() {
        let registry = canonical_tool_registry();
        assert_golden_read_only_tool_cohort(&registry);
    }

    #[test]
    fn golden_write_tool_cohort_is_characterized() {
        let registry = canonical_tool_registry();
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

    #[test]
    fn core_error_maps_invalid_input_without_prefix() {
        let err = core_error(CoreError::invalid_input("bad input"));
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(err.message.as_ref(), "bad input");
    }

    #[test]
    fn core_error_maps_operation_to_internal_error_with_prefix() {
        let err = core_error(CoreError::operation("send failed"));
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(err.message.as_ref(), "operation error: send failed");
    }

    #[test]
    fn host_runtime_error_maps_invalid_input_without_prefix() {
        let err = host_runtime_error(HostRuntimeError::invalid_input("unknown key label"));
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(err.message.as_ref(), "unknown key label");
    }

    #[test]
    fn host_runtime_error_maps_runtime_failures_to_internal_error() {
        let err = host_runtime_error(HostRuntimeError::io("disk failed"));
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(err.message.as_ref(), "io error: disk failed");
    }

    #[test]
    fn host_runtime_error_maps_denied_operations_to_invalid_request() {
        let err = host_runtime_error(HostRuntimeError::operation_denied("blocked"));
        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message.as_ref(), "blocked");
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
    async fn host_runtime_invalid_input_surfaces_as_invalid_params() {
        let (_dir, server) = golden_server("host-runtime-invalid-input");
        let err = server
            .nostr_keys_set_active(Parameters(SetActiveArgs {
                label: "missing".to_string(),
            }))
            .await
            .expect_err("missing key should surface invalid params");

        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(err.message.as_ref(), "unknown key label");
    }

    #[tokio::test]
    async fn core_invalid_input_surfaces_as_invalid_params() {
        let (_dir, server) = golden_server("core-invalid-input");
        let err = server
            .nostr_nip44_decrypt(Parameters(Nip44DecryptArgs {
                private_key: FIXTURE_PRIMARY_NSEC.to_string(),
                public_key: FIXTURE_SECONDARY_NPUB.to_string(),
                ciphertext: "not-base64".to_string(),
            }))
            .await
            .expect_err("invalid nip44 payload should surface invalid params");

        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.as_ref().contains("invalid nip44 payload"),
            "unexpected error message: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn production_runtime_denies_local_key_generation() {
        let (_dir, server) = production_server("local-key-generation-deny");
        let err = server
            .nostr_keys_generate(Parameters(GenerateArgs {
                label: FIXTURE_PRIMARY_LABEL.to_string(),
                make_active: Some(true),
                persist_secret: Some(true),
            }))
            .await
            .expect_err("production runtime should deny local key generation");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message.as_ref(), "local key test support is disabled");
    }

    #[tokio::test]
    async fn production_runtime_denies_local_secret_import() {
        let (_dir, server) = production_server("local-secret-import-deny");
        let err = server
            .nostr_keys_import(Parameters(ImportArgs {
                label: FIXTURE_PRIMARY_LABEL.to_string(),
                key_material: FIXTURE_PRIMARY_NSEC.to_string(),
                make_active: Some(true),
                persist_secret: Some(true),
            }))
            .await
            .expect_err("production runtime should deny local secret import");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message.as_ref(), "local key test support is disabled");
    }

    #[tokio::test]
    async fn production_runtime_denies_private_key_export() {
        let (_dir, server) = production_server("private-key-export-deny");
        import_primary_watch_only_key(&server).await;
        let err = server
            .nostr_keys_export(Parameters(ExportArgs {
                label: None,
                format: ExportFormat::Both,
                include_private: true,
            }))
            .await
            .expect_err("production runtime should deny private key export");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message.as_ref(), "local key test support is disabled");
    }

    #[tokio::test]
    async fn production_runtime_denies_private_key_derivation() {
        let (_dir, server) = production_server("private-key-derivation-deny");
        let err = server
            .nostr_keys_derive_public(Parameters(DerivePublicArgs {
                private_key: FIXTURE_PRIMARY_NSEC.to_string(),
            }))
            .await
            .expect_err("production runtime should deny private key derivation");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message.as_ref(), "local key test support is disabled");
    }

    #[tokio::test]
    async fn production_runtime_denies_nip44_raw_secret_tools() {
        let (_dir, server) = production_server("nip44-raw-secret-deny");
        let encrypt_err = server
            .nostr_nip44_encrypt(Parameters(Nip44EncryptArgs {
                private_key: FIXTURE_PRIMARY_NSEC.to_string(),
                public_key: FIXTURE_SECONDARY_NPUB.to_string(),
                plaintext: "hello orchard".to_string(),
                version: None,
            }))
            .await
            .expect_err("production runtime should deny nip44 encrypt");

        assert_eq!(encrypt_err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(
            encrypt_err.message.as_ref(),
            "local key test support is disabled"
        );

        let decrypt_err = server
            .nostr_nip44_decrypt(Parameters(Nip44DecryptArgs {
                private_key: FIXTURE_PRIMARY_NSEC.to_string(),
                public_key: FIXTURE_SECONDARY_NPUB.to_string(),
                ciphertext: "not-base64".to_string(),
            }))
            .await
            .expect_err("production runtime should deny nip44 decrypt");

        assert_eq!(decrypt_err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(
            decrypt_err.message.as_ref(),
            "local key test support is disabled"
        );
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
    async fn policy_denies_unsigned_event_authoring_without_scope() {
        let dir = tempdir().unwrap();
        let seed_server = NostrMcpServer::with_runtime(NostrMcpRuntime::new(
            "policy-seed-build-unsigned",
            "policy-seed-build-unsigned",
            dir.path().to_path_buf(),
        ));
        import_primary_watch_only_key(&seed_server).await;

        let server = server_with_policy(
            "build-unsigned-deny",
            dir.path().to_path_buf(),
            default_signer_policy(),
        );
        let err = server
            .nostr_events_create_text(Parameters(CreateTextArgs {
                content: "hello orchard".to_string(),
                tags: None,
                created_at: Some(1_700_000_000),
            }))
            .await
            .expect_err("missing build unsigned scope should deny");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(policy_reason(&err), Some("missing_capability_scope"));
    }

    #[tokio::test]
    async fn policy_denies_signing_when_active_identity_is_watch_only() {
        let (_dir, server) = golden_server("policy-watch-only-sign-deny");
        import_primary_watch_only_key(&server).await;

        let unsigned = tool_result_json(
            server
                .nostr_events_create_text(Parameters(CreateTextArgs {
                    content: "hello orchard".to_string(),
                    tags: None,
                    created_at: Some(1_700_000_000),
                }))
                .await
                .expect("watch-only create text"),
        );
        let err = server
            .nostr_events_sign(Parameters(SignEventArgs {
                unsigned_event_json: unsigned["unsigned_event_json"]
                    .as_str()
                    .expect("unsigned event json")
                    .to_string(),
            }))
            .await
            .expect_err("watch-only active identity should deny signing");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(policy_reason(&err), Some("identity_class_mismatch"));
    }

    #[tokio::test]
    async fn policy_denies_publish_to_relay_outside_allowlist() {
        let dir = tempdir().unwrap();
        let mut relay_policy = default_runtime_signer_policy();
        relay_policy.relay_target_scope =
            RelayTargetScope::allowlist(vec!["wss://relay.radroots.org".to_string()]);
        let server =
            server_with_policy("relay-target-deny", dir.path().to_path_buf(), relay_policy);
        import_primary_signing_key(&server).await;

        let err = server
            .nostr_events_post_text(Parameters(PostTextArgs {
                content: "hello orchard".to_string(),
                pow: None,
                to_relays: Some(vec!["wss://relay.example.com".to_string()]),
            }))
            .await
            .expect_err("relay outside allowlist should deny publish");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(policy_reason(&err), Some("relay_target_out_of_scope"));
    }

    #[tokio::test]
    async fn policy_denies_local_secret_import_when_runtime_backend_is_remote() {
        let dir = tempdir().unwrap();
        let mut remote_policy = default_signer_policy();
        remote_policy.capability_scopes = vec![CapabilityScope::ManageIdentity];
        remote_policy.signer_backend = SignerBackend::Nip46Remote;
        let server = server_with_policy(
            "local-secret-import-deny",
            dir.path().to_path_buf(),
            remote_policy,
        );

        let err = server
            .nostr_keys_import(Parameters(ImportArgs {
                label: FIXTURE_PRIMARY_LABEL.to_string(),
                key_material: FIXTURE_PRIMARY_NSEC.to_string(),
                make_active: Some(true),
                persist_secret: Some(true),
            }))
            .await
            .expect_err("remote backend should deny local secret import");

        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(policy_reason(&err), Some("signer_backend_mismatch"));
    }

    #[tokio::test]
    async fn server_state_is_scoped_per_instance() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let server_a = NostrMcpServer::with_runtime(
            NostrMcpRuntime::new("nostr-a", "service-a", dir_a.path().to_path_buf())
                .with_local_key_test_support(true),
        );
        let server_b = NostrMcpServer::with_runtime(
            NostrMcpRuntime::new("nostr-b", "service-b", dir_b.path().to_path_buf())
                .with_local_key_test_support(true),
        );

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

        assert_eq!(server_a.runtime().server_name, "nostr-a");
        assert_eq!(server_b.runtime().server_name, "nostr-b");
        assert_eq!(
            server_a.runtime().paths.config_root,
            dir_a.path().to_path_buf()
        );
        assert_eq!(
            server_b.runtime().paths.config_root,
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
