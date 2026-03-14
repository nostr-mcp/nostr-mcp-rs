#![forbid(unsafe_code)]

#[cfg(feature = "types")]
pub mod types {
    pub use nostr_mcp_types::*;
}

#[cfg(feature = "policy")]
pub mod policy {
    pub use nostr_mcp_policy::*;
}

#[cfg(feature = "core")]
pub mod core {
    pub use nostr_mcp_core::*;
}

#[cfg(feature = "nip46")]
pub mod nip46 {
    pub use nostr_mcp_nip46::*;
}

#[cfg(feature = "server")]
pub mod server {
    pub use nostr_mcp_server::*;
    pub use nostr_mcp_tools::NostrMcpServer;
}

#[cfg(feature = "transport-stdio")]
pub mod transport_stdio {
    pub use nostr_mcp_transport_stdio::*;
}

pub mod prelude {
    #[cfg(feature = "policy")]
    pub use crate::policy::{CapabilityScope, PolicyRequest, SignerPolicy};
    #[cfg(feature = "server")]
    pub use crate::{NostrMcpRuntime, NostrMcpServer};
    #[cfg(feature = "transport-stdio")]
    pub use crate::{start_stdio_server, start_stdio_server_with_runtime};
}

#[cfg(feature = "server")]
pub use nostr_mcp_server::{
    HOST_LOCAL_TOOL_NAMES, NostrMcpPaths, NostrMcpRuntime, NostrMcpServerCatalog,
    NostrMcpServerServices, default_config_root, default_runtime_signer_policy, is_host_local_tool,
};
#[cfg(feature = "server")]
pub use nostr_mcp_tools::NostrMcpServer;
#[cfg(feature = "transport-stdio")]
pub use nostr_mcp_transport_stdio::{start_stdio_server, start_stdio_server_with_runtime};

#[cfg(test)]
mod tests {
    use super::{
        NostrMcpRuntime, NostrMcpServer, core, nip46, policy, prelude, start_stdio_server,
        start_stdio_server_with_runtime, types,
    };

    #[test]
    fn default_feature_set_reexports_curated_surface() {
        let runtime = NostrMcpRuntime::default();
        assert_eq!(runtime.server_name, "nostr-mcp");
        let _server = NostrMcpServer::with_runtime(runtime);
        let _ = start_stdio_server;
        let _ = start_stdio_server_with_runtime;
        let _ = prelude::NostrMcpServer::new;
        let _ = types::ToolStatus::Stable;
        let _ = policy::baseline_policy();
        let _ = core::CoreError::operation("transport");
        let _ = nip46::NIP46_BUNKER_URI_SCHEME;
    }
}
