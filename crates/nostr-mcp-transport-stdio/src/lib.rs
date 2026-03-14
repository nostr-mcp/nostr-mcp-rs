#![forbid(unsafe_code)]

use nostr_mcp_server::NostrMcpRuntime;
use nostr_mcp_tools::NostrMcpServer;
use rmcp::{ServiceExt, transport::stdio};
use tokio::time::{Duration, sleep};
use tracing::info;

fn default_stdio_runtime() -> NostrMcpRuntime {
    NostrMcpRuntime::default()
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

async fn initialized_stdio_server(
    runtime_config: NostrMcpRuntime,
) -> anyhow::Result<(String, NostrMcpServer)> {
    let server_name = runtime_config.server_name.clone();
    let server = NostrMcpServer::with_runtime(runtime_config);
    server.initialize().await?;
    Ok((server_name, server))
}

pub async fn start_stdio_server() -> anyhow::Result<()> {
    start_stdio_server_with_runtime(default_stdio_runtime()).await
}

pub async fn start_stdio_server_with_runtime(
    runtime_config: NostrMcpRuntime,
) -> anyhow::Result<()> {
    let (server_name, server) = initialized_stdio_server(runtime_config).await?;
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
    use super::{
        default_stdio_runtime, initialized_stdio_server, start_stdio_server,
        start_stdio_server_with_runtime,
    };
    use nostr_mcp_server::NostrMcpRuntime;
    use nostr_mcp_tools::NostrMcpServer;
    use rmcp::ServerHandler;
    use tempfile::tempdir;

    #[test]
    fn exports_stdio_entrypoints() {
        let _ = start_stdio_server;
        let _ = start_stdio_server_with_runtime;
    }

    #[test]
    fn default_stdio_runtime_matches_server_default_runtime() {
        assert_eq!(default_stdio_runtime(), NostrMcpRuntime::default());
    }

    #[tokio::test]
    async fn initialized_stdio_server_matches_direct_server_surface() {
        let runtime = NostrMcpRuntime::default();
        let (_server_name, adapter_server) =
            initialized_stdio_server(runtime.clone()).await.unwrap();

        let direct_server = NostrMcpServer::with_runtime(runtime);
        direct_server.initialize().await.unwrap();

        let adapter_info = ServerHandler::get_info(&adapter_server);
        let direct_info = ServerHandler::get_info(&direct_server);

        assert_eq!(adapter_info.protocol_version, direct_info.protocol_version);
        assert_eq!(adapter_info.capabilities, direct_info.capabilities);
        assert_eq!(adapter_info.server_info, direct_info.server_info);
        assert_eq!(adapter_info.instructions, direct_info.instructions);
    }

    #[tokio::test]
    async fn initialized_stdio_server_respects_runtime_configuration() {
        let dir = tempdir().unwrap();
        let config_root = dir.path().join("nostr-stdio");
        let runtime = NostrMcpRuntime::new("nostr-stdio", "nostr-stdio", config_root.clone());

        let (server_name, adapter_server) =
            initialized_stdio_server(runtime.clone()).await.unwrap();

        assert_eq!(server_name, runtime.server_name);
        assert!(config_root.join("keystore.secret").exists());

        let direct_server = NostrMcpServer::with_runtime(runtime);
        direct_server.initialize().await.unwrap();

        let adapter_info = ServerHandler::get_info(&adapter_server);
        let direct_info = ServerHandler::get_info(&direct_server);
        assert_eq!(adapter_info.instructions, direct_info.instructions);
    }
}
