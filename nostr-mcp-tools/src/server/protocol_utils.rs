use super::{core_error, NostrMcpServer};
use nostr_mcp_core::nip05::{resolve_nip05, verify_nip05, Nip05ResolveArgs, Nip05VerifyArgs};
use nostr_mcp_core::nip44::{decrypt_nip44, encrypt_nip44, Nip44DecryptArgs, Nip44EncryptArgs};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

#[tool_router(router = protocol_utility_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    #[tool(
        description = "Resolve a NIP-05 identifier (name@domain) to a pubkey and relay hints. Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_nip05_resolve(
        &self,
        Parameters(args): Parameters<Nip05ResolveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = resolve_nip05(args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Verify a NIP-05 identifier against a pubkey (npub or 64-char hex). Optional: timeout_secs (default: 10)."
    )]
    pub async fn nostr_nip05_verify(
        &self,
        Parameters(args): Parameters<Nip05VerifyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = verify_nip05(args).await.map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Encrypt plaintext using NIP-44.")]
    pub async fn nostr_nip44_encrypt(
        &self,
        Parameters(args): Parameters<Nip44EncryptArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = encrypt_nip44(args).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Decrypt ciphertext using NIP-44.")]
    pub async fn nostr_nip44_decrypt(
        &self,
        Parameters(args): Parameters<Nip44DecryptArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = decrypt_nip44(args).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
