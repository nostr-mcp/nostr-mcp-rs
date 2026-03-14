use super::{NostrMcpServer, core_error, host_runtime_error};
use nostr_mcp_core::keys::{derive_public, verify_key};
use nostr_mcp_policy::{CapabilityScope, SignerMethod};
use nostr_mcp_types::common::EmptyArgs;
use nostr_mcp_types::key_store::{
    ExportArgs, GenerateArgs, ImportArgs, KeyRemovalResult, KeysListResult, RemoveArgs,
    RenameLabelArgs, SetActiveArgs,
};
use nostr_mcp_types::keys::{DerivePublicArgs, VerifyArgs};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ErrorData},
    tool, tool_router,
};

#[tool_router(router = key_tool_router, vis = "pub(crate)")]
impl NostrMcpServer {
    #[tool(description = "Generate a new Nostr keypair")]
    pub async fn nostr_keys_generate(
        &self,
        Parameters(args): Parameters<GenerateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(
            self.raw_secret_request(CapabilityScope::ManageIdentity, None),
        )
        .await?;
        self.ensure_local_key_test_support()?;
        let keystore = self.keystore().await?;
        let entry = keystore
            .generate(
                args.label,
                args.make_active.unwrap_or(true),
                args.persist_secret.unwrap_or(true),
            )
            .await
            .map_err(host_runtime_error)?;
        self.reset_client().await?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Import key material (nsec or npub). npub imports are watch-only and do not enable signing."
    )]
    pub async fn nostr_keys_import(
        &self,
        Parameters(args): Parameters<ImportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(
            self.raw_secret_request(CapabilityScope::ManageIdentity, None),
        )
        .await?;
        if args.key_material.trim().starts_with("nsec1") {
            self.ensure_local_key_test_support()?;
        }
        let keystore = self.keystore().await?;
        let entry = keystore
            .import_secret(
                args.label,
                args.key_material,
                args.make_active.unwrap_or(true),
                args.persist_secret.unwrap_or(true),
            )
            .await
            .map_err(host_runtime_error)?;
        self.reset_client().await?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Remove a key by label")]
    pub async fn nostr_keys_remove(
        &self,
        Parameters(args): Parameters<RemoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(self.capability_request(CapabilityScope::ManageIdentity))
            .await?;
        let keystore = self.keystore().await?;
        let removed = keystore
            .remove(args.label)
            .await
            .map_err(host_runtime_error)?;
        self.reset_client().await?;
        let content = Content::json(serde_json::json!(KeyRemovalResult {
            removed: removed.is_some(),
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "List all stored keys (metadata only)")]
    pub async fn nostr_keys_list(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let keys = keystore.list().await;
        let active_label = keystore.get_active().await.map(|key| key.label);
        let count = keys.len();
        let content = Content::json(serde_json::json!(KeysListResult {
            keys,
            count,
            active: active_label,
        }))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Set the active key by label")]
    pub async fn nostr_keys_set_active(
        &self,
        Parameters(args): Parameters<SetActiveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(self.capability_request(CapabilityScope::ManageIdentity))
            .await?;
        let keystore = self.keystore().await?;
        let entry = keystore
            .set_active(args.label)
            .await
            .map_err(host_runtime_error)?;
        self.reset_client().await?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Get the active key (metadata only)")]
    pub async fn nostr_keys_get_active(
        &self,
        _args: Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let keystore = self.keystore().await?;
        let active = keystore.get_active().await;
        let content = Content::json(serde_json::json!(active))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(description = "Rename a key's label; when 'from' is omitted, renames the active key")]
    pub async fn nostr_keys_rename_label(
        &self,
        Parameters(args): Parameters<RenameLabelArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(self.capability_request(CapabilityScope::ManageIdentity))
            .await?;
        let keystore = self.keystore().await?;
        let source = match args.from {
            Some(label) => label,
            None => keystore
                .get_active()
                .await
                .map(|key| key.label)
                .ok_or_else(|| ErrorData::invalid_params("no active key to rename", None))?,
        };
        let entry = keystore
            .rename_label(source, args.to)
            .await
            .map_err(host_runtime_error)?;
        self.reset_client().await?;
        let content = Content::json(serde_json::json!(entry))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Export a key in various formats (npub/nsec/hex). Exports active key if label not specified. WARNING: include_private=true will expose your private key"
    )]
    pub async fn nostr_keys_export(
        &self,
        Parameters(args): Parameters<ExportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let request = if args.include_private {
            self.raw_secret_request(
                CapabilityScope::ManageIdentity,
                Some(SignerMethod::GetPublicKey),
            )
        } else {
            self.capability_request(CapabilityScope::ManageIdentity)
        };
        self.authorize_policy_request(request).await?;
        if args.include_private {
            self.ensure_local_key_test_support()?;
        }
        let keystore = self.keystore().await?;
        let result = keystore
            .export_key(args.label, args.format, args.include_private)
            .await
            .map_err(host_runtime_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Verify a Nostr key format and validity. Checks if a string is a valid npub, nsec, or hex key"
    )]
    pub async fn nostr_keys_verify(
        &self,
        Parameters(args): Parameters<VerifyArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = verify_key(&args.key);
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }

    #[tool(
        description = "Derive public key from a private key. Accepts nsec or hex private key format"
    )]
    pub async fn nostr_keys_derive_public(
        &self,
        Parameters(args): Parameters<DerivePublicArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.authorize_policy_request(self.raw_secret_request(
            CapabilityScope::ManageIdentity,
            Some(SignerMethod::GetPublicKey),
        ))
        .await?;
        self.ensure_local_key_test_support()?;
        let result = derive_public(&args.private_key).map_err(core_error)?;
        let content = Content::json(serde_json::json!(result))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
