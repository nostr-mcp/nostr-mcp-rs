use std::path::PathBuf;

use nostr_mcp_policy::{
    AuthoringAction, CapabilityScope, EventKindScope, IdentityClass, RelayTargetScope,
    SignerBackend, SignerMethod, SignerPolicy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrMcpPaths {
    pub config_root: PathBuf,
    pub index_path: PathBuf,
    pub settings_path: PathBuf,
    pub keystore_secret_path: PathBuf,
}

impl NostrMcpPaths {
    pub fn from_root(config_root: PathBuf) -> Self {
        Self {
            index_path: config_root.join("keys.enc"),
            settings_path: config_root.join("settings.enc"),
            keystore_secret_path: config_root.join("keystore.secret"),
            config_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrMcpRuntime {
    pub server_name: String,
    pub keyring_service: String,
    pub paths: NostrMcpPaths,
    pub signer_policy: SignerPolicy,
    pub allow_local_key_test_support: bool,
}

impl NostrMcpRuntime {
    pub fn new<S, T>(server_name: S, keyring_service: T, config_root: PathBuf) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            server_name: server_name.into(),
            keyring_service: keyring_service.into(),
            paths: NostrMcpPaths::from_root(config_root),
            signer_policy: default_runtime_signer_policy(),
            allow_local_key_test_support: false,
        }
    }

    pub fn with_config_root(&self, config_root: PathBuf) -> Self {
        Self {
            server_name: self.server_name.clone(),
            keyring_service: self.keyring_service.clone(),
            paths: NostrMcpPaths::from_root(config_root),
            signer_policy: self.signer_policy.clone(),
            allow_local_key_test_support: self.allow_local_key_test_support,
        }
    }

    pub fn with_signer_policy(&self, signer_policy: SignerPolicy) -> Self {
        Self {
            server_name: self.server_name.clone(),
            keyring_service: self.keyring_service.clone(),
            paths: self.paths.clone(),
            signer_policy,
            allow_local_key_test_support: self.allow_local_key_test_support,
        }
    }

    pub fn with_local_key_test_support(&self, allow_local_key_test_support: bool) -> Self {
        Self {
            server_name: self.server_name.clone(),
            keyring_service: self.keyring_service.clone(),
            paths: self.paths.clone(),
            signer_policy: self.signer_policy.clone(),
            allow_local_key_test_support,
        }
    }
}

impl Default for NostrMcpRuntime {
    fn default() -> Self {
        Self::new("nostr-mcp", "nostr-mcp", default_config_root())
    }
}

pub fn default_config_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("nostr-mcp")
}

pub fn default_runtime_signer_policy() -> SignerPolicy {
    SignerPolicy {
        identity_class: IdentityClass::SignerBacked,
        signer_backend: SignerBackend::LocalTestOnly,
        capability_scopes: vec![
            CapabilityScope::ManageIdentity,
            CapabilityScope::ManageRelays,
            CapabilityScope::ManageMetadata,
            CapabilityScope::ManageFollows,
            CapabilityScope::ModerateGroups,
            CapabilityScope::BuildUnsignedEvents,
            CapabilityScope::PreviewEvents,
            CapabilityScope::SignEvents,
            CapabilityScope::PublishEvents,
            CapabilityScope::EncryptNip44,
            CapabilityScope::DecryptNip44,
        ],
        signer_methods: vec![
            SignerMethod::GetPublicKey,
            SignerMethod::SignEvent,
            SignerMethod::Nip44Encrypt,
            SignerMethod::Nip44Decrypt,
            SignerMethod::SwitchRelays,
        ],
        authoring_actions: vec![
            AuthoringAction::BuildUnsigned,
            AuthoringAction::Preview,
            AuthoringAction::Sign,
            AuthoringAction::Publish,
        ],
        event_kind_scope: EventKindScope::Any,
        relay_target_scope: RelayTargetScope::Any,
        ..SignerPolicy::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NostrMcpPaths, NostrMcpRuntime, default_config_root, default_runtime_signer_policy,
    };
    use nostr_mcp_policy::default_signer_policy;
    use std::path::PathBuf;

    #[test]
    fn default_runtime_is_host_neutral() {
        let runtime = NostrMcpRuntime::default();
        assert_eq!(runtime.server_name, "nostr-mcp");
        assert_eq!(runtime.keyring_service, "nostr-mcp");
        assert_eq!(
            runtime.paths,
            NostrMcpPaths::from_root(default_config_root())
        );
        assert_eq!(runtime.signer_policy, default_runtime_signer_policy());
        assert!(!runtime.allow_local_key_test_support);
        assert!(
            runtime
                .paths
                .config_root
                .ends_with(PathBuf::from(".config").join("nostr-mcp"))
        );
    }

    #[test]
    fn runtime_recomputes_paths_from_new_root() {
        let runtime = NostrMcpRuntime::new("host", "service", PathBuf::from("/tmp/original"));
        let updated = runtime.with_config_root(PathBuf::from("/tmp/custom"));

        assert_eq!(updated.server_name, "host");
        assert_eq!(updated.keyring_service, "service");
        assert_eq!(updated.paths.config_root, PathBuf::from("/tmp/custom"));
        assert_eq!(updated.signer_policy, runtime.signer_policy);
        assert_eq!(
            updated.allow_local_key_test_support,
            runtime.allow_local_key_test_support
        );
        assert_eq!(
            updated.paths.index_path,
            PathBuf::from("/tmp/custom/keys.enc")
        );
        assert_eq!(
            updated.paths.settings_path,
            PathBuf::from("/tmp/custom/settings.enc")
        );
        assert_eq!(
            updated.paths.keystore_secret_path,
            PathBuf::from("/tmp/custom/keystore.secret")
        );
    }

    #[test]
    fn runtime_can_override_signer_policy() {
        let runtime = NostrMcpRuntime::default();
        let strict = runtime.with_signer_policy(default_signer_policy());

        assert_eq!(strict.server_name, runtime.server_name);
        assert_eq!(strict.keyring_service, runtime.keyring_service);
        assert_eq!(strict.paths, runtime.paths);
        assert_eq!(strict.signer_policy, default_signer_policy());
        assert_eq!(
            strict.allow_local_key_test_support,
            runtime.allow_local_key_test_support
        );
    }

    #[test]
    fn runtime_can_enable_local_key_test_support() {
        let runtime = NostrMcpRuntime::default();
        let enabled = runtime.with_local_key_test_support(true);

        assert_eq!(enabled.server_name, runtime.server_name);
        assert_eq!(enabled.keyring_service, runtime.keyring_service);
        assert_eq!(enabled.paths, runtime.paths);
        assert_eq!(enabled.signer_policy, runtime.signer_policy);
        assert!(enabled.allow_local_key_test_support);
    }
}
