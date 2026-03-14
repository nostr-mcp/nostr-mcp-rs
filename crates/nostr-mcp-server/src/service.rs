use std::sync::Arc;

use crate::host_runtime::client::{ActiveClient, ClientStore};
use crate::host_runtime::error::{HostRuntimeError, HostRuntimeResult};
use crate::host_runtime::key_store::KeyStore;
#[cfg(not(feature = "keyring"))]
use crate::host_runtime::secrets::InMemorySecretStore;
#[cfg(feature = "keyring")]
use crate::host_runtime::secrets::KeyringSecretStore;
use crate::host_runtime::secrets::SecretStore;
use crate::host_runtime::settings::SettingsStore;
use crate::runtime::{NostrMcpPaths, NostrMcpRuntime};
use crate::util;
use nostr_mcp_policy::{
    AuthoringAction, CapabilityScope, IdentityClass, PolicyDecision, PolicyDecisionEffect,
    PolicyRequest, SignerBackend, SignerMethod, SignerPolicy,
};
use tokio::sync::OnceCell;

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
) -> HostRuntimeResult<KeyStore> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    KeyStore::load_or_init(
        paths.index_path.clone(),
        pass,
        secret_store(runtime),
        runtime.allow_local_key_test_support,
    )
    .await
}

async fn load_or_init_settings(paths: &NostrMcpPaths) -> HostRuntimeResult<SettingsStore> {
    let pass = Arc::new(util::ensure_keystore_secret(
        paths.keystore_secret_path.as_path(),
    )?);
    SettingsStore::load_or_init(paths.settings_path.clone(), pass).await
}

struct ServerStores {
    keystore: Arc<KeyStore>,
    settings_store: Arc<SettingsStore>,
}

#[derive(Debug)]
pub enum NostrMcpServerServiceError {
    HostRuntime(HostRuntimeError),
    PolicyDecision(PolicyDecision),
}

impl From<HostRuntimeError> for NostrMcpServerServiceError {
    fn from(err: HostRuntimeError) -> Self {
        Self::HostRuntime(err)
    }
}

pub struct NostrMcpServerServices {
    runtime: NostrMcpRuntime,
    stores: OnceCell<ServerStores>,
    client_store: ClientStore,
}

impl NostrMcpServerServices {
    pub fn new(runtime: NostrMcpRuntime) -> Self {
        Self {
            runtime,
            stores: OnceCell::const_new(),
            client_store: ClientStore::new(),
        }
    }

    pub fn runtime(&self) -> &NostrMcpRuntime {
        &self.runtime
    }

    pub async fn initialize(&self) -> HostRuntimeResult<()> {
        self.stores().await?;
        Ok(())
    }

    pub fn configured_signer_backend(&self) -> SignerBackend {
        self.runtime.signer_policy.signer_backend
    }

    pub fn local_key_test_support_enabled(&self) -> bool {
        self.runtime.allow_local_key_test_support
    }

    pub fn required_signing_identity_class(&self) -> IdentityClass {
        match self.configured_signer_backend() {
            SignerBackend::Nip46Remote => IdentityClass::RemoteSignerSession,
            SignerBackend::LocalTestOnly => IdentityClass::SignerBacked,
        }
    }

    pub fn capability_request(&self, capability_scope: CapabilityScope) -> PolicyRequest {
        PolicyRequest {
            capability_scope: Some(capability_scope),
            ..PolicyRequest::default()
        }
    }

    pub fn raw_secret_request(
        &self,
        capability_scope: CapabilityScope,
        signer_method: Option<SignerMethod>,
    ) -> PolicyRequest {
        PolicyRequest {
            capability_scope: Some(capability_scope),
            signer_method,
            required_signer_backend: Some(SignerBackend::LocalTestOnly),
            ..PolicyRequest::default()
        }
    }

    pub fn authoring_request(
        &self,
        capability_scope: CapabilityScope,
        authoring_action: AuthoringAction,
        signer_method: Option<SignerMethod>,
        event_kind: Option<u16>,
        relay_targets: Option<Vec<String>>,
    ) -> PolicyRequest {
        let request = PolicyRequest {
            capability_scope: Some(capability_scope),
            signer_method,
            authoring_action: Some(authoring_action),
            event_kind,
            required_identity_class: authoring_action
                .requires_signer()
                .then(|| self.required_signing_identity_class()),
            required_signer_backend: authoring_action
                .requires_signer()
                .then(|| self.configured_signer_backend()),
            ..PolicyRequest::default()
        };
        relay_targets.map_or(request.clone(), |targets| {
            request.with_relay_targets(targets)
        })
    }

    pub async fn effective_signer_policy(&self) -> HostRuntimeResult<SignerPolicy> {
        let mut policy = self.runtime.signer_policy.clone();

        if matches!(policy.signer_backend, SignerBackend::LocalTestOnly) {
            if !self.local_key_test_support_enabled() {
                policy.identity_class = IdentityClass::WatchOnly;
                return Ok(policy);
            }
            let keystore = self.keystore().await?;
            let active = keystore.get_active().await;
            let has_secret = match active {
                Some(active_key) => keystore.secrets().get(&active_key.label)?.is_some(),
                None => false,
            };
            policy.identity_class = if has_secret {
                IdentityClass::SignerBacked
            } else {
                IdentityClass::WatchOnly
            };
        }

        Ok(policy)
    }

    pub async fn authorize_policy_request(
        &self,
        request: PolicyRequest,
    ) -> Result<(), NostrMcpServerServiceError> {
        let policy = self.effective_signer_policy().await?;
        let decision = policy.evaluate_request(request);
        match decision.effect {
            PolicyDecisionEffect::Allow => Ok(()),
            PolicyDecisionEffect::Deny | PolicyDecisionEffect::Escalate => {
                Err(NostrMcpServerServiceError::PolicyDecision(decision))
            }
        }
    }

    pub async fn keystore(&self) -> HostRuntimeResult<Arc<KeyStore>> {
        let stores = self.stores().await?;
        Ok(stores.keystore.clone())
    }

    pub async fn settings_store(&self) -> HostRuntimeResult<Arc<SettingsStore>> {
        let stores = self.stores().await?;
        Ok(stores.settings_store.clone())
    }

    pub fn ensure_local_key_test_support(&self) -> HostRuntimeResult<()> {
        if self.local_key_test_support_enabled() {
            return Ok(());
        }
        Err(HostRuntimeError::operation_denied(
            "local key test support is disabled",
        ))
    }

    pub async fn ensure_client_from(
        &self,
        keystore: Arc<KeyStore>,
        settings_store: Arc<SettingsStore>,
    ) -> HostRuntimeResult<ActiveClient> {
        self.client_store
            .ensure_client(keystore, settings_store)
            .await
    }

    pub async fn reset_client(&self) -> HostRuntimeResult<()> {
        self.client_store.reset().await
    }

    #[cfg(test)]
    pub async fn client(&self) -> HostRuntimeResult<ActiveClient> {
        let stores = self.stores().await?;
        self.ensure_client_from(stores.keystore.clone(), stores.settings_store.clone())
            .await
    }

    async fn stores(&self) -> HostRuntimeResult<&ServerStores> {
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
