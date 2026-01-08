use crate::error::CoreError;
use crate::secrets::SecretStore;
use crate::storage;
use crate::fs::ensure_parent_dir;
use chrono::Utc;
use nostr::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct KeyEntry {
    pub label: String,
    pub public_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct KeyFile {
    pub active: Option<String>,
    pub keys: BTreeMap<String, KeyEntry>,
}

#[derive(Clone)]
pub struct KeyStore {
    path: PathBuf,
    inner: Arc<RwLock<KeyFile>>,
    pass: Arc<Vec<u8>>,
    secrets: Arc<dyn SecretStore>,
}

impl KeyStore {
    pub async fn load_or_init(
        path: PathBuf,
        pass: Arc<Vec<u8>>,
        secrets: Arc<dyn SecretStore>,
        legacy_json_path: Option<PathBuf>,
    ) -> Result<Self, CoreError> {
        ensure_parent_dir(&path)?;
        let data = if path.exists() {
            storage::decrypt_from_file::<KeyFile>(&path, &pass)?
        } else if let Some(legacy_path) = legacy_json_path.filter(|p| p.exists()) {
            let s = fs::read_to_string(&legacy_path)
                .map_err(|e| CoreError::Io(format!("reading {}: {e}", legacy_path.display())))?;
            let legacy: KeyFile = serde_json::from_str(&s)
                .map_err(|e| CoreError::SerdeJson(format!("parse legacy keys: {e}")))?;
            storage::encrypt_to_file(&path, &pass, &legacy)?;
            let _ = fs::remove_file(&legacy_path);
            legacy
        } else {
            KeyFile::default()
        };
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(data)),
            pass,
            secrets,
        })
    }

    pub async fn persist(&self) -> Result<(), CoreError> {
        let data = { self.inner.read().await.clone() };
        storage::encrypt_to_file(&self.path, &self.pass, &data)
    }

    pub async fn list(&self) -> Vec<KeyEntry> {
        let data = self.inner.read().await;
        data.keys.values().cloned().collect()
    }

    pub async fn get_active(&self) -> Option<KeyEntry> {
        let data = self.inner.read().await;
        match &data.active {
            Some(label) => data.keys.get(label).cloned(),
            None => None,
        }
    }

    pub async fn set_active(&self, label: String) -> Result<KeyEntry, CoreError> {
        let mut data = self.inner.write().await;
        if !data.keys.contains_key(&label) {
            return Err(CoreError::invalid_input("unknown key label"));
        }
        data.active = Some(label.clone());
        let entry = data.keys.get(&label).cloned().ok_or_else(|| {
            CoreError::invalid_input("unknown key label")
        })?;
        drop(data);
        self.persist().await?;
        Ok(entry)
    }

    pub async fn remove(&self, label: String) -> Result<Option<KeyEntry>, CoreError> {
        let mut data = self.inner.write().await;
        let removed = data.keys.remove(&label);
        if data.active.as_deref() == Some(&label) {
            data.active = None;
        }
        drop(data);
        self.persist().await?;
        let _ = self.secrets.delete(&label);
        Ok(removed)
    }

    pub async fn import_secret(
        &self,
        label: String,
        secret: String,
        make_active: bool,
        persist_secret: bool,
    ) -> Result<KeyEntry, CoreError> {
        let keys = if secret.starts_with("nsec1") || secret.starts_with("npub1") {
            Keys::parse(&secret).map_err(|e| CoreError::invalid_input(e.to_string()))?
        } else {
            return Err(CoreError::invalid_input("unsupported key material"));
        };
        self.insert_keys(label, keys, make_active, persist_secret)
            .await
    }

    pub async fn generate(
        &self,
        label: String,
        make_active: bool,
        persist_secret: bool,
    ) -> Result<KeyEntry, CoreError> {
        let keys = Keys::generate();
        self.insert_keys(label, keys, make_active, persist_secret)
            .await
    }

    async fn insert_keys(
        &self,
        label: String,
        keys: Keys,
        make_active: bool,
        persist_secret: bool,
    ) -> Result<KeyEntry, CoreError> {
        let public_key = keys
            .public_key()
            .to_bech32()
            .map_err(|e| CoreError::invalid_input(e.to_string()))?;
        if persist_secret {
            let mut sk = keys
                .secret_key()
                .to_bech32()
                .map_err(|e| CoreError::invalid_input(e.to_string()))?;
            self.secrets.set(&label, &sk)?;
            sk.zeroize();
        }
        let entry = KeyEntry {
            label: label.clone(),
            public_key,
            created_at: Utc::now().timestamp(),
        };
        let mut data = self.inner.write().await;
        data.keys.insert(label.clone(), entry.clone());
        if make_active {
            data.active = Some(label);
        }
        drop(data);
        self.persist().await?;
        Ok(entry)
    }

    pub async fn rename_label(&self, from: String, to: String) -> Result<KeyEntry, CoreError> {
        if from == to {
            return Err(CoreError::invalid_input("new label must be different"));
        }
        let mut data = self.inner.write().await;
        if !data.keys.contains_key(&from) {
            return Err(CoreError::invalid_input("unknown key label"));
        }
        if data.keys.contains_key(&to) {
            return Err(CoreError::invalid_input("label already exists"));
        }
        let mut entry = data
            .keys
            .remove(&from)
            .ok_or_else(|| CoreError::invalid_input("unknown key label"))?;
        entry.label = to.clone();
        data.keys.insert(to.clone(), entry.clone());
        if data.active.as_deref() == Some(&from) {
            data.active = Some(to.clone());
        }
        drop(data);
        self.persist().await?;
        if let Some(sk) = self.secrets.get(&from)? {
            let _ = self.secrets.delete(&from);
            self.secrets.set(&to, &sk)?;
        }
        Ok(entry)
    }

    pub async fn export_key(
        &self,
        label: Option<String>,
        format: ExportFormat,
        include_private: bool,
    ) -> Result<ExportResult, CoreError> {
        let target_label = match label {
            Some(l) => l,
            None => {
                let active = self.get_active().await.ok_or_else(|| {
                    CoreError::invalid_input("no active key; specify label or set active key")
                })?;
                active.label
            }
        };

        let data = self.inner.read().await;
        let entry = data.keys.get(&target_label).ok_or_else(|| {
            CoreError::invalid_input(format!("key not found: {}", target_label))
        })?;

        let public_key_bech32 = entry.public_key.clone();
        let public_key = PublicKey::from_bech32(&public_key_bech32)
            .map_err(|e| CoreError::invalid_input(e.to_string()))?;

        let mut result = ExportResult {
            label: target_label.clone(),
            public_key_npub: public_key_bech32.clone(),
            public_key_hex: public_key.to_hex(),
            private_key_nsec: None,
            private_key_hex: None,
            warning: None,
        };

        if include_private {
            let secret = self.secrets.get(&target_label)?.ok_or_else(|| {
                CoreError::invalid_input(format!(
                    "private key not found in secure storage for key: {}",
                    target_label
                ))
            })?;

            let keys = Keys::parse(&secret)
                .map_err(|e| CoreError::invalid_input(e.to_string()))?;

            match format {
                ExportFormat::Bech32 => {
                    result.private_key_nsec = Some(
                        keys.secret_key()
                            .to_bech32()
                            .map_err(|e| CoreError::invalid_input(e.to_string()))?,
                    );
                }
                ExportFormat::Hex => {
                    result.private_key_hex = Some(keys.secret_key().to_secret_hex());
                }
                ExportFormat::Both => {
                    result.private_key_nsec = Some(
                        keys.secret_key()
                            .to_bech32()
                            .map_err(|e| CoreError::invalid_input(e.to_string()))?,
                    );
                    result.private_key_hex = Some(keys.secret_key().to_secret_hex());
                }
            }

            result.warning = Some(
                "WARNING: This export contains your private key. Keep it secure and never share it. Anyone with access to this key can control your Nostr identity.".to_string()
            );
        }

        Ok(result)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateArgs {
    pub label: String,
    pub make_active: Option<bool>,
    pub persist_secret: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImportArgs {
    pub label: String,
    pub key_material: String,
    pub make_active: Option<bool>,
    pub persist_secret: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveArgs {
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetActiveArgs {
    pub label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameLabelArgs {
    pub from: Option<String>,
    pub to: String,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct EmptyArgs {}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Bech32,
    Hex,
    Both,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExportResult {
    pub label: String,
    pub public_key_npub: String,
    pub public_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_nsec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportArgs {
    pub label: Option<String>,
    #[serde(default = "default_export_format")]
    pub format: ExportFormat,
    #[serde(default)]
    pub include_private: bool,
}

fn default_export_format() -> ExportFormat {
    ExportFormat::Bech32
}

#[cfg(test)]
mod tests {
    use super::{ExportFormat, KeyStore};
    use crate::secrets::InMemorySecretStore;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn keystore_generate_and_export() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.enc");
        let pass = Arc::new(b"passphrase".to_vec());
        let secrets = Arc::new(InMemorySecretStore::new());

        let store = KeyStore::load_or_init(path, pass, secrets, None)
            .await
            .unwrap();

        let entry = store.generate("alice".to_string(), true, true).await.unwrap();
        assert_eq!(entry.label, "alice");

        let exported = store
            .export_key(Some("alice".to_string()), ExportFormat::Both, true)
            .await
            .unwrap();

        assert!(exported.private_key_nsec.is_some());
        assert!(exported.private_key_hex.is_some());

        let renamed = store
            .rename_label("alice".to_string(), "bob".to_string())
            .await
            .unwrap();
        assert_eq!(renamed.label, "bob");

        let exported_again = store
            .export_key(Some("bob".to_string()), ExportFormat::Bech32, true)
            .await
            .unwrap();
        assert!(exported_again.private_key_nsec.is_some());
    }
}
