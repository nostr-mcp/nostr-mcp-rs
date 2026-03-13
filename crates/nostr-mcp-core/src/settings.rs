use crate::error::CoreError;
use crate::storage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub struct ProfileMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud06: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FollowEntry {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub petname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub struct KeySettings {
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProfileMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub follows: Vec<FollowEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct SettingsFile {
    pub settings: BTreeMap<String, KeySettings>,
}

#[derive(Clone)]
pub struct SettingsStore {
    path: PathBuf,
    inner: Arc<RwLock<SettingsFile>>,
    pass: Arc<Vec<u8>>,
}

impl SettingsStore {
    pub async fn load_or_init(path: PathBuf, pass: Arc<Vec<u8>>) -> Result<Self, CoreError> {
        let data = if path.exists() {
            storage::decrypt_from_file::<SettingsFile>(&path, &pass)?
        } else {
            SettingsFile::default()
        };

        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(data)),
            pass,
        })
    }

    pub async fn persist(&self) -> Result<(), CoreError> {
        let data = { self.inner.read().await.clone() };
        storage::encrypt_to_file(&self.path, &self.pass, &data)
    }

    pub async fn get_settings(&self, pubkey_hex: &str) -> Option<KeySettings> {
        let data = self.inner.read().await;
        data.settings.get(pubkey_hex).cloned()
    }

    pub async fn save_settings(
        &self,
        pubkey_hex: String,
        settings: KeySettings,
    ) -> Result<(), CoreError> {
        {
            let mut data = self.inner.write().await;
            data.settings.insert(pubkey_hex, settings);
        }
        self.persist().await
    }

    pub async fn remove_settings(&self, pubkey_hex: &str) -> Result<(), CoreError> {
        {
            let mut data = self.inner.write().await;
            data.settings.remove(pubkey_hex);
        }
        self.persist().await
    }

    pub async fn all_settings(&self) -> BTreeMap<String, KeySettings> {
        let data = self.inner.read().await;
        data.settings.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeySettings, SettingsStore};
    use crate::keystore::ensure_keystore_secret;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn settings_round_trip() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("keystore.secret");
        let pass = Arc::new(ensure_keystore_secret(&secret_path).unwrap());

        let settings_path = dir.path().join("settings.enc");
        let store = SettingsStore::load_or_init(settings_path.clone(), pass.clone())
            .await
            .unwrap();

        let initial = store.get_settings("pubkey").await;
        assert!(initial.is_none());

        let settings = KeySettings {
            relays: vec!["wss://relay.example".to_string()],
            metadata: None,
            follows: Vec::new(),
        };
        store
            .save_settings("pubkey".to_string(), settings.clone())
            .await
            .unwrap();

        let updated = store.get_settings("pubkey").await;
        assert_eq!(updated, Some(settings));

        let reloaded = SettingsStore::load_or_init(settings_path, pass)
            .await
            .unwrap();
        let persisted = reloaded.get_settings("pubkey").await;
        assert!(persisted.is_some());
    }
}
