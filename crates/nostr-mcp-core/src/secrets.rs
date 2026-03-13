use crate::error::CoreError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub trait SecretStore: Send + Sync {
    fn set(&self, label: &str, secret: &str) -> Result<(), CoreError>;
    fn get(&self, label: &str) -> Result<Option<String>, CoreError>;
    fn delete(&self, label: &str) -> Result<(), CoreError>;
}

#[derive(Clone, Default)]
pub struct InMemorySecretStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn set(&self, label: &str, secret: &str) -> Result<(), CoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| CoreError::invalid_input("secret store lock poisoned"))?;
        guard.insert(label.to_string(), secret.to_string());
        Ok(())
    }

    fn get(&self, label: &str) -> Result<Option<String>, CoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CoreError::invalid_input("secret store lock poisoned"))?;
        Ok(guard.get(label).cloned())
    }

    fn delete(&self, label: &str) -> Result<(), CoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| CoreError::invalid_input("secret store lock poisoned"))?;
        guard.remove(label);
        Ok(())
    }
}

#[cfg(feature = "keyring")]
#[derive(Clone, Debug)]
pub struct KeyringSecretStore {
    service: String,
}

#[cfg(feature = "keyring")]
impl KeyringSecretStore {
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    fn entry_for(&self, label: &str) -> Result<keyring::Entry, CoreError> {
        keyring::Entry::new(&self.service, label)
            .map_err(|e| CoreError::Keyring(format!("creating keyring entry: {e}")))
    }
}

#[cfg(feature = "keyring")]
impl SecretStore for KeyringSecretStore {
    fn set(&self, label: &str, secret: &str) -> Result<(), CoreError> {
        let entry = self.entry_for(label)?;
        entry
            .set_password(secret)
            .map_err(|e| CoreError::Keyring(format!("storing secret in keyring: {e}")))
    }

    fn get(&self, label: &str) -> Result<Option<String>, CoreError> {
        let entry = self.entry_for(label)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::Keyring(format!(
                "retrieving secret from keyring: {e}"
            ))),
        }
    }

    fn delete(&self, label: &str) -> Result<(), CoreError> {
        let entry = self.entry_for(label)?;
        match entry.delete_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::Keyring(format!(
                "deleting secret from keyring: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemorySecretStore, SecretStore};

    #[test]
    fn in_memory_store_round_trip() {
        let store = InMemorySecretStore::new();
        store.set("alice", "secret").unwrap();

        let fetched = store.get("alice").unwrap();
        assert_eq!(fetched.as_deref(), Some("secret"));

        store.delete("alice").unwrap();
        let missing = store.get("alice").unwrap();
        assert!(missing.is_none());
    }
}
