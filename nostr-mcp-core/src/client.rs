use crate::error::CoreError;
use crate::follows;
use crate::key_store::KeyStore;
use crate::settings::{KeySettings, SettingsStore};
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell, RwLock};

#[derive(Clone, Debug)]
pub struct ActiveClient {
    pub client: Client,
    pub active_label: String,
    pub active_pubkey: PublicKey,
}

static CLIENT_CELL: OnceCell<RwLock<Option<ActiveClient>>> = OnceCell::const_new();
static BUILD_LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();

async fn build_from_keystore(
    ks: &KeyStore,
    settings_store: &SettingsStore,
) -> Result<Option<ActiveClient>, CoreError> {
    let active = ks.get_active().await;
    let Some(active_entry) = active else {
        return Ok(None);
    };
    let label = active_entry.label.clone();
    let pubkey = PublicKey::from_bech32(&active_entry.public_key)
        .map_err(|e| CoreError::invalid_input(format!("invalid active public key: {e}")))?;

    let secrets = ks.secrets();
    let maybe_nsec = secrets.get(&label)?;
    let client = if let Some(nsec) = maybe_nsec {
        let keys = Keys::parse(&nsec)
            .map_err(|e| CoreError::invalid_input(format!("invalid stored secret for '{label}': {e}")))?;

        Client::builder()
            .signer(keys)
            .opts(ClientOptions::new().automatic_authentication(true))
            .build()
    } else {
        Client::builder()
            .opts(ClientOptions::new().automatic_authentication(true))
            .build()
    };

    let pubkey_hex = pubkey.to_hex();
    let settings = settings_store.get_settings(&pubkey_hex).await;

    if let Some(ref settings) = settings {
        if !settings.relays.is_empty() {
            for url in &settings.relays {
                let _ = client.add_relay(url).await;
            }
            client.connect().await;
        }
    }

    tokio::spawn({
        let client_clone = client.clone();
        let pubkey_clone = pubkey;
        let settings_store_clone = settings_store.clone();
        let pubkey_hex_clone = pubkey_hex.clone();
        async move {
            if let Some(settings) = settings {
                if !settings.relays.is_empty() {
                    if let Ok((synced_follows, _published)) =
                        follows::sync_follows(&client_clone, &pubkey_clone, settings.follows).await
                    {
                        let updated_settings = KeySettings {
                            relays: settings.relays,
                            metadata: settings.metadata,
                            follows: synced_follows,
                        };
                        let _ = settings_store_clone
                            .save_settings(pubkey_hex_clone, updated_settings)
                            .await;
                    }
                }
            }
        }
    });

    Ok(Some(ActiveClient {
        client,
        active_label: label,
        active_pubkey: pubkey,
    }))
}

pub async fn ensure_client(
    ks: Arc<KeyStore>,
    settings_store: Arc<SettingsStore>,
) -> Result<ActiveClient, CoreError> {
    let cell = CLIENT_CELL
        .get_or_try_init(|| async {
            Ok::<RwLock<Option<ActiveClient>>, CoreError>(RwLock::new(None))
        })
        .await?;
    {
        let r = cell.read().await;
        if let Some(ac) = r.clone() {
            let active = ks.get_active().await;
            if active.as_ref().map(|e| &e.label) == Some(&ac.active_label) {
                return Ok(ac);
            }
        }
    }
    let _g = BUILD_LOCK
        .get_or_try_init(|| async { Ok::<Mutex<()>, CoreError>(Mutex::new(())) })
        .await?
        .lock()
        .await;
    {
        let r = cell.read().await;
        if let Some(ac) = r.clone() {
            let active = ks.get_active().await;
            if active.as_ref().map(|e| &e.label) == Some(&ac.active_label) {
                return Ok(ac);
            }
        }
    }
    let built = build_from_keystore(&ks, &settings_store).await?;
    if let Some(ac) = built {
        {
            let mut w = cell.write().await;
            *w = Some(ac.clone());
        }
        Ok(ac)
    } else {
        Err(CoreError::invalid_input(
            "no active nostr key; set one with nostr_keys_set_active",
        ))
    }
}

pub async fn reset_cached_client() -> Result<(), CoreError> {
    if let Some(cell) = CLIENT_CELL.get() {
        let mut w = cell.write().await;
        *w = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_client;
    use crate::key_store::KeyStore;
    use crate::secrets::InMemorySecretStore;
    use crate::settings::SettingsStore;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn ensure_client_rejects_missing_active_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("keys.enc");
        let settings_path = dir.path().join("settings.enc");
        let pass = Arc::new(vec![1u8; 32]);
        let secrets = Arc::new(InMemorySecretStore::new());

        let ks = KeyStore::load_or_init(key_path, pass.clone(), secrets)
            .await
            .unwrap();
        let ss = SettingsStore::load_or_init(settings_path, pass).await.unwrap();

        let err = ensure_client(Arc::new(ks), Arc::new(ss)).await.unwrap_err();
        assert!(err.to_string().contains("no active nostr key"));
    }
}
