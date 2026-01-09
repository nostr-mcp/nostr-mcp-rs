use nostr_mcp_core::error::CoreError;
use std::path::{Path, PathBuf};

pub fn nostr_config_root() -> PathBuf {
    std::env::var_os("GOOSTR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
                .join("goostr")
        })
}

pub fn nostr_index_path() -> PathBuf {
    nostr_config_root().join("keys.enc")
}

pub fn nostr_settings_path() -> PathBuf {
    nostr_config_root().join("settings.enc")
}

pub fn legacy_keys_json_path() -> PathBuf {
    nostr_config_root().join("keys.json")
}

pub fn keystore_secret_path() -> PathBuf {
    nostr_config_root().join("keystore.secret")
}

pub fn ensure_keystore_secret() -> Result<Vec<u8>, CoreError> {
    let path = keystore_secret_path();
    nostr_mcp_core::keystore::ensure_keystore_secret(&path)
}

pub fn ensure_parent_dir(p: &Path) -> std::io::Result<()> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}
