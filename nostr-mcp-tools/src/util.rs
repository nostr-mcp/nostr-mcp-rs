use nostr_mcp_core::error::CoreError;
use std::path::Path;

pub fn ensure_keystore_secret(path: &Path) -> Result<Vec<u8>, CoreError> {
    nostr_mcp_core::keystore::ensure_keystore_secret(path)
}
