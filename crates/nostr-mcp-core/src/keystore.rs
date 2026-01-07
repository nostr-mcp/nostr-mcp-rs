use crate::error::CoreError;
use crate::fs::ensure_parent_dir;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;

pub fn ensure_keystore_secret(path: &Path) -> Result<Vec<u8>, CoreError> {
    ensure_parent_dir(path)?;
    if !path.exists() {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        let b64 = B64.encode(buf);
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| CoreError::Io(format!("opening {}: {e}", path.display())))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        f.write_all(b64.as_bytes())
            .map_err(|e| CoreError::Io(format!("writing keystore secret: {e}")))?;
        let _ = f.flush();
    }

    let mut f = File::open(path)
        .map_err(|e| CoreError::Io(format!("opening {}: {e}", path.display())))?;
    let mut s = String::new();
    f.read_to_string(&mut s)
        .map_err(|e| CoreError::Io(format!("reading {}: {e}", path.display())))?;
    let bytes = B64
        .decode(s.trim())
        .map_err(|e| CoreError::Base64(format!("decoding keystore secret: {e}")))?;
    s.zeroize();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::ensure_keystore_secret;
    use tempfile::tempdir;

    #[test]
    fn ensure_keystore_secret_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.secret");

        let first = ensure_keystore_secret(&path).unwrap();
        let second = ensure_keystore_secret(&path).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
    }
}
