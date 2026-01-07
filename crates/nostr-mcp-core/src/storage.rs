use crate::error::CoreError;
use crate::fs::ensure_parent_dir;
use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"GSK1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

fn derive_key(pass: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], CoreError> {
    use argon2::Argon2;
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(pass, salt, &mut key)
        .map_err(|e| CoreError::Crypto(format!("kdf: {e}")))?;
    Ok(key)
}

pub fn encrypt_to_file<T: serde::Serialize>(
    path: &Path,
    pass: &[u8],
    value: &T,
) -> Result<(), CoreError> {
    ensure_parent_dir(path)?;
    let json = serde_json::to_vec(value)
        .map_err(|e| CoreError::SerdeJson(format!("serialize: {e}")))?;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(pass, &salt)?;
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, json.as_slice())
        .map_err(|e| CoreError::Crypto(format!("encrypt: {e}")))?;

    let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(1u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    let b64 = B64.encode(out);
    let mut f = fs::File::create(path)
        .map_err(|e| CoreError::Io(format!("create {}: {e}", path.display())))?;
    f.write_all(b64.as_bytes())
        .map_err(|e| CoreError::Io(format!("write {}: {e}", path.display())))?;
    let _ = f.flush();

    let mut z = [0u8; KEY_LEN];
    z.copy_from_slice(&key);
    z.zeroize();
    Ok(())
}

pub fn decrypt_from_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    pass: &[u8],
) -> Result<T, CoreError> {
    let b64 = fs::read_to_string(path)
        .map_err(|e| CoreError::Io(format!("read {}: {e}", path.display())))?;
    let data = B64
        .decode(b64.as_bytes())
        .map_err(|e| CoreError::Base64(format!("base64 decode: {e}")))?;
    if data.len() < 4 + 1 + SALT_LEN + NONCE_LEN {
        return Err(CoreError::invalid_input("file too short"));
    }
    if &data[0..4] != MAGIC {
        return Err(CoreError::invalid_input("bad magic"));
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce_slice = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let ct = &data[5 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(pass, salt)?;
    let cipher = Aes256Gcm::new((&key).into());

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_slice);
    let nonce = Nonce::from(nonce_arr);

    let pt = cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|e| CoreError::Crypto(format!("decrypt: {e}")))?;
    let val = serde_json::from_slice::<T>(&pt)
        .map_err(|e| CoreError::SerdeJson(format!("parse json: {e}")))?;

    let mut z = [0u8; KEY_LEN];
    z.copy_from_slice(&key);
    z.zeroize();
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::{decrypt_from_file, encrypt_to_file};
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SampleData {
        name: String,
        count: u64,
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.enc");
        let pass = b"test-passphrase";
        let data = SampleData {
            name: "nostr".to_string(),
            count: 7,
        };

        encrypt_to_file(&path, pass, &data).unwrap();
        let decoded: SampleData = decrypt_from_file(&path, pass).unwrap();
        assert_eq!(decoded, data);
    }
}
