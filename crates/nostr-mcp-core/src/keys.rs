use crate::error::CoreError;
use nostr::prelude::*;
use nostr_mcp_types::keys::{DerivePublicResult, KeyType, VerifyResult};

pub fn verify_key(key: &str) -> VerifyResult {
    let key = key.trim();

    if key.starts_with("npub1") {
        match PublicKey::from_bech32(key) {
            Ok(pk) => VerifyResult {
                input: key.to_string(),
                key_type: KeyType::Npub,
                valid: true,
                public_key_npub: Some(key.to_string()),
                public_key_hex: Some(pk.to_hex()),
                error: None,
            },
            Err(e) => VerifyResult {
                input: key.to_string(),
                key_type: KeyType::Npub,
                valid: false,
                public_key_npub: None,
                public_key_hex: None,
                error: Some(e.to_string()),
            },
        }
    } else if key.starts_with("nsec1") {
        match Keys::parse(key) {
            Ok(keys) => {
                let pk = keys.public_key();
                VerifyResult {
                    input: key.to_string(),
                    key_type: KeyType::Nsec,
                    valid: true,
                    public_key_npub: Some(public_key_npub(&pk)),
                    public_key_hex: Some(pk.to_hex()),
                    error: None,
                }
            }
            Err(e) => VerifyResult {
                input: key.to_string(),
                key_type: KeyType::Nsec,
                valid: false,
                public_key_npub: None,
                public_key_hex: None,
                error: Some(e.to_string()),
            },
        }
    } else if key.len() == 64 {
        match PublicKey::from_hex(key) {
            Ok(pk) => VerifyResult {
                input: key.to_string(),
                key_type: KeyType::Hex,
                valid: true,
                public_key_npub: Some(public_key_npub(&pk)),
                public_key_hex: Some(key.to_string()),
                error: None,
            },
            Err(e) => VerifyResult {
                input: key.to_string(),
                key_type: KeyType::Hex,
                valid: false,
                public_key_npub: None,
                public_key_hex: None,
                error: Some(e.to_string()),
            },
        }
    } else {
        VerifyResult {
            input: key.to_string(),
            key_type: KeyType::Invalid,
            valid: false,
            public_key_npub: None,
            public_key_hex: None,
            error: Some(
                "Unrecognized key format. Expected npub1..., nsec1..., or 64-character hex"
                    .to_string(),
            ),
        }
    }
}

pub fn derive_public(private_key: &str) -> Result<DerivePublicResult, CoreError> {
    let private_key = private_key.trim();

    let keys = if private_key.starts_with("nsec1") {
        Keys::parse(private_key).map_err(|e| CoreError::invalid_input(e.to_string()))?
    } else if private_key.len() == 64 && private_key.chars().all(|c| c.is_ascii_hexdigit()) {
        let secret = SecretKey::from_hex(private_key)
            .map_err(|e| CoreError::invalid_input(e.to_string()))?;
        Keys::new(secret)
    } else {
        return Err(CoreError::invalid_input(
            "Invalid private key format. Expected nsec1... or 64-character hex",
        ));
    };

    let public_key = keys.public_key();

    Ok(DerivePublicResult {
        public_key_npub: public_key_npub(&public_key),
        public_key_hex: public_key.to_hex(),
    })
}

#[cfg(test)]
mod tests;

fn public_key_npub(public_key: &PublicKey) -> String {
    match public_key.to_bech32() {
        Ok(npub) => npub,
        Err(never) => match never {},
    }
}
