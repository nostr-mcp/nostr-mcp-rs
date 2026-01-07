use crate::error::CoreError;
use nostr::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyArgs {
    pub key: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct VerifyResult {
    pub input: String,
    pub key_type: KeyType,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Npub,
    Nsec,
    Hex,
    Invalid,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DerivePublicArgs {
    pub private_key: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DerivePublicResult {
    pub public_key_npub: String,
    pub public_key_hex: String,
}

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
                match (pk.to_bech32(), pk.to_hex()) {
                    (Ok(npub), hex) => VerifyResult {
                        input: key.to_string(),
                        key_type: KeyType::Nsec,
                        valid: true,
                        public_key_npub: Some(npub),
                        public_key_hex: Some(hex),
                        error: None,
                    },
                    (Err(e), _) => VerifyResult {
                        input: key.to_string(),
                        key_type: KeyType::Nsec,
                        valid: false,
                        public_key_npub: None,
                        public_key_hex: None,
                        error: Some(e.to_string()),
                    },
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
    } else if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        match PublicKey::from_hex(key) {
            Ok(pk) => match pk.to_bech32() {
                Ok(npub) => VerifyResult {
                    input: key.to_string(),
                    key_type: KeyType::Hex,
                    valid: true,
                    public_key_npub: Some(npub),
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

pub fn derive_public_from_private(
    private_key: &str,
) -> Result<DerivePublicResult, CoreError> {
    let private_key = private_key.trim();

    let keys = if private_key.starts_with("nsec1") {
        Keys::parse(private_key).map_err(|e| CoreError::invalid_input(e.to_string()))?
    } else if private_key.len() == 64 && private_key.chars().all(|c| c.is_ascii_hexdigit()) {
        let secret =
            SecretKey::from_hex(private_key).map_err(|e| CoreError::invalid_input(e.to_string()))?;
        Keys::new(secret)
    } else {
        return Err(CoreError::invalid_input(
            "Invalid private key format. Expected nsec1... or 64-character hex",
        ));
    };

    let public_key = keys.public_key();

    Ok(DerivePublicResult {
        public_key_npub: public_key.to_bech32().map_err(|e| CoreError::invalid_input(e.to_string()))?,
        public_key_hex: public_key.to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::{derive_public_from_private, verify_key, KeyType};
    use nostr::prelude::*;

    #[test]
    fn verify_key_accepts_npub() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let result = verify_key(&npub);

        assert!(result.valid);
        assert!(matches!(result.key_type, KeyType::Npub));
        assert_eq!(result.public_key_npub.as_deref(), Some(npub.as_str()));
        assert_eq!(result.public_key_hex.as_deref(), Some(keys.public_key().to_hex().as_str()));
    }

    #[test]
    fn verify_key_accepts_nsec() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let pubkey_npub = keys.public_key().to_bech32().unwrap();
        let result = verify_key(&nsec);

        assert!(result.valid);
        assert!(matches!(result.key_type, KeyType::Nsec));
        assert_eq!(result.public_key_npub.as_deref(), Some(pubkey_npub.as_str()));
        assert_eq!(result.public_key_hex.as_deref(), Some(keys.public_key().to_hex().as_str()));
    }

    #[test]
    fn verify_key_accepts_hex() {
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let pubkey_npub = keys.public_key().to_bech32().unwrap();
        let result = verify_key(&hex);

        assert!(result.valid);
        assert!(matches!(result.key_type, KeyType::Hex));
        assert_eq!(result.public_key_npub.as_deref(), Some(pubkey_npub.as_str()));
        assert_eq!(result.public_key_hex.as_deref(), Some(hex.as_str()));
    }

    #[test]
    fn derive_public_from_private_accepts_nsec_and_hex() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let hex = keys.secret_key().to_secret_hex();

        let derived_from_nsec = derive_public_from_private(&nsec).unwrap();
        assert_eq!(derived_from_nsec.public_key_hex, keys.public_key().to_hex());
        assert_eq!(
            derived_from_nsec.public_key_npub,
            keys.public_key().to_bech32().unwrap()
        );

        let derived_from_hex = derive_public_from_private(&hex).unwrap();
        assert_eq!(derived_from_hex.public_key_hex, keys.public_key().to_hex());
        assert_eq!(
            derived_from_hex.public_key_npub,
            keys.public_key().to_bech32().unwrap()
        );
    }

    #[test]
    fn derive_public_from_private_rejects_invalid_format() {
        let err = derive_public_from_private("not-a-key").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid private key format. Expected nsec1... or 64-character hex"
        );
    }
}
