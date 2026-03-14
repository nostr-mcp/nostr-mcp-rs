use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip44EncryptArgs {
    pub private_key: String,
    pub public_key: String,
    pub plaintext: String,
    pub version: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip44DecryptArgs {
    pub private_key: String,
    pub public_key: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip44EncryptResult {
    pub ciphertext: String,
    pub version: u8,
    pub peer_public_key_hex: String,
    pub peer_public_key_npub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip44DecryptResult {
    pub plaintext: String,
    pub version: u8,
    pub peer_public_key_hex: String,
    pub peer_public_key_npub: String,
}
