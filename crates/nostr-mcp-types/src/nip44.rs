use schemars::JsonSchema;
use serde::Deserialize;

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
