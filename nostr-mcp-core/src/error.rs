use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("base64 error: {0}")]
    Base64(String),
    #[error("serde json error: {0}")]
    SerdeJson(String),
    #[error("keyring error: {0}")]
    Keyring(String),
}

impl CoreError {
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }
}
