use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Nip46Error {
    #[error("invalid permission: {0}")]
    InvalidPermission(String),
    #[error("invalid uri: unsupported scheme `{0}`")]
    UnsupportedUriScheme(String),
    #[error("invalid uri: missing public key")]
    MissingPublicKey,
    #[error("invalid uri: missing relay")]
    MissingRelay,
    #[error("invalid uri: missing secret")]
    MissingSecret,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid relay url: {0}")]
    InvalidRelayUrl(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

impl Nip46Error {
    pub fn invalid_permission<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidPermission(message.into())
    }

    pub fn invalid_public_key<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidPublicKey(message.into())
    }

    pub fn invalid_relay_url<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidRelayUrl(message.into())
    }

    pub fn invalid_url<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidUrl(message.into())
    }
}
