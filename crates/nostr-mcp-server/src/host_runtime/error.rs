use thiserror::Error;

pub type HostRuntimeResult<T> = Result<T, HostRuntimeError>;

#[derive(Debug, Error)]
pub enum HostRuntimeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("operation denied: {0}")]
    OperationDenied(String),
    #[error("operation timeout: {0}")]
    OperationTimeout(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[cfg(feature = "keyring")]
    #[error("keyring error: {0}")]
    Keyring(String),
}

impl HostRuntimeError {
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }

    pub fn io<S: Into<String>>(msg: S) -> Self {
        Self::Io(msg.into())
    }

    pub fn operation_denied<S: Into<String>>(msg: S) -> Self {
        Self::OperationDenied(msg.into())
    }

    pub fn operation_timeout<S: Into<String>>(msg: S) -> Self {
        Self::OperationTimeout(msg.into())
    }

    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn encoding<S: Into<String>>(msg: S) -> Self {
        Self::Encoding(msg.into())
    }

    pub fn serialization<S: Into<String>>(msg: S) -> Self {
        Self::Serialization(msg.into())
    }

    #[cfg(feature = "keyring")]
    pub fn keyring<S: Into<String>>(msg: S) -> Self {
        Self::Keyring(msg.into())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn is_invalid_input(&self) -> bool {
        matches!(self, Self::InvalidInput(_))
    }
}

#[cfg(test)]
mod tests {
    use super::HostRuntimeError;

    #[test]
    fn invalid_input_is_classified() {
        assert!(HostRuntimeError::invalid_input("bad input").is_invalid_input());
        assert!(!HostRuntimeError::io("disk").is_invalid_input());
        assert!(!HostRuntimeError::operation_denied("blocked").is_invalid_input());
        assert!(!HostRuntimeError::operation_timeout("slow").is_invalid_input());
    }

    #[test]
    fn error_display_remains_stable() {
        assert_eq!(
            HostRuntimeError::invalid_input("bad input").to_string(),
            "invalid input: bad input"
        );
        assert_eq!(HostRuntimeError::io("disk").to_string(), "io error: disk");
        assert_eq!(
            HostRuntimeError::operation_denied("blocked").to_string(),
            "operation denied: blocked"
        );
        assert_eq!(
            HostRuntimeError::operation_timeout("slow").to_string(),
            "operation timeout: slow"
        );
        assert_eq!(
            HostRuntimeError::crypto("cipher").to_string(),
            "crypto error: cipher"
        );
        assert_eq!(
            HostRuntimeError::encoding("bad base64").to_string(),
            "encoding error: bad base64"
        );
        assert_eq!(
            HostRuntimeError::serialization("bad json").to_string(),
            "serialization error: bad json"
        );
    }
}
