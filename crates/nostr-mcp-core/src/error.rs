use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
}

impl CoreError {
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }

    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn operation<S: Into<String>>(msg: S) -> Self {
        Self::Operation(msg.into())
    }

    pub const fn is_invalid_input(&self) -> bool {
        matches!(self, Self::InvalidInput(_))
    }
}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn invalid_input_is_classified() {
        assert!(CoreError::invalid_input("bad input").is_invalid_input());
        assert!(!CoreError::crypto("encrypt failed").is_invalid_input());
        assert!(!CoreError::operation("send failed").is_invalid_input());
    }
}
