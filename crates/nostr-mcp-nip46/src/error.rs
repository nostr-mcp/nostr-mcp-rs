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
    #[error("invalid json: {0}")]
    InvalidJson(String),
    #[error("unsupported method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid message: missing request id")]
    MissingRequestId,
    #[error("invalid message: expected request")]
    ExpectedRequestMessage,
    #[error("invalid message: expected response")]
    ExpectedResponseMessage,
    #[error("invalid timeout seconds: expected a positive bounded timeout, received `{0}`")]
    InvalidTimeoutSeconds(u64),
    #[error("invalid params for `{method}`: expected {expected}, received {received}")]
    InvalidParamsLength {
        method: String,
        expected: String,
        received: usize,
    },
    #[error("response error: {0}")]
    ResponseError(String),
    #[error("unexpected response id: expected `{expected}`, received `{received}`")]
    UnexpectedResponseId { expected: String, received: String },
    #[error("unexpected remote signer public key: expected `{expected}`, received `{received}`")]
    UnexpectedRemoteSignerPublicKey { expected: String, received: String },
    #[error("unexpected response for `{method}`: expected `{expected}`, received `{received}`")]
    UnexpectedResponseValue {
        method: String,
        expected: String,
        received: String,
    },
    #[error("request timed out for `{method}` with id `{request_id}`")]
    RequestTimedOut { method: String, request_id: String },
    #[error("replayed response for `{method}` with id `{request_id}`")]
    RequestReplayed { method: String, request_id: String },
    #[error("invalid connect flow: {0}")]
    InvalidConnectFlow(String),
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

    pub fn invalid_json<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidJson(message.into())
    }

    pub fn unsupported_method<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::UnsupportedMethod(message.into())
    }

    pub fn invalid_params_length<S, T>(method: S, expected: T, received: usize) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self::InvalidParamsLength {
            method: method.into(),
            expected: expected.into(),
            received,
        }
    }

    pub const fn invalid_timeout_seconds(received: u64) -> Self {
        Self::InvalidTimeoutSeconds(received)
    }

    pub fn response_error<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::ResponseError(message.into())
    }

    pub fn unexpected_response_value<S, T, U>(method: S, expected: T, received: U) -> Self
    where
        S: Into<String>,
        T: Into<String>,
        U: Into<String>,
    {
        Self::UnexpectedResponseValue {
            method: method.into(),
            expected: expected.into(),
            received: received.into(),
        }
    }

    pub fn invalid_connect_flow<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::InvalidConnectFlow(message.into())
    }

    pub fn request_timed_out(
        method: crate::permission::Nip46Method,
        request_id: crate::message::Nip46RequestId,
    ) -> Self {
        Self::RequestTimedOut {
            method: method.to_string(),
            request_id: request_id.to_string(),
        }
    }

    pub fn request_replayed(
        method: crate::permission::Nip46Method,
        request_id: crate::message::Nip46RequestId,
    ) -> Self {
        Self::RequestReplayed {
            method: method.to_string(),
            request_id: request_id.to_string(),
        }
    }
}
