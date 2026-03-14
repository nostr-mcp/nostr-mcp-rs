use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::connect::Nip46ConnectRequest;
use crate::error::Nip46Error;
use crate::permission::Nip46Method;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nip46RequestId(String);

impl Nip46RequestId {
    pub fn new<S>(value: S) -> Result<Self, Nip46Error>
    where
        S: Into<String>,
    {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Nip46Error::MissingRequestId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Nip46RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Nip46RequestId {
    type Err = Nip46Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip46Request {
    Connect(Nip46ConnectRequest),
}

impl Nip46Request {
    pub fn method(&self) -> Nip46Method {
        match self {
            Self::Connect(_) => Nip46Method::Connect,
        }
    }

    pub fn params(&self) -> Vec<String> {
        match self {
            Self::Connect(request) => request.params(),
        }
    }

    pub fn from_message(method: Nip46Method, params: Vec<String>) -> Result<Self, Nip46Error> {
        match method {
            Nip46Method::Connect => Ok(Self::Connect(Nip46ConnectRequest::from_params(params)?)),
            other => Err(Nip46Error::unsupported_method(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46RequestMessage {
    pub id: Nip46RequestId,
    pub method: Nip46Method,
    pub params: Vec<String>,
}

impl Nip46RequestMessage {
    pub fn new(id: Nip46RequestId, request: &Nip46Request) -> Self {
        Self {
            id,
            method: request.method(),
            params: request.params(),
        }
    }

    pub fn into_request(self) -> Result<Nip46Request, Nip46Error> {
        Nip46Request::from_message(self.method, self.params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46ResponseMessage {
    pub id: Nip46RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Nip46ResponseMessage {
    pub fn with_result<S>(id: Nip46RequestId, result: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            id,
            result: Some(result.into()),
            error: None,
        }
    }

    pub fn with_error<S>(id: Nip46RequestId, error: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            id,
            result: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Nip46Message {
    Request(Nip46RequestMessage),
    Response(Nip46ResponseMessage),
}

impl Nip46Message {
    pub fn request(id: Nip46RequestId, request: &Nip46Request) -> Self {
        Self::Request(Nip46RequestMessage::new(id, request))
    }

    pub fn response(response: Nip46ResponseMessage) -> Self {
        Self::Response(response)
    }

    pub fn id(&self) -> &Nip46RequestId {
        match self {
            Self::Request(request) => &request.id,
            Self::Response(response) => &response.id,
        }
    }

    pub fn into_request(self) -> Result<Nip46RequestMessage, Nip46Error> {
        match self {
            Self::Request(request) => Ok(request),
            Self::Response(_) => Err(Nip46Error::ExpectedRequestMessage),
        }
    }

    pub fn into_response(self) -> Result<Nip46ResponseMessage, Nip46Error> {
        match self {
            Self::Response(response) => Ok(response),
            Self::Request(_) => Err(Nip46Error::ExpectedResponseMessage),
        }
    }

    pub fn from_json(value: &str) -> Result<Self, Nip46Error> {
        serde_json::from_str(value).map_err(|err| Nip46Error::invalid_json(err.to_string()))
    }

    pub fn as_json(&self) -> Result<String, Nip46Error> {
        serde_json::to_string(self).map_err(|err| Nip46Error::invalid_json(err.to_string()))
    }
}

impl fmt::Display for Nip46Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = self.as_json().map_err(|_| fmt::Error)?;
        f.write_str(&json)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::PublicKey;

    use super::{Nip46Message, Nip46Request, Nip46RequestId, Nip46ResponseMessage};
    use crate::connect::Nip46ConnectRequest;
    use crate::permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};

    const REMOTE_SIGNER_PUBKEY: &str =
        "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";

    #[test]
    fn request_message_round_trips_through_json() {
        let id = Nip46RequestId::new("3047714669").unwrap();
        let request = Nip46Request::Connect(Nip46ConnectRequest {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            secret: Some("shh".to_string()),
            requested_permissions: Nip46PermissionSet::from(vec![Nip46Permission::new(
                Nip46Method::Nip44Encrypt,
            )]),
        });

        let message = Nip46Message::request(id.clone(), &request);
        let reparsed = Nip46Message::from_json(&message.as_json().unwrap()).unwrap();

        assert_eq!(reparsed.id(), &id);
        assert_eq!(reparsed, message);
        assert_eq!(
            reparsed.into_request().unwrap().into_request().unwrap(),
            request
        );
    }

    #[test]
    fn response_message_round_trips_through_json() {
        let response =
            Nip46ResponseMessage::with_result(Nip46RequestId::new("3047714669").unwrap(), "ack");
        let message = Nip46Message::response(response.clone());
        let reparsed = Nip46Message::from_json(&message.as_json().unwrap()).unwrap();
        assert_eq!(reparsed.into_response().unwrap(), response);
    }

    #[test]
    fn request_id_rejects_empty_value() {
        let err = Nip46RequestId::new("  ").unwrap_err();
        assert_eq!(err.to_string(), "invalid message: missing request id");
    }

    #[test]
    fn invalid_json_uses_message_error_surface() {
        let err = Nip46Message::from_json("{").unwrap_err();
        assert!(err.to_string().starts_with("invalid json: "));
    }
}
