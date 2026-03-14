use core::fmt;

use nostr::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::Nip46Error;
use crate::message::{Nip46RequestId, Nip46ResponseMessage};
use crate::permission::Nip46PermissionSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46ConnectRequest {
    pub remote_signer_public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub requested_permissions: Nip46PermissionSet,
}

impl Nip46ConnectRequest {
    pub fn params(&self) -> Vec<String> {
        let mut params = vec![self.remote_signer_public_key.to_hex()];
        if self.secret.is_some() || !self.requested_permissions.is_empty() {
            params.push(self.secret.clone().unwrap_or_default());
        }
        if !self.requested_permissions.is_empty() {
            params.push(self.requested_permissions.to_string());
        }
        params
    }

    pub fn from_params(params: Vec<String>) -> Result<Self, Nip46Error> {
        if params.is_empty() || params.len() > 3 {
            return Err(Nip46Error::invalid_params_length(
                "connect",
                "1-3 positional params",
                params.len(),
            ));
        }

        let remote_signer_public_key = PublicKey::parse(&params[0])
            .map_err(|err| Nip46Error::invalid_public_key(err.to_string()))?;
        let secret = params
            .get(1)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let requested_permissions = match params.get(2) {
            Some(value) => Nip46PermissionSet::parse_csv(value)?,
            None => Nip46PermissionSet::default(),
        };

        Ok(Self {
            remote_signer_public_key,
            secret,
            requested_permissions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nip46ConnectResult {
    Ack,
    SecretEcho(String),
}

impl fmt::Display for Nip46ConnectResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ack => f.write_str("ack"),
            Self::SecretEcho(secret) => f.write_str(secret),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46ConnectResponse {
    pub id: Nip46RequestId,
    pub result: Nip46ConnectResult,
}

impl Nip46ConnectResponse {
    pub fn from_response_message(response: Nip46ResponseMessage) -> Result<Self, Nip46Error> {
        if let Some(error) = response.error {
            return Err(Nip46Error::response_error(error));
        }

        let result = match response.result {
            Some(value) if value == "ack" => Nip46ConnectResult::Ack,
            Some(value) => Nip46ConnectResult::SecretEcho(value),
            None => {
                return Err(Nip46Error::UnexpectedConnectResult {
                    expected: "ack or secret echo".to_string(),
                    received: "<none>".to_string(),
                });
            }
        };

        Ok(Self {
            id: response.id,
            result,
        })
    }

    pub fn to_response_message(&self) -> Nip46ResponseMessage {
        Nip46ResponseMessage::with_result(self.id.clone(), self.result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::{Kind, PublicKey};

    use super::{Nip46ConnectRequest, Nip46ConnectResponse, Nip46ConnectResult};
    use crate::message::{Nip46RequestId, Nip46ResponseMessage};
    use crate::permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};

    const REMOTE_SIGNER_PUBKEY: &str =
        "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";

    #[test]
    fn connect_request_uses_empty_secret_placeholder_when_only_permissions_exist() {
        let request = Nip46ConnectRequest {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            secret: None,
            requested_permissions: Nip46PermissionSet::from(vec![
                Nip46Permission::new(Nip46Method::Nip44Encrypt),
                Nip46Permission::sign_event(Some(Kind::from_u16(13))),
            ]),
        };

        assert_eq!(
            request.params(),
            vec![
                REMOTE_SIGNER_PUBKEY.to_string(),
                String::new(),
                "nip44_encrypt,sign_event:13".to_string(),
            ]
        );
    }

    #[test]
    fn connect_request_round_trips_through_params() {
        let request = Nip46ConnectRequest {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            secret: Some("shh".to_string()),
            requested_permissions: Nip46PermissionSet::from(vec![Nip46Permission::new(
                Nip46Method::Nip44Encrypt,
            )]),
        };

        let reparsed = Nip46ConnectRequest::from_params(request.params()).unwrap();
        assert_eq!(reparsed, request);
    }

    #[test]
    fn connect_response_parses_ack_and_secret_echo() {
        let ack = Nip46ConnectResponse::from_response_message(Nip46ResponseMessage::with_result(
            Nip46RequestId::new("3047714669").unwrap(),
            "ack",
        ))
        .unwrap();
        assert_eq!(ack.result, Nip46ConnectResult::Ack);

        let secret =
            Nip46ConnectResponse::from_response_message(Nip46ResponseMessage::with_result(
                Nip46RequestId::new("3047714670").unwrap(),
                "0s8j2djs",
            ))
            .unwrap();
        assert_eq!(
            secret.result,
            Nip46ConnectResult::SecretEcho("0s8j2djs".to_string())
        );
    }

    #[test]
    fn connect_response_rejects_error_payload() {
        let err = Nip46ConnectResponse::from_response_message(Nip46ResponseMessage::with_error(
            Nip46RequestId::new("3047714669").unwrap(),
            "secret mismatch",
        ))
        .unwrap_err();
        assert_eq!(err.to_string(), "response error: secret mismatch");
    }
}
