use nostr::{PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::error::Nip46Error;
use crate::message::{Nip46RequestId, Nip46ResponseMessage};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46GetPublicKeyRequest;

impl Nip46GetPublicKeyRequest {
    pub fn params(&self) -> Vec<String> {
        Vec::new()
    }

    pub fn from_params(params: Vec<String>) -> Result<Self, Nip46Error> {
        if !params.is_empty() {
            return Err(Nip46Error::invalid_params_length(
                "get_public_key",
                "0 positional params",
                params.len(),
            ));
        }
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46GetPublicKeyResponse {
    pub id: Nip46RequestId,
    pub user_public_key: PublicKey,
}

impl Nip46GetPublicKeyResponse {
    pub fn from_response_message(response: Nip46ResponseMessage) -> Result<Self, Nip46Error> {
        if let Some(error) = response.error {
            return Err(Nip46Error::response_error(error));
        }

        let result = response.result.ok_or_else(|| {
            Nip46Error::unexpected_response_value("get_public_key", "user public key", "<none>")
        })?;
        let user_public_key = PublicKey::parse(&result)
            .map_err(|err| Nip46Error::invalid_public_key(err.to_string()))?;

        Ok(Self {
            id: response.id,
            user_public_key,
        })
    }

    pub fn to_response_message(&self) -> Nip46ResponseMessage {
        Nip46ResponseMessage::with_result(self.id.clone(), self.user_public_key.to_hex())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46SwitchRelaysRequest;

impl Nip46SwitchRelaysRequest {
    pub fn params(&self) -> Vec<String> {
        Vec::new()
    }

    pub fn from_params(params: Vec<String>) -> Result<Self, Nip46Error> {
        if !params.is_empty() {
            return Err(Nip46Error::invalid_params_length(
                "switch_relays",
                "0 positional params",
                params.len(),
            ));
        }
        Ok(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nip46SwitchRelaysResult {
    Unchanged,
    Updated(Vec<RelayUrl>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46SwitchRelaysResponse {
    pub id: Nip46RequestId,
    pub result: Nip46SwitchRelaysResult,
}

impl Nip46SwitchRelaysResponse {
    pub fn from_response_message(response: Nip46ResponseMessage) -> Result<Self, Nip46Error> {
        if let Some(error) = response.error {
            return Err(Nip46Error::response_error(error));
        }

        let result = match response.result {
            None => Nip46SwitchRelaysResult::Unchanged,
            Some(value) if value.trim() == "null" => Nip46SwitchRelaysResult::Unchanged,
            Some(value) => {
                let relay_urls: Vec<String> = serde_json::from_str(&value)
                    .map_err(|err| Nip46Error::invalid_json(err.to_string()))?;
                let mut relays = Vec::with_capacity(relay_urls.len());
                for relay in relay_urls {
                    relays.push(
                        RelayUrl::parse(&relay)
                            .map_err(|err| Nip46Error::invalid_relay_url(err.to_string()))?,
                    );
                }
                Nip46SwitchRelaysResult::Updated(relays)
            }
        };

        Ok(Self {
            id: response.id,
            result,
        })
    }

    pub fn to_response_message(&self) -> Result<Nip46ResponseMessage, Nip46Error> {
        match &self.result {
            Nip46SwitchRelaysResult::Unchanged => {
                Ok(Nip46ResponseMessage::new(self.id.clone(), None, None))
            }
            Nip46SwitchRelaysResult::Updated(relays) => {
                let relay_urls = relays
                    .iter()
                    .map(|relay| relay.as_str())
                    .collect::<Vec<_>>();
                let result = serde_json::to_string(&relay_urls)
                    .map_err(|err| Nip46Error::invalid_json(err.to_string()))?;
                Ok(Nip46ResponseMessage::with_result(self.id.clone(), result))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::{PublicKey, RelayUrl};

    use super::{
        Nip46GetPublicKeyRequest, Nip46GetPublicKeyResponse, Nip46SwitchRelaysRequest,
        Nip46SwitchRelaysResponse, Nip46SwitchRelaysResult,
    };
    use crate::message::{Nip46RequestId, Nip46ResponseMessage};

    const USER_PUBKEY: &str = "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3";

    #[test]
    fn get_public_key_request_rejects_params() {
        let err =
            Nip46GetPublicKeyRequest::from_params(vec!["unexpected".to_string()]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid params for `get_public_key`: expected 0 positional params, received 1"
        );
    }

    #[test]
    fn get_public_key_response_round_trips() {
        let response =
            Nip46GetPublicKeyResponse::from_response_message(Nip46ResponseMessage::with_result(
                Nip46RequestId::new("3047714671").unwrap(),
                USER_PUBKEY,
            ))
            .unwrap();

        assert_eq!(
            response.user_public_key,
            PublicKey::from_str(USER_PUBKEY).unwrap()
        );
        assert_eq!(
            response.to_response_message(),
            Nip46ResponseMessage::with_result(
                Nip46RequestId::new("3047714671").unwrap(),
                USER_PUBKEY,
            )
        );
    }

    #[test]
    fn switch_relays_request_rejects_params() {
        let err =
            Nip46SwitchRelaysRequest::from_params(vec!["unexpected".to_string()]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid params for `switch_relays`: expected 0 positional params, received 1"
        );
    }

    #[test]
    fn switch_relays_response_parses_null_as_unchanged() {
        let response = Nip46SwitchRelaysResponse::from_response_message(Nip46ResponseMessage::new(
            Nip46RequestId::new("3047714672").unwrap(),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(response.result, Nip46SwitchRelaysResult::Unchanged);
    }

    #[test]
    fn switch_relays_response_round_trips_updated_relays() {
        let response =
            Nip46SwitchRelaysResponse::from_response_message(Nip46ResponseMessage::with_result(
                Nip46RequestId::new("3047714673").unwrap(),
                "[\"wss://relay1.example.com\",\"wss://relay2.example.com\"]",
            ))
            .unwrap();

        assert_eq!(
            response.result,
            Nip46SwitchRelaysResult::Updated(vec![
                RelayUrl::parse("wss://relay1.example.com").unwrap(),
                RelayUrl::parse("wss://relay2.example.com").unwrap(),
            ])
        );

        let encoded = response.to_response_message().unwrap();
        assert_eq!(
            encoded,
            Nip46ResponseMessage::with_result(
                Nip46RequestId::new("3047714673").unwrap(),
                "[\"wss://relay1.example.com\",\"wss://relay2.example.com\"]",
            )
        );
    }
}
