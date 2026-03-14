use nostr::{PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::connect::{Nip46ConnectRequest, Nip46ConnectResponse, Nip46ConnectResult};
use crate::error::Nip46Error;
use crate::message::{Nip46Message, Nip46Request, Nip46RequestId};
use crate::permission::Nip46PermissionSet;
use crate::uri::{Nip46ClientMetadata, Nip46ConnectUri};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nip46ConnectionMode {
    Bunker,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46SessionProfile {
    pub connection_mode: Nip46ConnectionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_public_key: Option<PublicKey>,
    pub relays: Vec<RelayUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub requested_permissions: Nip46PermissionSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<Nip46ClientMetadata>,
}

impl Nip46SessionProfile {
    pub fn from_uri(uri: &Nip46ConnectUri) -> Self {
        match uri {
            Nip46ConnectUri::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } => Self {
                connection_mode: Nip46ConnectionMode::Bunker,
                client_public_key: None,
                remote_signer_public_key: Some(*remote_signer_public_key),
                relays: relays.clone(),
                secret: secret.clone(),
                requested_permissions: Nip46PermissionSet::default(),
                client_metadata: None,
            },
            Nip46ConnectUri::Client {
                client_public_key,
                relays,
                secret,
                permissions,
                metadata,
            } => Self {
                connection_mode: Nip46ConnectionMode::Client,
                client_public_key: Some(*client_public_key),
                remote_signer_public_key: None,
                relays: relays.clone(),
                secret: Some(secret.clone()),
                requested_permissions: permissions.clone(),
                client_metadata: if metadata.is_empty() {
                    None
                } else {
                    Some(metadata.as_ref().clone())
                },
            },
        }
    }
}

impl From<&Nip46ConnectUri> for Nip46SessionProfile {
    fn from(uri: &Nip46ConnectUri) -> Self {
        Self::from_uri(uri)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46PendingSession {
    pub connection_mode: Nip46ConnectionMode,
    pub client_public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_remote_signer_public_key: Option<PublicKey>,
    pub relays: Vec<RelayUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_secret: Option<String>,
    pub requested_permissions: Nip46PermissionSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<Nip46ClientMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_request_id: Option<Nip46RequestId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46Session {
    pub connection_mode: Nip46ConnectionMode,
    pub client_public_key: PublicKey,
    pub remote_signer_public_key: PublicKey,
    pub relays: Vec<RelayUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub requested_permissions: Nip46PermissionSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<Nip46ClientMetadata>,
}

impl Nip46PendingSession {
    pub fn initiate_bunker_connect(
        uri: &Nip46ConnectUri,
        client_public_key: PublicKey,
        request_id: Nip46RequestId,
        requested_permissions: Nip46PermissionSet,
    ) -> Result<(Self, Nip46Message), Nip46Error> {
        let Nip46ConnectUri::Bunker {
            remote_signer_public_key,
            relays,
            secret,
        } = uri
        else {
            return Err(Nip46Error::invalid_connect_flow(
                "bunker connect must start from a bunker uri",
            ));
        };

        let pending = Self {
            connection_mode: Nip46ConnectionMode::Bunker,
            client_public_key,
            expected_remote_signer_public_key: Some(*remote_signer_public_key),
            relays: relays.clone(),
            expected_secret: secret.clone(),
            requested_permissions: requested_permissions.clone(),
            client_metadata: None,
            connect_request_id: Some(request_id.clone()),
        };

        let request = Nip46Request::Connect(Nip46ConnectRequest {
            remote_signer_public_key: *remote_signer_public_key,
            secret: secret.clone(),
            requested_permissions,
        });

        Ok((pending, Nip46Message::request(request_id, &request)))
    }

    pub fn await_client_connect(uri: &Nip46ConnectUri) -> Result<Self, Nip46Error> {
        let profile = Nip46SessionProfile::from_uri(uri);
        if profile.connection_mode != Nip46ConnectionMode::Client {
            return Err(Nip46Error::invalid_connect_flow(
                "client connect must start from a nostrconnect uri",
            ));
        }

        Ok(Self {
            connection_mode: Nip46ConnectionMode::Client,
            client_public_key: profile.client_public_key.ok_or_else(|| {
                Nip46Error::invalid_connect_flow("client uri missing client pubkey")
            })?,
            expected_remote_signer_public_key: None,
            relays: profile.relays,
            expected_secret: profile.secret,
            requested_permissions: profile.requested_permissions,
            client_metadata: profile.client_metadata,
            connect_request_id: None,
        })
    }

    pub fn accept_connect_response(
        &self,
        remote_signer_public_key: PublicKey,
        message: Nip46Message,
    ) -> Result<Nip46Session, Nip46Error> {
        if let Some(expected) = self.expected_remote_signer_public_key
            && expected != remote_signer_public_key
        {
            return Err(Nip46Error::UnexpectedRemoteSignerPublicKey {
                expected: expected.to_hex(),
                received: remote_signer_public_key.to_hex(),
            });
        }

        let response = Nip46ConnectResponse::from_response_message(message.into_response()?)?;

        if let Some(expected_id) = &self.connect_request_id
            && expected_id != &response.id
        {
            return Err(Nip46Error::UnexpectedResponseId {
                expected: expected_id.to_string(),
                received: response.id.to_string(),
            });
        }

        match self.connection_mode {
            Nip46ConnectionMode::Bunker => {
                if let Some(expected_secret) = &self.expected_secret {
                    match &response.result {
                        Nip46ConnectResult::Ack => {}
                        Nip46ConnectResult::SecretEcho(secret) if secret == expected_secret => {}
                        Nip46ConnectResult::SecretEcho(secret) => {
                            return Err(Nip46Error::UnexpectedConnectResult {
                                expected: format!("ack or `{expected_secret}`"),
                                received: secret.clone(),
                            });
                        }
                    }
                } else if response.result != Nip46ConnectResult::Ack {
                    return Err(Nip46Error::UnexpectedConnectResult {
                        expected: "ack".to_string(),
                        received: response.result.to_string(),
                    });
                }
            }
            Nip46ConnectionMode::Client => {
                let expected_secret = self.expected_secret.as_ref().ok_or_else(|| {
                    Nip46Error::invalid_connect_flow("client connect requires a secret")
                })?;
                match &response.result {
                    Nip46ConnectResult::SecretEcho(secret) if secret == expected_secret => {}
                    other => {
                        return Err(Nip46Error::UnexpectedConnectResult {
                            expected: expected_secret.clone(),
                            received: other.to_string(),
                        });
                    }
                }
            }
        }

        Ok(Nip46Session {
            connection_mode: self.connection_mode,
            client_public_key: self.client_public_key,
            remote_signer_public_key,
            relays: self.relays.clone(),
            secret: self.expected_secret.clone(),
            requested_permissions: self.requested_permissions.clone(),
            client_metadata: self.client_metadata.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::{PublicKey, RelayUrl, Url};

    use super::{Nip46ConnectionMode, Nip46PendingSession, Nip46SessionProfile};
    use crate::message::{Nip46Message, Nip46RequestId, Nip46ResponseMessage};
    use crate::permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};
    use crate::uri::{Nip46ClientMetadata, Nip46ConnectUri};

    const REMOTE_SIGNER_PUBKEY: &str =
        "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";
    const CLIENT_PUBKEY: &str = "eff37350d839ce3707332348af4549a96051bd695d3223af4aabce4993531d86";
    const ALT_REMOTE_SIGNER_PUBKEY: &str =
        "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3";

    #[test]
    fn session_profile_from_bunker_uri_sets_remote_signer_boundary() {
        let uri = Nip46ConnectUri::Bunker {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: Some("bunker-secret".to_string()),
        };

        let profile = Nip46SessionProfile::from_uri(&uri);
        assert_eq!(profile.connection_mode, Nip46ConnectionMode::Bunker);
        assert_eq!(profile.client_public_key, None);
        assert_eq!(
            profile.remote_signer_public_key,
            Some(PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap())
        );
        assert!(profile.requested_permissions.is_empty());
        assert!(profile.client_metadata.is_none());
    }

    #[test]
    fn session_profile_from_client_uri_carries_requested_permissions() {
        let uri = Nip46ConnectUri::Client {
            client_public_key: PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: "client-secret".to_string(),
            permissions: Nip46PermissionSet::from(vec![
                Nip46Permission::new(Nip46Method::GetPublicKey),
                Nip46Permission::sign_event(Some(nostr::Kind::from_u16(1))),
            ]),
            metadata: Box::new(Nip46ClientMetadata {
                name: Some("Agent".to_string()),
                url: Some(Url::parse("https://agent.example.com").unwrap()),
                image: None,
            }),
        };

        let profile = Nip46SessionProfile::from_uri(&uri);
        assert_eq!(profile.connection_mode, Nip46ConnectionMode::Client);
        assert_eq!(
            profile.client_public_key,
            Some(PublicKey::from_str(CLIENT_PUBKEY).unwrap())
        );
        assert_eq!(profile.remote_signer_public_key, None);
        assert_eq!(profile.secret.as_deref(), Some("client-secret"));
        assert_eq!(
            profile.requested_permissions.to_string(),
            "get_public_key,sign_event:1"
        );
        assert_eq!(
            profile.client_metadata.unwrap().url.unwrap().as_str(),
            "https://agent.example.com/"
        );
    }

    #[test]
    fn initiate_bunker_connect_builds_request_message() {
        let uri = Nip46ConnectUri::Bunker {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: Some("bunker-secret".to_string()),
        };

        let (pending, message) = Nip46PendingSession::initiate_bunker_connect(
            &uri,
            PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            Nip46RequestId::new("3047714669").unwrap(),
            Nip46PermissionSet::from(vec![
                Nip46Permission::new(Nip46Method::Nip44Encrypt),
                Nip46Permission::sign_event(Some(nostr::Kind::from_u16(13))),
            ]),
        )
        .unwrap();

        assert_eq!(pending.connection_mode, Nip46ConnectionMode::Bunker);
        let request = message.into_request().unwrap().into_request().unwrap();
        let crate::message::Nip46Request::Connect(request) = request;
        assert_eq!(
            request.params(),
            vec![
                REMOTE_SIGNER_PUBKEY.to_string(),
                "bunker-secret".to_string(),
                "nip44_encrypt,sign_event:13".to_string(),
            ]
        );
    }

    #[test]
    fn bunker_connect_accepts_ack_from_expected_remote_signer() {
        let uri = Nip46ConnectUri::Bunker {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: Some("bunker-secret".to_string()),
        };

        let (pending, _) = Nip46PendingSession::initiate_bunker_connect(
            &uri,
            PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            Nip46RequestId::new("3047714669").unwrap(),
            Nip46PermissionSet::default(),
        )
        .unwrap();

        let session = pending
            .accept_connect_response(
                PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
                Nip46Message::response(Nip46ResponseMessage::with_result(
                    Nip46RequestId::new("3047714669").unwrap(),
                    "ack",
                )),
            )
            .unwrap();

        assert_eq!(session.connection_mode, Nip46ConnectionMode::Bunker);
        assert_eq!(
            session.client_public_key,
            PublicKey::from_str(CLIENT_PUBKEY).unwrap()
        );
        assert_eq!(
            session.remote_signer_public_key,
            PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap()
        );
    }

    #[test]
    fn client_connect_discovers_remote_signer_from_secret_echo() {
        let uri = Nip46ConnectUri::Client {
            client_public_key: PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: "client-secret".to_string(),
            permissions: Nip46PermissionSet::from(vec![Nip46Permission::new(
                Nip46Method::GetPublicKey,
            )]),
            metadata: Box::new(Nip46ClientMetadata {
                name: Some("Agent".to_string()),
                url: None,
                image: None,
            }),
        };

        let pending = Nip46PendingSession::await_client_connect(&uri).unwrap();
        let session = pending
            .accept_connect_response(
                PublicKey::from_str(ALT_REMOTE_SIGNER_PUBKEY).unwrap(),
                Nip46Message::response(Nip46ResponseMessage::with_result(
                    Nip46RequestId::new("remote-connect-1").unwrap(),
                    "client-secret",
                )),
            )
            .unwrap();

        assert_eq!(session.connection_mode, Nip46ConnectionMode::Client);
        assert_eq!(
            session.remote_signer_public_key,
            PublicKey::from_str(ALT_REMOTE_SIGNER_PUBKEY).unwrap()
        );
        assert_eq!(session.requested_permissions.to_string(), "get_public_key");
    }

    #[test]
    fn client_connect_rejects_ack_without_secret_echo() {
        let uri = Nip46ConnectUri::Client {
            client_public_key: PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: "client-secret".to_string(),
            permissions: Nip46PermissionSet::default(),
            metadata: Box::new(Nip46ClientMetadata::default()),
        };

        let pending = Nip46PendingSession::await_client_connect(&uri).unwrap();
        let err = pending
            .accept_connect_response(
                PublicKey::from_str(ALT_REMOTE_SIGNER_PUBKEY).unwrap(),
                Nip46Message::response(Nip46ResponseMessage::with_result(
                    Nip46RequestId::new("remote-connect-1").unwrap(),
                    "ack",
                )),
            )
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "unexpected connect result: expected `client-secret`, received `ack`"
        );
    }

    #[test]
    fn bunker_connect_rejects_wrong_remote_signer() {
        let uri = Nip46ConnectUri::Bunker {
            remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: None,
        };

        let (pending, _) = Nip46PendingSession::initiate_bunker_connect(
            &uri,
            PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            Nip46RequestId::new("3047714669").unwrap(),
            Nip46PermissionSet::default(),
        )
        .unwrap();

        let err = pending
            .accept_connect_response(
                PublicKey::from_str(ALT_REMOTE_SIGNER_PUBKEY).unwrap(),
                Nip46Message::response(Nip46ResponseMessage::with_result(
                    Nip46RequestId::new("3047714669").unwrap(),
                    "ack",
                )),
            )
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "unexpected remote signer public key: expected `{}`, received `{}`",
                REMOTE_SIGNER_PUBKEY, ALT_REMOTE_SIGNER_PUBKEY
            )
        );
    }
}
