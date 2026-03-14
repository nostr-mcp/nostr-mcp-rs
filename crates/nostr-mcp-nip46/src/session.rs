use nostr::{PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::{PublicKey, RelayUrl, Url};

    use super::{Nip46ConnectionMode, Nip46SessionProfile};
    use crate::permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};
    use crate::uri::{Nip46ClientMetadata, Nip46ConnectUri};

    const REMOTE_SIGNER_PUBKEY: &str =
        "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";
    const CLIENT_PUBKEY: &str = "eff37350d839ce3707332348af4549a96051bd695d3223af4aabce4993531d86";

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
}
