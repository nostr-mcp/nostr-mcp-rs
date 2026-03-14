use core::fmt;
use core::str::FromStr;

use nostr::{PublicKey, RelayUrl, Url};
use serde::{Deserialize, Serialize};

use crate::error::Nip46Error;
use crate::permission::Nip46PermissionSet;

pub const NIP46_CLIENT_URI_SCHEME: &str = "nostrconnect";
pub const NIP46_BUNKER_URI_SCHEME: &str = "bunker";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46ClientMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Url>,
}

impl Nip46ClientMetadata {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.url.is_none() && self.image.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip46ConnectUri {
    Bunker {
        remote_signer_public_key: PublicKey,
        relays: Vec<RelayUrl>,
        secret: Option<String>,
    },
    Client {
        client_public_key: PublicKey,
        relays: Vec<RelayUrl>,
        secret: String,
        permissions: Nip46PermissionSet,
        metadata: Box<Nip46ClientMetadata>,
    },
}

impl Nip46ConnectUri {
    pub fn parse<S>(value: S) -> Result<Self, Nip46Error>
    where
        S: AsRef<str>,
    {
        let url =
            Url::parse(value.as_ref()).map_err(|err| Nip46Error::invalid_url(err.to_string()))?;
        let scheme = url.scheme().to_owned();
        let key = url.host_str().ok_or(Nip46Error::MissingPublicKey)?;
        let key = PublicKey::from_str(key)
            .map_err(|err| Nip46Error::invalid_public_key(err.to_string()))?;

        let mut relays = Vec::new();
        let mut secret = None;
        let mut permissions = Nip46PermissionSet::default();
        let mut metadata = Nip46ClientMetadata::default();

        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "relay" => {
                    relays.push(
                        RelayUrl::parse(value.as_ref())
                            .map_err(|err| Nip46Error::invalid_relay_url(err.to_string()))?,
                    );
                }
                "secret" => {
                    secret = Some(value.into_owned());
                }
                "perms" => {
                    permissions = Nip46PermissionSet::parse_csv(value.as_ref())?;
                }
                "name" => {
                    metadata.name = Some(value.into_owned());
                }
                "url" => {
                    metadata.url = Some(
                        Url::parse(value.as_ref())
                            .map_err(|err| Nip46Error::invalid_url(err.to_string()))?,
                    );
                }
                "image" => {
                    metadata.image = Some(
                        Url::parse(value.as_ref())
                            .map_err(|err| Nip46Error::invalid_url(err.to_string()))?,
                    );
                }
                _ => {}
            }
        }

        if relays.is_empty() {
            return Err(Nip46Error::MissingRelay);
        }

        match scheme.as_str() {
            NIP46_BUNKER_URI_SCHEME => Ok(Self::Bunker {
                remote_signer_public_key: key,
                relays,
                secret,
            }),
            NIP46_CLIENT_URI_SCHEME => Ok(Self::Client {
                client_public_key: key,
                relays,
                secret: secret.ok_or(Nip46Error::MissingSecret)?,
                permissions,
                metadata: Box::new(metadata),
            }),
            _ => Err(Nip46Error::UnsupportedUriScheme(scheme)),
        }
    }

    pub fn relays(&self) -> &[RelayUrl] {
        match self {
            Self::Bunker { relays, .. } | Self::Client { relays, .. } => relays,
        }
    }
}

impl fmt::Display for Nip46ConnectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut url = match self {
            Self::Bunker {
                remote_signer_public_key,
                ..
            } => Url::parse(&format!(
                "{NIP46_BUNKER_URI_SCHEME}://{}",
                remote_signer_public_key.to_hex()
            )),
            Self::Client {
                client_public_key, ..
            } => Url::parse(&format!(
                "{NIP46_CLIENT_URI_SCHEME}://{}",
                client_public_key.to_hex()
            )),
        }
        .map_err(|_| fmt::Error)?;

        {
            let mut pairs = url.query_pairs_mut();
            match self {
                Self::Bunker { relays, secret, .. } => {
                    for relay in relays {
                        pairs.append_pair("relay", relay.as_str());
                    }
                    if let Some(secret) = secret {
                        pairs.append_pair("secret", secret);
                    }
                }
                Self::Client {
                    relays,
                    secret,
                    permissions,
                    metadata,
                    ..
                } => {
                    for relay in relays {
                        pairs.append_pair("relay", relay.as_str());
                    }
                    pairs.append_pair("secret", secret);
                    if !permissions.is_empty() {
                        pairs.append_pair("perms", &permissions.to_string());
                    }
                    if let Some(name) = &metadata.name {
                        pairs.append_pair("name", name);
                    }
                    if let Some(url) = &metadata.url {
                        pairs.append_pair("url", url.as_str());
                    }
                    if let Some(image) = &metadata.image {
                        pairs.append_pair("image", image.as_str());
                    }
                }
            }
        }

        f.write_str(url.as_str())
    }
}

impl FromStr for Nip46ConnectUri {
    type Err = Nip46Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::{PublicKey, RelayUrl, Url};

    use super::{NIP46_BUNKER_URI_SCHEME, Nip46ClientMetadata, Nip46ConnectUri};
    use crate::permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};

    const REMOTE_SIGNER_PUBKEY: &str =
        "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52";
    const CLIENT_PUBKEY: &str = "eff37350d839ce3707332348af4549a96051bd695d3223af4aabce4993531d86";

    #[test]
    fn parse_bunker_uri_matches_spec_shape() {
        let uri = Nip46ConnectUri::parse(format!(
            "{NIP46_BUNKER_URI_SCHEME}://{REMOTE_SIGNER_PUBKEY}?relay=wss%3A%2F%2Frelay1.example.com&relay=wss%3A%2F%2Frelay2.example.com&secret=shh"
        ))
        .unwrap();

        assert_eq!(
            uri,
            Nip46ConnectUri::Bunker {
                remote_signer_public_key: PublicKey::from_str(REMOTE_SIGNER_PUBKEY).unwrap(),
                relays: vec![
                    RelayUrl::parse("wss://relay1.example.com").unwrap(),
                    RelayUrl::parse("wss://relay2.example.com").unwrap(),
                ],
                secret: Some("shh".to_string()),
            }
        );
    }

    #[test]
    fn parse_client_uri_matches_spec_shape() {
        let uri = Nip46ConnectUri::parse(format!(
            "nostrconnect://{CLIENT_PUBKEY}?relay=wss%3A%2F%2Frelay1.example.com&perms=nip44_encrypt%2Csign_event%3A1059&name=My+Client&url=https%3A%2F%2Fexample.com&image=https%3A%2F%2Fexample.com%2Ficon.png&secret=0s8j2djs&relay=wss%3A%2F%2Frelay2.example.com"
        ))
        .unwrap();

        assert_eq!(
            uri,
            Nip46ConnectUri::Client {
                client_public_key: PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
                relays: vec![
                    RelayUrl::parse("wss://relay1.example.com").unwrap(),
                    RelayUrl::parse("wss://relay2.example.com").unwrap(),
                ],
                secret: "0s8j2djs".to_string(),
                permissions: Nip46PermissionSet::from(vec![
                    Nip46Permission::new(Nip46Method::Nip44Encrypt),
                    Nip46Permission::sign_event(Some(nostr::Kind::from_u16(1059))),
                ]),
                metadata: Box::new(Nip46ClientMetadata {
                    name: Some("My Client".to_string()),
                    url: Some(Url::parse("https://example.com").unwrap()),
                    image: Some(Url::parse("https://example.com/icon.png").unwrap()),
                }),
            }
        );
    }

    #[test]
    fn client_uri_round_trips_through_display() {
        let uri = Nip46ConnectUri::Client {
            client_public_key: PublicKey::from_str(CLIENT_PUBKEY).unwrap(),
            relays: vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
            secret: "super-secret".to_string(),
            permissions: Nip46PermissionSet::from(vec![
                Nip46Permission::new(Nip46Method::GetPublicKey),
                Nip46Permission::new(Nip46Method::SwitchRelays),
            ]),
            metadata: Box::new(Nip46ClientMetadata {
                name: Some("Agent".to_string()),
                url: Some(Url::parse("https://agent.example.com").unwrap()),
                image: None,
            }),
        };

        let reparsed = Nip46ConnectUri::parse(uri.to_string()).unwrap();
        assert_eq!(reparsed, uri);
    }

    #[test]
    fn client_uri_requires_secret() {
        let err = Nip46ConnectUri::parse(format!(
            "nostrconnect://{CLIENT_PUBKEY}?relay=wss%3A%2F%2Frelay1.example.com"
        ))
        .unwrap_err();
        assert_eq!(err.to_string(), "invalid uri: missing secret");
    }

    #[test]
    fn bunker_uri_requires_relays() {
        let err = Nip46ConnectUri::parse(format!(
            "{NIP46_BUNKER_URI_SCHEME}://{REMOTE_SIGNER_PUBKEY}"
        ))
        .unwrap_err();
        assert_eq!(err.to_string(), "invalid uri: missing relay");
    }
}
