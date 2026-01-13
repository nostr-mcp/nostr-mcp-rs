use crate::error::CoreError;
use nostr::nips::nip19::Nip19;
use nostr::prelude::FromBech32;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip19DecodeArgs {
    pub input: String,
    pub allow_secret: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Nip19DecodeResult {
    pub input: String,
    pub input_type: Nip19EntityType,
    pub data: Nip19DecodedData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Nip19EntityType {
    Npub,
    Nsec,
    Note,
    Nprofile,
    Nevent,
    Naddr,
    Hex,
}

#[derive(Debug, Serialize)]
pub struct Nip19DecodedData {
    pub pubkey_hex: Option<String>,
    pub event_id_hex: Option<String>,
    pub relays: Option<Vec<String>>,
    pub author_hex: Option<String>,
    pub kind: Option<u16>,
    pub identifier: Option<String>,
    pub is_secret: bool,
}

pub fn decode_nip19(args: Nip19DecodeArgs) -> Result<Nip19DecodeResult, CoreError> {
    let input = args.input.trim().to_string();
    if input.is_empty() {
        return Err(CoreError::invalid_input("input must not be empty"));
    }

    let allow_secret = args.allow_secret.unwrap_or(false);

    if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Hex,
            data: Nip19DecodedData {
                pubkey_hex: None,
                event_id_hex: None,
                relays: None,
                author_hex: None,
                kind: None,
                identifier: None,
                is_secret: false,
            },
        });
    }

    let nip19 = Nip19::from_bech32(&input).map_err(|e| {
        CoreError::invalid_input(format!("invalid nip19 entity: {e}"))
    })?;

    match nip19 {
        Nip19::Pubkey(pubkey) => Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Npub,
            data: Nip19DecodedData {
                pubkey_hex: Some(pubkey.to_hex()),
                event_id_hex: None,
                relays: None,
                author_hex: None,
                kind: None,
                identifier: None,
                is_secret: false,
            },
        }),
        Nip19::Secret(secret) => {
            if !allow_secret {
                return Err(CoreError::invalid_input(
                    "nsec decoding is disabled (allow_secret=false)",
                ));
            }
            Ok(Nip19DecodeResult {
                input,
                input_type: Nip19EntityType::Nsec,
                data: Nip19DecodedData {
                    pubkey_hex: None,
                    event_id_hex: None,
                    relays: None,
                    author_hex: None,
                    kind: None,
                    identifier: None,
                    is_secret: true,
                },
            })
        }
        Nip19::EventId(event_id) => Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Note,
            data: Nip19DecodedData {
                pubkey_hex: None,
                event_id_hex: Some(event_id.to_hex()),
                relays: None,
                author_hex: None,
                kind: None,
                identifier: None,
                is_secret: false,
            },
        }),
        Nip19::Profile(profile) => Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Nprofile,
            data: Nip19DecodedData {
                pubkey_hex: Some(profile.public_key.to_hex()),
                event_id_hex: None,
                relays: Some(profile.relays.iter().map(|r| r.to_string()).collect()),
                author_hex: None,
                kind: None,
                identifier: None,
                is_secret: false,
            },
        }),
        Nip19::Event(event) => Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Nevent,
            data: Nip19DecodedData {
                pubkey_hex: None,
                event_id_hex: Some(event.event_id.to_hex()),
                relays: Some(event.relays.iter().map(|r| r.to_string()).collect()),
                author_hex: event.author.map(|pk| pk.to_hex()),
                kind: event.kind.map(|k| k.as_u16()),
                identifier: None,
                is_secret: false,
            },
        }),
        Nip19::Coordinate(coordinate) => Ok(Nip19DecodeResult {
            input,
            input_type: Nip19EntityType::Naddr,
            data: Nip19DecodedData {
                pubkey_hex: Some(coordinate.public_key.to_hex()),
                event_id_hex: None,
                relays: Some(coordinate.relays.iter().map(|r| r.to_string()).collect()),
                author_hex: None,
                kind: Some(coordinate.kind.as_u16()),
                identifier: Some(coordinate.identifier.clone()),
                is_secret: false,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_nip19, Nip19DecodeArgs, Nip19EntityType};
    use nostr::nips::nip19::ToBech32;
    use nostr::prelude::{EventId, Keys};

    #[test]
    fn decode_rejects_empty() {
        let err = decode_nip19(Nip19DecodeArgs {
            input: "".to_string(),
            allow_secret: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("input must not be empty"));
    }

    #[test]
    fn decode_accepts_npub() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let result = decode_nip19(Nip19DecodeArgs {
            input: npub,
            allow_secret: None,
        })
        .unwrap();
        assert!(matches!(result.input_type, Nip19EntityType::Npub));
        assert_eq!(result.data.pubkey_hex, Some(keys.public_key().to_hex()));
    }

    #[test]
    fn decode_accepts_note() {
        let id = EventId::all_zeros();
        let note = id.to_bech32().unwrap();
        let result = decode_nip19(Nip19DecodeArgs {
            input: note,
            allow_secret: None,
        })
        .unwrap();
        assert!(matches!(result.input_type, Nip19EntityType::Note));
        assert_eq!(result.data.event_id_hex, Some(id.to_hex()));
    }

    #[test]
    fn decode_rejects_nsec_when_disabled() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let err = decode_nip19(Nip19DecodeArgs {
            input: nsec,
            allow_secret: Some(false),
        })
        .unwrap_err();
        assert!(err.to_string().contains("allow_secret"));
    }
}
