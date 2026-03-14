use crate::error::CoreError;
use nostr::nips::nip19::{Nip19, Nip19Coordinate, Nip19Event, Nip19Profile};
use nostr::prelude::{
    Coordinate, EventId, FromBech32, Kind, PublicKey, RelayUrl, SecretKey, ToBech32,
};
use nostr_mcp_types::nip19::{
    Nip19DecodeArgs, Nip19DecodeResult, Nip19DecodedData, Nip19EncodeArgs, Nip19EncodeResult,
    Nip19EncodeTarget, Nip19EntityType,
};

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

    let nip19 = Nip19::from_bech32(&input)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip19 entity: {e}")))?;

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
        Nip19::Secret(_secret) => {
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

pub fn encode_nip19(args: Nip19EncodeArgs) -> Result<Nip19EncodeResult, CoreError> {
    let Nip19EncodeArgs {
        target,
        input,
        relays,
        author,
        kind,
        identifier,
        allow_secret,
    } = args;

    let input = input.trim().to_string();
    if input.is_empty() {
        return Err(CoreError::invalid_input("input must not be empty"));
    }

    let encoded = match &target {
        Nip19EncodeTarget::Npub => {
            let pubkey = parse_public_key(&input)?;
            public_key_npub(&pubkey)
        }
        Nip19EncodeTarget::Nsec => {
            if !allow_secret.unwrap_or(false) {
                return Err(CoreError::invalid_input(
                    "nsec encoding is disabled (allow_secret=false)",
                ));
            }
            let secret_key = parse_secret_key(&input)?;
            secret_key_nsec(&secret_key)
        }
        Nip19EncodeTarget::Note => {
            let event_id = parse_event_id(&input)?;
            event_id_note(&event_id)
        }
        Nip19EncodeTarget::Nprofile => {
            let pubkey = parse_public_key(&input)?;
            let relays = parse_relays(relays.as_deref())?;
            Nip19Profile::new(pubkey, relays)
                .to_bech32()
                .map_err(|e| CoreError::invalid_input(format!("invalid nprofile: {e}")))?
        }
        Nip19EncodeTarget::Nevent => {
            let event_id = parse_event_id(&input)?;
            let relays = parse_relays(relays.as_deref())?;
            let author = author.as_deref().map(parse_public_key).transpose()?;
            let kind = kind.map(Kind::from);

            let mut event = Nip19Event::new(event_id);
            if let Some(author) = author {
                event = event.author(author);
            }
            if let Some(kind) = kind {
                event = event.kind(kind);
            }
            event = event.relays(relays);
            event
                .to_bech32()
                .map_err(|e| CoreError::invalid_input(format!("invalid nevent: {e}")))?
        }
        Nip19EncodeTarget::Naddr => {
            let coordinate = parse_coordinate(&input, kind, identifier)?;
            let relays = parse_relays(relays.as_deref())?;
            Nip19Coordinate::new(coordinate, relays)
                .to_bech32()
                .map_err(|e| CoreError::invalid_input(format!("invalid naddr: {e}")))?
        }
    };

    Ok(Nip19EncodeResult {
        input,
        target,
        encoded,
    })
}

fn parse_public_key(value: &str) -> Result<PublicKey, CoreError> {
    PublicKey::parse(value.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid pubkey: {e}")))
}

fn parse_event_id(value: &str) -> Result<EventId, CoreError> {
    EventId::parse(value.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid event id: {e}")))
}

fn parse_secret_key(value: &str) -> Result<SecretKey, CoreError> {
    SecretKey::parse(value.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid secret key: {e}")))
}

fn parse_relays(values: Option<&[String]>) -> Result<Vec<RelayUrl>, CoreError> {
    let mut relays = Vec::new();
    if let Some(values) = values {
        for value in values {
            let relay = value.trim();
            if relay.is_empty() {
                return Err(CoreError::invalid_input("relay url must not be empty"));
            }
            let relay = RelayUrl::parse(relay)
                .map_err(|e| CoreError::invalid_input(format!("invalid relay url: {e}")))?;
            relays.push(relay);
        }
    }
    Ok(relays)
}

fn parse_coordinate(
    input: &str,
    kind: Option<u16>,
    identifier: Option<String>,
) -> Result<Coordinate, CoreError> {
    let coordinate = match Coordinate::parse(input) {
        Ok(coordinate) => coordinate,
        Err(err) => {
            if looks_like_coordinate(input) {
                return Err(CoreError::invalid_input(format!(
                    "invalid coordinate: {err}"
                )));
            }
            let kind = kind.ok_or_else(|| {
                CoreError::invalid_input("kind is required for naddr when input is a pubkey")
            })?;
            let identifier = identifier.unwrap_or_default();
            Coordinate {
                kind: Kind::from(kind),
                public_key: parse_public_key(input)?,
                identifier,
            }
        }
    };

    coordinate
        .verify()
        .map_err(|e| CoreError::invalid_input(format!("invalid coordinate: {e}")))?;

    Ok(coordinate)
}

fn looks_like_coordinate(value: &str) -> bool {
    if value.starts_with("nostr:") {
        return value.starts_with("nostr:naddr1");
    }

    value.starts_with("naddr1") || value.contains(':')
}

#[cfg(test)]
mod tests;

fn public_key_npub(public_key: &PublicKey) -> String {
    match public_key.to_bech32() {
        Ok(npub) => npub,
        Err(never) => match never {},
    }
}

fn secret_key_nsec(secret_key: &SecretKey) -> String {
    match secret_key.to_bech32() {
        Ok(nsec) => nsec,
        Err(never) => match never {},
    }
}

fn event_id_note(event_id: &EventId) -> String {
    match event_id.to_bech32() {
        Ok(note) => note,
        Err(never) => match never {},
    }
}
