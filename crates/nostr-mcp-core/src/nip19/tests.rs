use super::{decode_nip19, encode_nip19};
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{Coordinate, EventId, Keys, Kind};
use nostr_mcp_types::nip19::{
    Nip19DecodeArgs, Nip19EncodeArgs, Nip19EncodeTarget, Nip19EntityType,
};

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
fn decode_accepts_hex_input() {
    let input = "a".repeat(64);
    let result = decode_nip19(Nip19DecodeArgs {
        input: input.clone(),
        allow_secret: None,
    })
    .unwrap();

    assert!(matches!(result.input_type, Nip19EntityType::Hex));
    assert_eq!(result.input, input);
    assert!(result.data.pubkey_hex.is_none());
}

#[test]
fn decode_accepts_nsec_when_enabled() {
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32().unwrap();
    let result = decode_nip19(Nip19DecodeArgs {
        input: nsec,
        allow_secret: Some(true),
    })
    .unwrap();

    assert!(matches!(result.input_type, Nip19EntityType::Nsec));
    assert!(result.data.is_secret);
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

#[test]
fn decode_rejects_invalid_entity() {
    let err = decode_nip19(Nip19DecodeArgs {
        input: "npub1invalid".to_string(),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid nip19 entity"));
}

#[test]
fn decode_rejects_non_hex_64_char_input() {
    let err = decode_nip19(Nip19DecodeArgs {
        input: "g".repeat(64),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid nip19 entity"));
}

#[test]
fn encode_npub_from_hex() {
    let keys = Keys::generate();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Npub,
        input: keys.public_key().to_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap();
    assert_eq!(result.encoded, keys.public_key().to_bech32().unwrap());
}

#[test]
fn encode_npub_from_npub() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().unwrap();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Npub,
        input: npub.clone(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap();

    assert_eq!(result.encoded, npub);
}

#[test]
fn encode_npub_rejects_invalid_pubkey() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Npub,
        input: "bad-pubkey".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid pubkey"));
}

#[test]
fn encode_nsec_requires_allow_secret() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nsec,
        input: keys.secret_key().to_secret_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: Some(false),
    })
    .unwrap_err();
    assert!(err.to_string().contains("allow_secret"));
}

#[test]
fn encode_nsec_when_enabled() {
    let keys = Keys::generate();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nsec,
        input: keys.secret_key().to_secret_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: Some(true),
    })
    .unwrap();

    assert_eq!(result.encoded, keys.secret_key().to_bech32().unwrap());
}

#[test]
fn encode_note_round_trip() {
    let event_id = EventId::all_zeros();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Note,
        input: event_id.to_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();

    assert!(matches!(decoded.input_type, Nip19EntityType::Note));
    assert_eq!(decoded.data.event_id_hex, Some(event_id.to_hex()));
}

#[test]
fn encode_nprofile_round_trip() {
    let keys = Keys::generate();
    let relay = "wss://relay.example.com".to_string();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nprofile,
        input: keys.public_key().to_hex(),
        relays: Some(vec![relay.clone()]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();
    assert!(matches!(decoded.input_type, Nip19EntityType::Nprofile));
    assert_eq!(decoded.data.pubkey_hex, Some(keys.public_key().to_hex()));
    assert_eq!(decoded.data.relays, Some(vec![relay]));
}

#[test]
fn encode_nprofile_rejects_invalid_relay() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nprofile,
        input: keys.public_key().to_hex(),
        relays: Some(vec!["not-a-relay".to_string()]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid relay url"));
}

#[test]
fn encode_nprofile_rejects_empty_relay_url() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nprofile,
        input: keys.public_key().to_hex(),
        relays: Some(vec![" ".to_string()]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("relay url must not be empty"));
}

#[test]
fn encode_nprofile_rejects_invalid_pubkey() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nprofile,
        input: "bad-pubkey".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid pubkey"));
}

#[test]
fn encode_nprofile_rejects_too_long_relay_payload() {
    let keys = Keys::generate();
    let relay = format!("wss://relay.example.com/{}", "a".repeat(1200));
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nprofile,
        input: keys.public_key().to_hex(),
        relays: Some(vec![relay]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid nprofile"));
}

#[test]
fn encode_nevent_round_trip() {
    let event_id = EventId::all_zeros();
    let keys = Keys::generate();
    let relay = "wss://relay.example.com".to_string();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: event_id.to_hex(),
        relays: Some(vec![relay.clone()]),
        author: Some(keys.public_key().to_hex()),
        kind: Some(1),
        identifier: None,
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();
    assert!(matches!(decoded.input_type, Nip19EntityType::Nevent));
    assert_eq!(decoded.data.event_id_hex, Some(event_id.to_hex()));
    assert_eq!(decoded.data.author_hex, Some(keys.public_key().to_hex()));
    assert_eq!(decoded.data.kind, Some(1));
    assert_eq!(decoded.data.relays, Some(vec![relay]));
}

#[test]
fn encode_nevent_rejects_too_long_relay_payload() {
    let relay = format!("wss://relay.example.com/{}", "a".repeat(1200));
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: EventId::all_zeros().to_hex(),
        relays: Some(vec![relay]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid nevent"));
}

#[test]
fn encode_nevent_rejects_invalid_event_id() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: "bad-event-id".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid event id"));
}

#[test]
fn encode_nevent_rejects_invalid_relay() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: EventId::all_zeros().to_hex(),
        relays: Some(vec!["not-a-relay".to_string()]),
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid relay url"));
}

#[test]
fn encode_nevent_without_optional_fields() {
    let event_id = EventId::all_zeros();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: event_id.to_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();

    assert!(matches!(decoded.input_type, Nip19EntityType::Nevent));
    assert_eq!(decoded.data.event_id_hex, Some(event_id.to_hex()));
    assert_eq!(decoded.data.author_hex, None);
    assert_eq!(decoded.data.kind, None);
    assert_eq!(decoded.data.relays, Some(vec![]));
}

#[test]
fn encode_nevent_rejects_invalid_author() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nevent,
        input: EventId::all_zeros().to_hex(),
        relays: None,
        author: Some("bad-author".to_string()),
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid pubkey"));
}

#[test]
fn encode_naddr_from_parts() {
    let keys = Keys::generate();
    let relay = "wss://relay.example.com".to_string();
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: keys.public_key().to_hex(),
        relays: Some(vec![relay.clone()]),
        author: None,
        kind: Some(30000),
        identifier: Some("profile".to_string()),
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();
    assert!(matches!(decoded.input_type, Nip19EntityType::Naddr));
    assert_eq!(decoded.data.pubkey_hex, Some(keys.public_key().to_hex()));
    assert_eq!(decoded.data.kind, Some(30000));
    assert_eq!(decoded.data.identifier, Some("profile".to_string()));
    assert_eq!(decoded.data.relays, Some(vec![relay]));
}

#[test]
fn encode_naddr_from_coordinate_input() {
    let keys = Keys::generate();
    let coordinate = Coordinate {
        kind: Kind::from(30000_u16),
        public_key: keys.public_key(),
        identifier: "profile".to_string(),
    };
    let result = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: coordinate.to_string(),
        relays: None,
        author: None,
        kind: Some(1),
        identifier: Some("ignored".to_string()),
        allow_secret: None,
    })
    .unwrap();

    let decoded = decode_nip19(Nip19DecodeArgs {
        input: result.encoded,
        allow_secret: None,
    })
    .unwrap();

    assert!(matches!(decoded.input_type, Nip19EntityType::Naddr));
    assert_eq!(decoded.data.pubkey_hex, Some(keys.public_key().to_hex()));
    assert_eq!(decoded.data.kind, Some(30000));
    assert_eq!(decoded.data.identifier, Some("profile".to_string()));
}

#[test]
fn encode_naddr_requires_kind_for_pubkey_input() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: keys.public_key().to_hex(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("kind is required for naddr"));
}

#[test]
fn encode_naddr_rejects_invalid_coordinate() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: "30000:not-a-pubkey:profile".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid coordinate"));
}

#[test]
fn encode_naddr_rejects_invalid_nostr_coordinate() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: "nostr:naddr1invalid".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid coordinate"));
}

#[test]
fn encode_naddr_rejects_invalid_bare_bech32_coordinate() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: "naddr1invalid".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid coordinate"));
}

#[test]
fn encode_naddr_rejects_non_addressable_kind() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: keys.public_key().to_hex(),
        relays: None,
        author: None,
        kind: Some(1),
        identifier: Some("profile".to_string()),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid coordinate"));
}

#[test]
fn encode_naddr_rejects_invalid_pubkey_input_with_kind() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: "bad-pubkey".to_string(),
        relays: None,
        author: None,
        kind: Some(30023),
        identifier: Some("article".to_string()),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid pubkey"));
}

#[test]
fn encode_naddr_rejects_too_long_identifier_payload() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: keys.public_key().to_hex(),
        relays: None,
        author: None,
        kind: Some(30000),
        identifier: Some("a".repeat(1200)),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid naddr"));
}

#[test]
fn encode_naddr_rejects_invalid_relay() {
    let keys = Keys::generate();
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Naddr,
        input: keys.public_key().to_hex(),
        relays: Some(vec!["not-a-relay".to_string()]),
        author: None,
        kind: Some(30023),
        identifier: Some("article".to_string()),
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid relay url"));
}

#[test]
fn encode_rejects_empty_input() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Npub,
        input: " ".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("input must not be empty"));
}

#[test]
fn encode_note_rejects_invalid_event_id() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Note,
        input: "bad-event-id".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: None,
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid event id"));
}

#[test]
fn encode_nsec_rejects_invalid_secret_key() {
    let err = encode_nip19(Nip19EncodeArgs {
        target: Nip19EncodeTarget::Nsec,
        input: "nsec1invalid".to_string(),
        relays: None,
        author: None,
        kind: None,
        identifier: None,
        allow_secret: Some(true),
    })
    .unwrap_err();

    assert!(err.to_string().contains("invalid secret key"));
}
