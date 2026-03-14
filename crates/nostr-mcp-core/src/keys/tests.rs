use super::{derive_public, verify_key};
use nostr::prelude::*;
use nostr_mcp_types::keys::KeyType;

#[test]
fn verify_key_accepts_npub() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().unwrap();
    let result = verify_key(&npub);

    assert!(result.valid);
    assert!(matches!(result.key_type, KeyType::Npub));
    assert_eq!(result.public_key_npub.as_deref(), Some(npub.as_str()));
    assert_eq!(
        result.public_key_hex.as_deref(),
        Some(keys.public_key().to_hex().as_str())
    );
}

#[test]
fn verify_key_accepts_nsec() {
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32().unwrap();
    let pubkey_npub = keys.public_key().to_bech32().unwrap();
    let result = verify_key(&nsec);

    assert!(result.valid);
    assert!(matches!(result.key_type, KeyType::Nsec));
    assert_eq!(
        result.public_key_npub.as_deref(),
        Some(pubkey_npub.as_str())
    );
    assert_eq!(
        result.public_key_hex.as_deref(),
        Some(keys.public_key().to_hex().as_str())
    );
}

#[test]
fn verify_key_accepts_hex() {
    let keys = Keys::generate();
    let hex = keys.public_key().to_hex();
    let pubkey_npub = keys.public_key().to_bech32().unwrap();
    let result = verify_key(&hex);

    assert!(result.valid);
    assert!(matches!(result.key_type, KeyType::Hex));
    assert_eq!(
        result.public_key_npub.as_deref(),
        Some(pubkey_npub.as_str())
    );
    assert_eq!(result.public_key_hex.as_deref(), Some(hex.as_str()));
}

#[test]
fn verify_key_trims_input() {
    let keys = Keys::generate();
    let hex = format!("  {}  ", keys.public_key().to_hex());

    let result = verify_key(&hex);

    assert!(result.valid);
    assert_eq!(result.input, keys.public_key().to_hex());
}

#[test]
fn verify_key_rejects_invalid_npub() {
    let result = verify_key("npub1invalid");

    assert!(!result.valid);
    assert!(matches!(result.key_type, KeyType::Npub));
    assert!(result.error.is_some());
}

#[test]
fn verify_key_rejects_invalid_nsec() {
    let result = verify_key("nsec1invalid");

    assert!(!result.valid);
    assert!(matches!(result.key_type, KeyType::Nsec));
    assert!(result.error.is_some());
}

#[test]
fn verify_key_rejects_invalid_hex_public_key() {
    let result = verify_key(&"g".repeat(64));

    assert!(!result.valid);
    assert!(matches!(result.key_type, KeyType::Hex));
    assert!(result.error.is_some());
}

#[test]
fn verify_key_rejects_invalid_format() {
    let result = verify_key("not-a-key");

    assert!(!result.valid);
    assert!(matches!(result.key_type, KeyType::Invalid));
    assert!(
        result
            .error
            .unwrap()
            .contains("Unrecognized key format. Expected npub1..., nsec1..., or 64-character hex")
    );
}

#[test]
fn derive_public_accepts_nsec_and_hex() {
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32().unwrap();
    let hex = keys.secret_key().to_secret_hex();

    let derived_from_nsec = derive_public(&nsec).unwrap();
    assert_eq!(derived_from_nsec.public_key_hex, keys.public_key().to_hex());
    assert_eq!(
        derived_from_nsec.public_key_npub,
        keys.public_key().to_bech32().unwrap()
    );

    let derived_from_hex = derive_public(&hex).unwrap();
    assert_eq!(derived_from_hex.public_key_hex, keys.public_key().to_hex());
    assert_eq!(
        derived_from_hex.public_key_npub,
        keys.public_key().to_bech32().unwrap()
    );
}

#[test]
fn derive_public_rejects_invalid_format() {
    let err = derive_public("not-a-key").unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid input: Invalid private key format. Expected nsec1... or 64-character hex"
    );
}

#[test]
fn derive_public_rejects_invalid_nsec() {
    let err = derive_public("nsec1invalid").unwrap_err();

    assert!(err.to_string().contains("invalid input"));
}

#[test]
fn derive_public_rejects_invalid_hex_secret() {
    let err = derive_public(&"0".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("invalid input"));
}

#[test]
fn derive_public_rejects_non_hex_64_char_secret() {
    let err = derive_public(&"g".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("Invalid private key format"));
}
