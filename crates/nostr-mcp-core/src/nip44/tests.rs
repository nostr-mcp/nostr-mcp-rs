use super::{decrypt_nip44, encrypt_nip44, parse_public_key, parse_secret_key, payload_version};
use crate::error::CoreError;
use base64::engine::{Engine, general_purpose};
use nostr::prelude::{Keys, SecretKey, ToBech32};
use nostr_mcp_types::nip44::{Nip44DecryptArgs, Nip44EncryptArgs};

fn fixed_keypair(hex: &str) -> Keys {
    Keys::new(SecretKey::from_hex(hex).unwrap())
}

#[test]
fn nip44_encrypt_decrypt_round_trip() {
    let alice_keys =
        fixed_keypair("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a");
    let bob_keys =
        fixed_keypair("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d");

    let plaintext = "hello nip44";
    let encrypted = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice_keys.secret_key().to_bech32().unwrap(),
        public_key: bob_keys.public_key().to_bech32().unwrap(),
        plaintext: plaintext.to_string(),
        version: None,
    })
    .unwrap();

    let decrypted = decrypt_nip44(Nip44DecryptArgs {
        private_key: bob_keys.secret_key().to_bech32().unwrap(),
        public_key: alice_keys.public_key().to_bech32().unwrap(),
        ciphertext: encrypted.ciphertext,
    })
    .unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.version, 2);
}

#[test]
fn nip44_encrypt_decrypt_round_trip_with_hex_keys() {
    let alice_keys =
        fixed_keypair("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a");
    let bob_keys =
        fixed_keypair("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d");

    let encrypted = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice_keys.secret_key().to_secret_hex(),
        public_key: bob_keys.public_key().to_hex(),
        plaintext: "hello hex".to_string(),
        version: Some(2),
    })
    .unwrap();

    let decrypted = decrypt_nip44(Nip44DecryptArgs {
        private_key: bob_keys.secret_key().to_secret_hex(),
        public_key: alice_keys.public_key().to_hex(),
        ciphertext: encrypted.ciphertext,
    })
    .unwrap();

    assert_eq!(decrypted.plaintext, "hello hex");
    assert_eq!(decrypted.version, 2);
}

#[test]
fn payload_version_reads_v2() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let encrypted = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: bob.public_key().to_bech32().unwrap(),
        plaintext: "test".to_string(),
        version: Some(2),
    })
    .unwrap();

    let version = payload_version(&encrypted.ciphertext).unwrap();
    assert_eq!(version, 2);
}

#[test]
fn encrypt_rejects_invalid_version() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let err = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: bob.public_key().to_bech32().unwrap(),
        plaintext: "test".to_string(),
        version: Some(1),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid nip44 version"));
}

#[test]
fn encrypt_rejects_invalid_private_key_before_crypto() {
    let bob = Keys::generate();
    let err = encrypt_nip44(Nip44EncryptArgs {
        private_key: "not-a-key".to_string(),
        public_key: bob.public_key().to_bech32().unwrap(),
        plaintext: "test".to_string(),
        version: Some(2),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid private key format"));
}

#[test]
fn encrypt_rejects_invalid_public_key_before_crypto() {
    let alice = Keys::generate();
    let err = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: "not-a-pubkey".to_string(),
        plaintext: "test".to_string(),
        version: Some(2),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid public key format"));
}

#[test]
fn decrypt_rejects_wrong_peer_key_as_crypto_error() {
    let alice = fixed_keypair("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a");
    let bob = fixed_keypair("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d");
    let mallory = fixed_keypair("9b0f1db8f263c28228477d5cfdf43cbfef834f18b29a8e65ec0d8d708db1d501");
    let encrypted = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: bob.public_key().to_bech32().unwrap(),
        plaintext: "test".to_string(),
        version: Some(2),
    })
    .unwrap();

    let err = decrypt_nip44(Nip44DecryptArgs {
        private_key: bob.secret_key().to_bech32().unwrap(),
        public_key: mallory.public_key().to_bech32().unwrap(),
        ciphertext: encrypted.ciphertext,
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::Crypto(_)));
    assert!(err.to_string().contains("nip44 decrypt"));
}

#[test]
fn decrypt_rejects_invalid_private_key_before_payload_parse() {
    let alice = Keys::generate();
    let err = decrypt_nip44(Nip44DecryptArgs {
        private_key: "not-a-key".to_string(),
        public_key: alice.public_key().to_bech32().unwrap(),
        ciphertext: "not-base64".to_string(),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid private key format"));
}

#[test]
fn decrypt_rejects_invalid_public_key_before_payload_parse() {
    let alice = Keys::generate();
    let err = decrypt_nip44(Nip44DecryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: "not-a-pubkey".to_string(),
        ciphertext: "not-base64".to_string(),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid public key format"));
}

#[test]
fn decrypt_rejects_invalid_payload_before_crypto() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let err = decrypt_nip44(Nip44DecryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: bob.public_key().to_bech32().unwrap(),
        ciphertext: "not-base64".to_string(),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid nip44 payload"));
}

#[test]
fn parse_secret_key_rejects_invalid() {
    let err = parse_secret_key("not-a-key").unwrap_err();
    assert!(err.to_string().contains("invalid private key format"));
}

#[test]
fn parse_secret_key_accepts_nsec_and_hex() {
    let keys = Keys::generate();
    let from_nsec = parse_secret_key(&keys.secret_key().to_bech32().unwrap()).unwrap();
    let from_hex = parse_secret_key(&keys.secret_key().to_secret_hex()).unwrap();

    assert_eq!(from_nsec, *keys.secret_key());
    assert_eq!(from_hex, *keys.secret_key());
}

#[test]
fn parse_secret_key_rejects_invalid_nsec() {
    let err = parse_secret_key("nsec1invalid").unwrap_err();

    assert!(err.to_string().contains("invalid nsec"));
}

#[test]
fn parse_secret_key_rejects_invalid_hex_secret() {
    let err = parse_secret_key(&"0".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("invalid secret key"));
}

#[test]
fn parse_secret_key_rejects_non_hex_64_char_secret() {
    let err = parse_secret_key(&"g".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("invalid private key format"));
}

#[test]
fn parse_public_key_rejects_invalid() {
    let err = parse_public_key("not-a-pubkey").unwrap_err();
    assert!(err.to_string().contains("invalid public key format"));
}

#[test]
fn parse_public_key_accepts_npub_and_hex() {
    let keys = Keys::generate();
    let from_npub = parse_public_key(&keys.public_key().to_bech32().unwrap()).unwrap();
    let from_hex = parse_public_key(&keys.public_key().to_hex()).unwrap();

    assert_eq!(from_npub, keys.public_key());
    assert_eq!(from_hex, keys.public_key());
}

#[test]
fn parse_public_key_rejects_invalid_npub() {
    let err = parse_public_key("npub1invalid").unwrap_err();

    assert!(err.to_string().contains("invalid npub"));
}

#[test]
fn parse_public_key_rejects_invalid_hex_public_key() {
    let err = parse_public_key(&"g".repeat(64)).unwrap_err();

    assert!(err.to_string().contains("invalid public key"));
}

#[test]
fn payload_version_rejects_invalid_base64_as_invalid_input() {
    let err = payload_version("not-base64").unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid nip44 payload"));
}

#[test]
fn payload_version_rejects_missing_version() {
    let err = payload_version(&general_purpose::STANDARD.encode([])).unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("missing version"));
}

#[test]
fn payload_version_rejects_invalid_version() {
    let err = payload_version(&general_purpose::STANDARD.encode([1_u8])).unwrap_err();

    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(err.to_string().contains("invalid nip44 version"));
}

#[test]
fn encrypt_rejects_empty_plaintext_as_crypto_error() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let err = encrypt_nip44(Nip44EncryptArgs {
        private_key: alice.secret_key().to_bech32().unwrap(),
        public_key: bob.public_key().to_bech32().unwrap(),
        plaintext: String::new(),
        version: Some(2),
    })
    .unwrap_err();

    assert!(matches!(err, CoreError::Crypto(_)));
    assert!(err.to_string().contains("nip44 encrypt"));
}
