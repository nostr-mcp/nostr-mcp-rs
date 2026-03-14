use crate::error::CoreError;
use base64::engine::{Engine, general_purpose};
use nostr::nips::nip44;
use nostr::prelude::{FromBech32, Keys, PublicKey, SecretKey, ToBech32};
use nostr_mcp_types::nip44::{
    Nip44DecryptArgs, Nip44DecryptResult, Nip44EncryptArgs, Nip44EncryptResult,
};

pub fn encrypt_nip44(args: Nip44EncryptArgs) -> Result<Nip44EncryptResult, CoreError> {
    let secret_key = parse_secret_key(&args.private_key)?;
    let public_key = parse_public_key(&args.public_key)?;
    let version = parse_version(args.version)?;
    let ciphertext = nip44::encrypt(&secret_key, &public_key, args.plaintext.as_bytes(), version)
        .map_err(|e| CoreError::Crypto(format!("nip44 encrypt: {e}")))?;
    let peer_public_key_npub = public_key_npub(&public_key);

    Ok(Nip44EncryptResult {
        ciphertext,
        version: version.as_u8(),
        peer_public_key_hex: public_key.to_hex(),
        peer_public_key_npub,
    })
}

pub fn decrypt_nip44(args: Nip44DecryptArgs) -> Result<Nip44DecryptResult, CoreError> {
    let secret_key = parse_secret_key(&args.private_key)?;
    let public_key = parse_public_key(&args.public_key)?;
    let version = payload_version(&args.ciphertext)?;
    let plaintext = nip44::decrypt(&secret_key, &public_key, &args.ciphertext)
        .map_err(|e| CoreError::Crypto(format!("nip44 decrypt: {e}")))?;
    let peer_public_key_npub = public_key_npub(&public_key);

    Ok(Nip44DecryptResult {
        plaintext,
        version,
        peer_public_key_hex: public_key.to_hex(),
        peer_public_key_npub,
    })
}

fn parse_version(value: Option<u8>) -> Result<nip44::Version, CoreError> {
    match value {
        Some(version) => nip44::Version::try_from(version)
            .map_err(|e| CoreError::invalid_input(format!("invalid nip44 version: {e}"))),
        None => Ok(nip44::Version::default()),
    }
}

fn payload_version(payload: &str) -> Result<u8, CoreError> {
    let bytes = general_purpose::STANDARD
        .decode(payload.as_bytes())
        .map_err(|e| CoreError::invalid_input(format!("invalid nip44 payload: {e}")))?;
    let version = bytes
        .first()
        .ok_or_else(|| CoreError::invalid_input("nip44 payload missing version"))?;
    nip44::Version::try_from(*version)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip44 version: {e}")))?;
    Ok(*version)
}

fn parse_secret_key(value: &str) -> Result<SecretKey, CoreError> {
    let value = value.trim();
    if value.starts_with("nsec1") {
        let keys = Keys::parse(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid nsec: {e}")))?;
        Ok(keys.secret_key().clone())
    } else if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        SecretKey::from_hex(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid secret key: {e}")))
    } else {
        Err(CoreError::invalid_input(
            "invalid private key format; expected nsec1... or 64-character hex",
        ))
    }
}

fn parse_public_key(value: &str) -> Result<PublicKey, CoreError> {
    let value = value.trim();
    if value.starts_with("npub1") {
        PublicKey::from_bech32(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid npub: {e}")))
    } else if value.len() == 64 {
        PublicKey::from_hex(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid public key: {e}")))
    } else {
        Err(CoreError::invalid_input(
            "invalid public key format; expected npub1... or 64-character hex",
        ))
    }
}

#[cfg(test)]
mod tests;

fn public_key_npub(public_key: &PublicKey) -> String {
    match public_key.to_bech32() {
        Ok(npub) => npub,
        Err(never) => match never {},
    }
}
