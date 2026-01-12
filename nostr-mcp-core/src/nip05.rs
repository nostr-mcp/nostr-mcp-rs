use crate::error::CoreError;
use nostr::nips::nip05::{verify_from_raw_json, Nip05Address, Nip05Profile};
use nostr::prelude::{FromBech32, PublicKey, ToBech32};
use reqwest::header::ACCEPT;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip05ResolveArgs {
    pub identifier: String,
    pub timeout_secs: Option<u64>,
}

impl Nip05ResolveArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Serialize)]
pub struct Nip05ResolveResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub pubkey_npub: String,
    pub relays: Vec<String>,
    pub nip46_relays: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Nip05VerifyArgs {
    pub identifier: String,
    pub pubkey: String,
    pub timeout_secs: Option<u64>,
}

impl Nip05VerifyArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Serialize)]
pub struct Nip05VerifyResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub valid: bool,
}

pub async fn resolve_nip05(
    args: Nip05ResolveArgs,
) -> Result<Nip05ResolveResult, CoreError> {
    let address = Nip05Address::parse(args.identifier.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 address: {e}")))?;
    let url = address.url().to_string();
    let raw_json = fetch_nip05_raw_json(&url, args.timeout()).await?;
    let profile = Nip05Profile::from_raw_json(&address, &raw_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 json: {e}")))?;
    let pubkey_npub = profile
        .public_key
        .to_bech32()
        .map_err(|e| CoreError::invalid_input(format!("invalid pubkey: {e}")))?;

    Ok(Nip05ResolveResult {
        identifier: address.to_string(),
        url,
        pubkey_hex: profile.public_key.to_hex(),
        pubkey_npub,
        relays: profile.relays.iter().map(|r| r.to_string()).collect(),
        nip46_relays: profile.nip46.iter().map(|r| r.to_string()).collect(),
    })
}

pub async fn verify_nip05(
    args: Nip05VerifyArgs,
) -> Result<Nip05VerifyResult, CoreError> {
    let address = Nip05Address::parse(args.identifier.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 address: {e}")))?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let url = address.url().to_string();
    let raw_json = fetch_nip05_raw_json(&url, args.timeout()).await?;
    let valid = verify_from_raw_json(&pubkey, &address, &raw_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 json: {e}")))?;

    Ok(Nip05VerifyResult {
        identifier: address.to_string(),
        url,
        pubkey_hex: pubkey.to_hex(),
        valid,
    })
}

fn parse_pubkey(value: &str) -> Result<PublicKey, CoreError> {
    let value = value.trim();
    if value.starts_with("npub1") {
        PublicKey::from_bech32(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid npub: {e}")))
    } else if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        PublicKey::from_hex(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid hex pubkey: {e}")))
    } else {
        Err(CoreError::invalid_input(
            "invalid pubkey format; expected npub1... or 64-character hex",
        ))
    }
}

async fn fetch_nip05_raw_json(url: &str, timeout_secs: u64) -> Result<String, CoreError> {
    let client = Client::new();
    let response = client
        .get(url)
        .header(ACCEPT, "application/json")
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|e| CoreError::Nostr(format!("nip05 request: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CoreError::Nostr(format!("nip05 body: {e}")))?;

    if !status.is_success() {
        return Err(CoreError::Nostr(format!(
            "nip05 status {}: {}",
            status.as_u16(),
            body
        )));
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{parse_pubkey, Nip05ResolveArgs};
    use nostr::nips::nip05::Nip05Address;
    use nostr::prelude::{Keys, ToBech32};

    #[test]
    fn parse_pubkey_accepts_npub_and_hex() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let hex = keys.public_key().to_hex();

        let parsed_npub = parse_pubkey(&npub).unwrap();
        let parsed_hex = parse_pubkey(&hex).unwrap();

        assert_eq!(parsed_npub, keys.public_key());
        assert_eq!(parsed_hex, keys.public_key());
    }

    #[test]
    fn nip05_address_builds_url() {
        let address = Nip05Address::parse("bob@example.com").unwrap();
        assert!(address.url().as_str().contains("/.well-known/nostr.json?name=bob"));
    }

    #[test]
    fn resolve_args_timeout_default() {
        let args = Nip05ResolveArgs {
            identifier: "bob@example.com".to_string(),
            timeout_secs: None,
        };

        assert_eq!(args.timeout(), 10);
    }
}
