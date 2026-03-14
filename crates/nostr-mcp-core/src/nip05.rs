use crate::error::CoreError;
use nostr::nips::nip05::{Nip05Address, Nip05Profile, verify_from_raw_json};
use nostr::prelude::{FromBech32, PublicKey, ToBech32};
use nostr_mcp_types::nip05::{
    Nip05ResolveArgs, Nip05ResolveResult, Nip05VerifyArgs, Nip05VerifyResult,
};
use reqwest::Client;
use reqwest::header::ACCEPT;
use std::time::Duration;

pub async fn resolve_nip05(args: Nip05ResolveArgs) -> Result<Nip05ResolveResult, CoreError> {
    resolve_nip05_with_client(&Client::new(), args).await
}

async fn resolve_nip05_with_client(
    client: &Client,
    args: Nip05ResolveArgs,
) -> Result<Nip05ResolveResult, CoreError> {
    let address = Nip05Address::parse(args.identifier.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 address: {e}")))?;
    let url = address.url().to_string();

    resolve_nip05_from_url_and_address(client, &address, &url, args.timeout()).await
}

async fn resolve_nip05_from_url_and_address(
    client: &Client,
    address: &Nip05Address,
    url: &str,
    timeout_secs: u64,
) -> Result<Nip05ResolveResult, CoreError> {
    let raw_json = fetch_nip05_raw_json(client, url, timeout_secs).await?;
    let profile = Nip05Profile::from_raw_json(address, &raw_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 json: {e}")))?;
    let pubkey_npub = public_key_npub(&profile.public_key);

    Ok(Nip05ResolveResult {
        identifier: address.to_string(),
        url: url.to_string(),
        pubkey_hex: profile.public_key.to_hex(),
        pubkey_npub,
        relays: profile.relays.iter().map(|r| r.to_string()).collect(),
        nip46_relays: profile.nip46.iter().map(|r| r.to_string()).collect(),
    })
}

pub async fn verify_nip05(args: Nip05VerifyArgs) -> Result<Nip05VerifyResult, CoreError> {
    verify_nip05_with_client(&Client::new(), args).await
}

async fn verify_nip05_with_client(
    client: &Client,
    args: Nip05VerifyArgs,
) -> Result<Nip05VerifyResult, CoreError> {
    let address = Nip05Address::parse(args.identifier.trim())
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 address: {e}")))?;
    let pubkey = parse_pubkey(&args.pubkey)?;
    let url = address.url().to_string();

    verify_nip05_from_url_and_address(client, &address, &pubkey, &url, args.timeout()).await
}

async fn verify_nip05_from_url_and_address(
    client: &Client,
    address: &Nip05Address,
    pubkey: &PublicKey,
    url: &str,
    timeout_secs: u64,
) -> Result<Nip05VerifyResult, CoreError> {
    let raw_json = fetch_nip05_raw_json(client, url, timeout_secs).await?;
    let valid = verify_from_raw_json(pubkey, address, &raw_json)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip05 json: {e}")))?;

    Ok(Nip05VerifyResult {
        identifier: address.to_string(),
        url: url.to_string(),
        pubkey_hex: pubkey.to_hex(),
        valid,
    })
}

fn parse_pubkey(value: &str) -> Result<PublicKey, CoreError> {
    let value = value.trim();
    if value.starts_with("npub1") {
        PublicKey::from_bech32(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid npub: {e}")))
    } else if value.len() == 64 {
        PublicKey::from_hex(value)
            .map_err(|e| CoreError::invalid_input(format!("invalid hex pubkey: {e}")))
    } else {
        Err(CoreError::invalid_input(
            "invalid pubkey format; expected npub1... or 64-character hex",
        ))
    }
}

async fn fetch_nip05_raw_json(
    client: &Client,
    url: &str,
    timeout_secs: u64,
) -> Result<String, CoreError> {
    let response = client
        .get(url)
        .header(ACCEPT, "application/json")
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|e| CoreError::operation(format!("nip05 request: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CoreError::operation(format!("nip05 body: {e}")))?;

    if !status.is_success() {
        return Err(CoreError::operation(format!(
            "nip05 status {}: {}",
            status.as_u16(),
            body
        )));
    }

    Ok(body)
}

#[cfg(test)]
mod tests;

fn public_key_npub(public_key: &PublicKey) -> String {
    match public_key.to_bech32() {
        Ok(npub) => npub,
        Err(never) => match never {},
    }
}
