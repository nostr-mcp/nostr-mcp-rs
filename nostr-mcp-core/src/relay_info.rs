use crate::error::CoreError;
use nostr::nips::nip11::RelayInformationDocument;
use nostr::JsonUtil;
use reqwest::header::ACCEPT;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelayInfoArgs {
    pub relay_url: String,
    pub timeout_secs: Option<u64>,
}

impl RelayInfoArgs {
    pub fn timeout(&self) -> u64 {
        self.timeout_secs.unwrap_or(10)
    }
}

#[derive(Debug, Serialize)]
pub struct RelayInfoResult {
    pub relay_url: String,
    pub http_url: String,
    pub status: u16,
    pub document: RelayInformationDocument,
}

pub async fn fetch_relay_info(args: RelayInfoArgs) -> Result<RelayInfoResult, CoreError> {
    let http_url = normalize_relay_http_url(&args.relay_url)?;
    let client = Client::new();
    let response = client
        .get(&http_url)
        .header(ACCEPT, "application/nostr+json")
        .timeout(Duration::from_secs(args.timeout()))
        .send()
        .await
        .map_err(|e| CoreError::Nostr(format!("relay info request: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CoreError::Nostr(format!("relay info body: {e}")))?;

    if !status.is_success() {
        return Err(CoreError::Nostr(format!(
            "relay info status {}: {}",
            status.as_u16(),
            body
        )));
    }

    let document = RelayInformationDocument::from_json(&body)
        .map_err(|e| CoreError::invalid_input(format!("invalid nip11 json: {e}")))?;

    Ok(RelayInfoResult {
        relay_url: args.relay_url,
        http_url,
        status: status.as_u16(),
        document,
    })
}

fn normalize_relay_http_url(input: &str) -> Result<String, CoreError> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return Ok(format!("https://{}", rest));
    }
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return Ok(format!("http://{}", rest));
    }
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return Ok(trimmed.to_string());
    }
    Err(CoreError::invalid_input(
        "relay_url must start with ws://, wss://, http://, or https://",
    ))
}

#[cfg(test)]
mod tests {
    use super::normalize_relay_http_url;

    #[test]
    fn normalize_relay_http_url_accepts_ws() {
        let url = normalize_relay_http_url("ws://relay.example").unwrap();
        assert_eq!(url, "http://relay.example");
    }

    #[test]
    fn normalize_relay_http_url_accepts_wss() {
        let url = normalize_relay_http_url("wss://relay.example").unwrap();
        assert_eq!(url, "https://relay.example");
    }

    #[test]
    fn normalize_relay_http_url_accepts_http() {
        let url = normalize_relay_http_url("https://relay.example").unwrap();
        assert_eq!(url, "https://relay.example");
    }

    #[test]
    fn normalize_relay_http_url_rejects_other_scheme() {
        let err = normalize_relay_http_url("ftp://relay.example").unwrap_err();
        assert!(err.to_string().contains("relay_url must start with"));
    }
}
