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
    let pubkey_npub = profile
        .public_key
        .to_bech32()
        .map_err(|e| CoreError::invalid_input(format!("invalid pubkey: {e}")))?;

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
mod tests {
    use super::{
        fetch_nip05_raw_json, parse_pubkey, resolve_nip05, resolve_nip05_from_url_and_address,
        resolve_nip05_with_client, verify_nip05, verify_nip05_from_url_and_address,
        verify_nip05_with_client,
    };
    use nostr::nips::nip05::Nip05Address;
    use nostr::prelude::{Keys, SecretKey, ToBech32};
    use nostr_mcp_types::nip05::{Nip05ResolveArgs, Nip05VerifyArgs};
    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn fixed_keys() -> Keys {
        Keys::new(
            SecretKey::from_hex(
                "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
            )
            .unwrap(),
        )
    }

    fn nip05_json(name: &str, pubkey_hex: &str, relays: &[&str], nip46_relays: &[&str]) -> String {
        let relays = relays
            .iter()
            .map(|relay| format!("\"{relay}\""))
            .collect::<Vec<_>>()
            .join(",");
        let nip46_relays = nip46_relays
            .iter()
            .map(|relay| format!("\"{relay}\""))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"names\":{{\"{name}\":\"{pubkey_hex}\"}},\"relays\":{{\"{pubkey_hex}\":[{relays}]}},\"nip46\":{{\"{pubkey_hex}\":[{nip46_relays}]}}}}"
        )
    }

    #[test]
    fn parse_pubkey_accepts_npub_and_hex() {
        let keys = fixed_keys();
        let npub = keys.public_key().to_bech32().unwrap();
        let hex = keys.public_key().to_hex();

        let parsed_npub = parse_pubkey(&npub).unwrap();
        let parsed_hex = parse_pubkey(&hex).unwrap();

        assert_eq!(parsed_npub, keys.public_key());
        assert_eq!(parsed_hex, keys.public_key());
    }

    #[test]
    fn parse_pubkey_rejects_invalid_npub() {
        let err = parse_pubkey("npub1invalid").unwrap_err();

        assert!(err.to_string().contains("invalid npub"));
    }

    #[test]
    fn parse_pubkey_rejects_invalid_hex_pubkey() {
        let err = parse_pubkey(&"g".repeat(64)).unwrap_err();

        assert!(err.to_string().contains("invalid hex pubkey"));
    }

    #[test]
    fn parse_pubkey_rejects_invalid_format() {
        let err = parse_pubkey("bad-pubkey").unwrap_err();

        assert!(err.to_string().contains("invalid pubkey format"));
    }

    #[test]
    fn nip05_address_builds_url() {
        let address = Nip05Address::parse("bob@example.com").unwrap();
        assert!(
            address
                .url()
                .as_str()
                .contains("/.well-known/nostr.json?name=bob")
        );
    }

    #[test]
    fn resolve_args_timeout_default() {
        let args = Nip05ResolveArgs {
            identifier: "bob@example.com".to_string(),
            timeout_secs: None,
        };

        assert_eq!(args.timeout(), 10);
    }

    #[tokio::test]
    async fn resolve_nip05_reads_profile_from_raw_json() {
        let keys = fixed_keys();
        let http_url = spawn_single_response_server(
            "200 OK",
            &nip05_json(
                "bob",
                &keys.public_key().to_hex(),
                &["wss://relay.example.com"],
                &["wss://relay.nip46.example.com"],
            ),
            "application/json",
        )
        .await;
        let address = Nip05Address::parse("bob@example.com").unwrap();

        let result =
            resolve_nip05_from_url_and_address(&Client::new(), &address, &http_url, 1).await.unwrap();

        assert_eq!(result.identifier, "bob@example.com");
        assert_eq!(result.url, http_url);
        assert_eq!(result.pubkey_hex, keys.public_key().to_hex());
        assert_eq!(result.pubkey_npub, keys.public_key().to_bech32().unwrap());
        assert_eq!(result.relays, vec!["wss://relay.example.com"]);
        assert_eq!(result.nip46_relays, vec!["wss://relay.nip46.example.com"]);
    }

    #[tokio::test]
    async fn verify_nip05_returns_true_for_matching_pubkey() {
        let keys = fixed_keys();
        let http_url = spawn_single_response_server(
            "200 OK",
            &nip05_json("bob", &keys.public_key().to_hex(), &[], &[]),
            "application/json",
        )
        .await;
        let address = Nip05Address::parse("bob@example.com").unwrap();

        let result = verify_nip05_from_url_and_address(
            &Client::new(),
            &address,
            &keys.public_key(),
            &http_url,
            1,
        )
        .await
        .unwrap();

        assert_eq!(result.identifier, "bob@example.com");
        assert_eq!(result.url, http_url);
        assert_eq!(result.pubkey_hex, keys.public_key().to_hex());
        assert!(result.valid);
    }

    #[tokio::test]
    async fn verify_nip05_returns_false_for_mismatched_pubkey() {
        let keys = fixed_keys();
        let other_keys = Keys::generate();
        let http_url = spawn_single_response_server(
            "200 OK",
            &nip05_json("bob", &keys.public_key().to_hex(), &[], &[]),
            "application/json",
        )
        .await;
        let address = Nip05Address::parse("bob@example.com").unwrap();

        let result = verify_nip05_from_url_and_address(
            &Client::new(),
            &address,
            &other_keys.public_key(),
            &http_url,
            1,
        )
        .await
        .unwrap();

        assert!(!result.valid);
    }

    #[tokio::test]
    async fn resolve_nip05_rejects_invalid_identifier() {
        assert!(
            resolve_nip05(Nip05ResolveArgs {
                identifier: "".to_string(),
                timeout_secs: Some(1),
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn verify_nip05_rejects_invalid_identifier() {
        assert!(
            verify_nip05(Nip05VerifyArgs {
                identifier: "".to_string(),
                pubkey: fixed_keys().public_key().to_hex(),
                timeout_secs: Some(1),
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn verify_nip05_rejects_invalid_pubkey_format() {
        let err = verify_nip05(Nip05VerifyArgs {
            identifier: "bob@example.com".to_string(),
            pubkey: "bad-pubkey".to_string(),
            timeout_secs: Some(1),
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid pubkey format"));
    }

    #[tokio::test]
    async fn verify_nip05_rejects_invalid_npub() {
        let err = verify_nip05(Nip05VerifyArgs {
            identifier: "bob@example.com".to_string(),
            pubkey: "npub1invalid".to_string(),
            timeout_secs: Some(1),
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid npub"));
    }

    #[tokio::test]
    async fn verify_nip05_rejects_invalid_hex_pubkey() {
        let err = verify_nip05(Nip05VerifyArgs {
            identifier: "bob@example.com".to_string(),
            pubkey: "g".repeat(64),
            timeout_secs: Some(1),
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid hex pubkey"));
    }

    #[tokio::test]
    async fn resolve_nip05_rejects_invalid_json() {
        let http_url = spawn_single_response_server("200 OK", "{}", "application/json").await;
        let address = Nip05Address::parse("bob@example.com").unwrap();
        let err =
            resolve_nip05_from_url_and_address(&Client::new(), &address, &http_url, 1)
                .await
                .unwrap_err();

        assert!(err.to_string().contains("invalid nip05 json"));
    }

    #[tokio::test]
    async fn verify_nip05_rejects_invalid_json() {
        let keys = fixed_keys();
        let http_url = spawn_single_response_server("200 OK", "{", "application/json").await;
        let address = Nip05Address::parse("bob@example.com").unwrap();
        let err = verify_nip05_from_url_and_address(
            &Client::new(),
            &address,
            &keys.public_key(),
            &http_url,
            1,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("invalid nip05 json"));
    }

    #[tokio::test]
    async fn fetch_nip05_raw_json_returns_body() {
        let http_url =
            spawn_single_response_server("200 OK", "{\"names\":{}}", "application/json").await;
        let body = fetch_nip05_raw_json(&Client::new(), &http_url, 1)
            .await
            .unwrap();

        assert_eq!(body, "{\"names\":{}}");
    }

    #[tokio::test]
    async fn fetch_nip05_raw_json_surfaces_status_errors() {
        let http_url =
            spawn_single_response_server("404 Not Found", "missing", "text/plain").await;
        let err = fetch_nip05_raw_json(&Client::new(), &http_url, 1)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("nip05 status 404: missing"));
    }

    #[tokio::test]
    async fn fetch_nip05_raw_json_surfaces_request_errors() {
        let err = fetch_nip05_raw_json(&Client::new(), "http://127.0.0.1:1", 1)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("nip05 request"));
    }

    #[tokio::test]
    async fn fetch_nip05_raw_json_surfaces_body_errors() {
        let http_url =
            spawn_truncated_response_server("200 OK", "{\"names\":{}}", "application/json", 32)
                .await;
        let err = fetch_nip05_raw_json(&Client::new(), &http_url, 1)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("nip05 body"));
    }

    #[tokio::test]
    async fn resolve_nip05_wrapper_calls_inner_client_path() {
        assert!(
            resolve_nip05_with_client(
                &Client::new(),
                Nip05ResolveArgs {
                    identifier: "".to_string(),
                    timeout_secs: Some(1),
                },
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn verify_nip05_wrapper_calls_inner_client_path() {
        assert!(
            verify_nip05_with_client(
                &Client::new(),
                Nip05VerifyArgs {
                    identifier: "".to_string(),
                    pubkey: fixed_keys().public_key().to_hex(),
                    timeout_secs: Some(1),
                },
            )
            .await
            .is_err()
        );
    }

    async fn spawn_single_response_server(
        status: &str,
        body: &str,
        content_type: &str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        let content_type = content_type.to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        format!("http://{address}")
    }

    async fn spawn_truncated_response_server(
        status: &str,
        body: &str,
        content_type: &str,
        announced_length: usize,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        let content_type = content_type.to_string();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {announced_length}\r\nconnection: close\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        format!("http://{address}")
    }
}
