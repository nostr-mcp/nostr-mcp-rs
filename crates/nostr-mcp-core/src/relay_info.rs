use crate::error::CoreError;
use nostr::JsonUtil;
use nostr::nips::nip11::RelayInformationDocument;
use nostr_mcp_types::relay_info::RelayInfoArgs;
use nostr_mcp_types::relay_info::RelayInfoResult;
use reqwest::Client;
use reqwest::header::ACCEPT;
use std::time::Duration;

pub async fn fetch_relay_info(args: RelayInfoArgs) -> Result<RelayInfoResult, CoreError> {
    let http_url = normalize_relay_http_url(&args.relay_url)?;
    let client = Client::new();
    let response = client
        .get(&http_url)
        .header(ACCEPT, "application/nostr+json")
        .timeout(Duration::from_secs(args.timeout()))
        .send()
        .await
        .map_err(|e| CoreError::operation(format!("relay info request: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| CoreError::operation(format!("relay info body: {e}")))?;

    if !status.is_success() {
        return Err(CoreError::operation(format!(
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
        return Ok(format!("https://{rest}"));
    }
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return Ok(format!("http://{rest}"));
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
    use super::{fetch_relay_info, normalize_relay_http_url};
    use nostr_mcp_types::relay_info::RelayInfoArgs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
    fn normalize_relay_http_url_accepts_plain_http() {
        let url = normalize_relay_http_url("http://relay.example").unwrap();
        assert_eq!(url, "http://relay.example");
    }

    #[test]
    fn normalize_relay_http_url_rejects_other_scheme() {
        let err = normalize_relay_http_url("ftp://relay.example").unwrap_err();
        assert!(err.to_string().contains("relay_url must start with"));
    }

    #[tokio::test]
    async fn fetch_relay_info_reads_nip11_document() {
        let http_url = spawn_single_response_server(
            "200 OK",
            r#"{"name":"Relay Example","supported_nips":[1,11]}"#,
            "application/nostr+json",
        )
        .await;
        let args = RelayInfoArgs {
            relay_url: http_url.clone(),
            timeout_secs: Some(1),
        };

        let result = fetch_relay_info(args).await.unwrap();

        assert_eq!(result.http_url, http_url);
        assert_eq!(result.status, 200);
        assert_eq!(result.document.name.as_deref(), Some("Relay Example"));
        assert_eq!(result.document.supported_nips, Some(vec![1, 11]));
    }

    #[tokio::test]
    async fn fetch_relay_info_rejects_non_success_status() {
        let http_url =
            spawn_single_response_server("404 Not Found", "missing", "text/plain").await;
        let args = RelayInfoArgs {
            relay_url: http_url,
            timeout_secs: Some(1),
        };

        let err = fetch_relay_info(args).await.unwrap_err();

        assert!(err.to_string().contains("relay info status 404: missing"));
    }

    #[tokio::test]
    async fn fetch_relay_info_rejects_invalid_json() {
        let http_url =
            spawn_single_response_server("200 OK", "{", "application/nostr+json").await;
        let args = RelayInfoArgs {
            relay_url: http_url,
            timeout_secs: Some(1),
        };

        let err = fetch_relay_info(args).await.unwrap_err();

        assert!(err.to_string().contains("invalid nip11 json"));
    }

    #[tokio::test]
    async fn fetch_relay_info_surfaces_request_errors() {
        let args = RelayInfoArgs {
            relay_url: "http://127.0.0.1:1".to_string(),
            timeout_secs: Some(1),
        };

        let err = fetch_relay_info(args).await.unwrap_err();

        assert!(err.to_string().contains("relay info request"));
    }

    #[tokio::test]
    async fn fetch_relay_info_rejects_invalid_scheme() {
        let args = RelayInfoArgs {
            relay_url: "ftp://relay.example".to_string(),
            timeout_secs: Some(1),
        };

        let err = fetch_relay_info(args).await.unwrap_err();

        assert!(err.to_string().contains("relay_url must start with"));
    }

    #[tokio::test]
    async fn fetch_relay_info_surfaces_body_errors() {
        let http_url = spawn_truncated_response_server(
            "200 OK",
            "{",
            "application/nostr+json",
            32,
        )
        .await;
        let args = RelayInfoArgs {
            relay_url: http_url,
            timeout_secs: Some(1),
        };

        let err = fetch_relay_info(args).await.unwrap_err();

        assert!(err.to_string().contains("relay info body"));
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
