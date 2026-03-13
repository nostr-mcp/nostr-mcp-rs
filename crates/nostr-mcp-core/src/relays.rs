use crate::error::CoreError;
use nostr_sdk::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysSetArgs {
    pub urls: Vec<String>,
    pub read_write: Option<String>,
    pub autoconnect: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysConnectArgs {
    pub urls: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RelaysDisconnectArgs {
    pub urls: Option<Vec<String>>,
    pub force_remove: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RelayStatusRow {
    pub url: String,
    pub status: String,
    pub read: bool,
    pub write: bool,
    pub discovery: bool,
}

#[derive(Debug, Clone, Copy)]
enum RelayMode {
    Read,
    Write,
    Both,
}

fn parse_read_write(value: Option<&str>) -> Result<RelayMode, CoreError> {
    match value.unwrap_or("both").to_ascii_lowercase().as_str() {
        "read" => Ok(RelayMode::Read),
        "write" => Ok(RelayMode::Write),
        "both" => Ok(RelayMode::Both),
        _ => Err(CoreError::invalid_input(
            "read_write must be one of: read, write, both",
        )),
    }
}

pub async fn set_relays(client: &Client, args: RelaysSetArgs) -> Result<(), CoreError> {
    let mode = parse_read_write(args.read_write.as_deref())?;
    for url in args.urls {
        match mode {
            RelayMode::Read => {
                client
                    .add_read_relay(&url)
                    .await
                    .map_err(|e| CoreError::Nostr(format!("add relay: {e}")))?;
            }
            RelayMode::Write => {
                client
                    .add_write_relay(&url)
                    .await
                    .map_err(|e| CoreError::Nostr(format!("add relay: {e}")))?;
            }
            RelayMode::Both => {
                client
                    .add_relay(&url)
                    .await
                    .map_err(|e| CoreError::Nostr(format!("add relay: {e}")))?;
            }
        }
    }
    if args.autoconnect.unwrap_or(true) {
        client.connect().await;
    }
    Ok(())
}

pub async fn connect_relays(client: &Client, args: RelaysConnectArgs) -> Result<(), CoreError> {
    if let Some(urls) = args.urls {
        for url in urls {
            client
                .connect_relay(&url)
                .await
                .map_err(|e| CoreError::Nostr(format!("connect relay: {e}")))?;
        }
    } else {
        client.connect().await;
    }
    Ok(())
}

pub async fn disconnect_relays(
    client: &Client,
    args: RelaysDisconnectArgs,
) -> Result<(), CoreError> {
    let force = args.force_remove.unwrap_or(false);
    if let Some(urls) = args.urls {
        for url in urls {
            if force {
                client
                    .force_remove_relay(&url)
                    .await
                    .map_err(|e| CoreError::Nostr(format!("remove relay: {e}")))?;
            } else {
                client
                    .remove_relay(&url)
                    .await
                    .map_err(|e| CoreError::Nostr(format!("remove relay: {e}")))?;
            }
        }
    } else if force {
        client.force_remove_all_relays().await;
    } else {
        client.remove_all_relays().await;
    }
    Ok(())
}

pub async fn list_relays(client: &Client) -> Result<Vec<RelayStatusRow>, CoreError> {
    let map = client.relays().await;
    let mut out = Vec::with_capacity(map.len());
    for (url, relay) in map {
        let flags = relay.flags();
        out.push(RelayStatusRow {
            url: url.to_string(),
            status: relay.status().to_string(),
            read: flags.has(RelayServiceFlags::READ, FlagCheck::Any),
            write: flags.has(RelayServiceFlags::WRITE, FlagCheck::Any),
            discovery: flags.has(RelayServiceFlags::DISCOVERY, FlagCheck::Any),
        });
    }
    Ok(out)
}

pub async fn get_relay_urls(client: &Client) -> Vec<String> {
    let map = client.relays().await;
    map.keys().map(|url| url.to_string()).collect()
}

pub async fn status_summary(client: &Client) -> Result<HashMap<String, String>, CoreError> {
    let mut summary = HashMap::new();
    let connected = client.relays().await;
    summary.insert("relay_count".into(), connected.len().to_string());
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::parse_read_write;

    #[test]
    fn parse_read_write_defaults_to_both() {
        let mode = parse_read_write(None).unwrap();
        assert!(matches!(mode, super::RelayMode::Both));
    }

    #[test]
    fn parse_read_write_rejects_invalid() {
        let err = parse_read_write(Some("nope")).unwrap_err();
        assert!(err
            .to_string()
            .contains("read_write must be one of: read, write, both"));
    }
}
