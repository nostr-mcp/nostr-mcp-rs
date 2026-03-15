use crate::error::CoreError;
use nostr_mcp_types::relays::RelayStatusRow;
use nostr_mcp_types::relays::{RelaysConnectArgs, RelaysDisconnectArgs, RelaysSetArgs};
use nostr_sdk::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
                    .map_err(|e| CoreError::operation(format!("add relay: {e}")))?;
            }
            RelayMode::Write => {
                client
                    .add_write_relay(&url)
                    .await
                    .map_err(|e| CoreError::operation(format!("add relay: {e}")))?;
            }
            RelayMode::Both => {
                client
                    .add_relay(&url)
                    .await
                    .map_err(|e| CoreError::operation(format!("add relay: {e}")))?;
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
                .map_err(|e| CoreError::operation(format!("connect relay: {e}")))?;
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
                    .map_err(|e| CoreError::operation(format!("remove relay: {e}")))?;
            } else {
                client
                    .remove_relay(&url)
                    .await
                    .map_err(|e| CoreError::operation(format!("remove relay: {e}")))?;
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
    use super::{
        connect_relays, disconnect_relays, get_relay_urls, list_relays, parse_read_write,
        set_relays, status_summary,
    };
    use nostr_mcp_types::relays::{RelaysConnectArgs, RelaysDisconnectArgs, RelaysSetArgs};
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::*;
    use std::collections::{HashMap, HashSet};

    async fn relay_flags(client: &Client, url: &str) -> (bool, bool, bool) {
        let relays = client.relays().await;
        let relay = relays.get(&RelayUrl::parse(url).unwrap()).unwrap();
        let flags = relay.flags();
        (
            flags.has(RelayServiceFlags::READ, FlagCheck::Any),
            flags.has(RelayServiceFlags::WRITE, FlagCheck::Any),
            flags.has(RelayServiceFlags::DISCOVERY, FlagCheck::Any),
        )
    }

    #[test]
    fn parse_read_write_defaults_to_both() {
        assert_eq!(parse_read_write(None).unwrap(), super::RelayMode::Both);
    }

    #[test]
    fn parse_read_write_accepts_read_and_write() {
        assert_eq!(parse_read_write(Some("read")).unwrap(), super::RelayMode::Read);
        assert_eq!(parse_read_write(Some("write")).unwrap(), super::RelayMode::Write);
    }

    #[test]
    fn parse_read_write_rejects_invalid() {
        let err = parse_read_write(Some("nope")).unwrap_err();
        assert!(
            err.to_string()
                .contains("read_write must be one of: read, write, both")
        );
    }

    #[tokio::test]
    async fn set_relays_adds_relays_for_all_modes_without_autoconnect() {
        let client = Client::new(Keys::generate());

        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://read.example.com".to_string()],
                read_write: Some("read".to_string()),
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();
        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://write.example.com".to_string()],
                read_write: Some("write".to_string()),
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();
        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://both.example.com".to_string()],
                read_write: None,
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            relay_flags(&client, "wss://read.example.com").await,
            (true, false, false)
        );
        assert_eq!(
            relay_flags(&client, "wss://write.example.com").await,
            (false, true, false)
        );
        assert_eq!(
            relay_flags(&client, "wss://both.example.com").await,
            (true, true, false)
        );
    }

    #[tokio::test]
    async fn set_relays_autoconnects_when_enabled() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let client = Client::new(Keys::generate());

        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec![url.to_string()],
                read_write: None,
                autoconnect: Some(true),
            },
        )
        .await
        .unwrap();

        let urls = get_relay_urls(&client).await;
        assert_eq!(urls, vec![url.to_string()]);
    }

    #[tokio::test]
    async fn set_relays_rejects_invalid_urls_for_each_mode() {
        let client = Client::new(Keys::generate());

        for mode in ["read", "write", "both"] {
            let err = set_relays(
                &client,
                RelaysSetArgs {
                    urls: vec!["not-a-url".to_string()],
                    read_write: Some(mode.to_string()),
                    autoconnect: Some(false),
                },
            )
            .await
            .unwrap_err();

            assert!(err.to_string().contains("add relay"));
        }
    }

    #[tokio::test]
    async fn set_relays_rejects_invalid_mode_before_touching_urls() {
        let client = Client::new(Keys::generate());

        let err = set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://read.example.com".to_string()],
                read_write: Some("nope".to_string()),
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("read_write must be one of"));
    }

    #[tokio::test]
    async fn connect_relays_connects_specific_urls() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let client = Client::new(Keys::generate());
        client.add_relay(&url).await.unwrap();

        connect_relays(
            &client,
            RelaysConnectArgs {
                urls: Some(vec![url.to_string()]),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connect_relays_connects_all_when_urls_missing() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let client = Client::new(Keys::generate());
        client.add_relay(&url).await.unwrap();

        connect_relays(&client, RelaysConnectArgs { urls: None })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connect_relays_rejects_invalid_url() {
        let client = Client::new(Keys::generate());

        let err = connect_relays(
            &client,
            RelaysConnectArgs {
                urls: Some(vec!["not-a-url".to_string()]),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("connect relay"));
    }

    #[tokio::test]
    async fn disconnect_relays_removes_specific_and_all_relays() {
        let client = Client::new(Keys::generate());
        client.add_relay("wss://one.example.com").await.unwrap();
        client.add_relay("wss://two.example.com").await.unwrap();

        disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: Some(vec!["wss://one.example.com".to_string()]),
                force_remove: Some(false),
            },
        )
        .await
        .unwrap();

        let urls = get_relay_urls(&client).await;
        assert_eq!(urls, vec!["wss://two.example.com".to_string()]);

        disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: None,
                force_remove: Some(false),
            },
        )
        .await
        .unwrap();

        assert!(get_relay_urls(&client).await.is_empty());
    }

    #[tokio::test]
    async fn disconnect_relays_force_removes_specific_and_all_relays() {
        let client = Client::new(Keys::generate());
        client.add_relay("wss://one.example.com").await.unwrap();
        client.add_relay("wss://two.example.com").await.unwrap();

        disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: Some(vec!["wss://one.example.com".to_string()]),
                force_remove: Some(true),
            },
        )
        .await
        .unwrap();

        let urls = get_relay_urls(&client).await;
        assert_eq!(urls, vec!["wss://two.example.com".to_string()]);

        disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: None,
                force_remove: Some(true),
            },
        )
        .await
        .unwrap();

        assert!(get_relay_urls(&client).await.is_empty());
    }

    #[tokio::test]
    async fn disconnect_relays_rejects_invalid_url() {
        let client = Client::new(Keys::generate());

        let err = disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: Some(vec!["not-a-url".to_string()]),
                force_remove: Some(false),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("remove relay"));
    }

    #[tokio::test]
    async fn disconnect_relays_force_rejects_invalid_url() {
        let client = Client::new(Keys::generate());

        let err = disconnect_relays(
            &client,
            RelaysDisconnectArgs {
                urls: Some(vec!["not-a-url".to_string()]),
                force_remove: Some(true),
            },
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("remove relay"));
    }

    #[tokio::test]
    async fn list_relays_get_urls_and_status_summary_report_current_relays() {
        let client = Client::new(Keys::generate());
        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec![
                    "wss://read.example.com".to_string(),
                    "wss://both.example.com".to_string(),
                ],
                read_write: Some("read".to_string()),
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();
        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://write.example.com".to_string()],
                read_write: Some("write".to_string()),
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();
        set_relays(
            &client,
            RelaysSetArgs {
                urls: vec!["wss://both.example.com".to_string()],
                read_write: None,
                autoconnect: Some(false),
            },
        )
        .await
        .unwrap();

        let rows = list_relays(&client).await.unwrap();
        let urls = get_relay_urls(&client).await;
        let summary = status_summary(&client).await.unwrap();
        let row_map: HashMap<_, _> = rows.into_iter().map(|row| (row.url.clone(), row)).collect();

        let url_set: HashSet<_> = urls.into_iter().collect();
        assert_eq!(
            url_set,
            HashSet::from([
                "wss://read.example.com".to_string(),
                "wss://write.example.com".to_string(),
                "wss://both.example.com".to_string(),
            ])
        );
        assert_eq!(summary.get("relay_count"), Some(&"3".to_string()));
        assert_eq!(row_map.len(), 3);

        let read_row = row_map.get("wss://read.example.com").unwrap();
        assert!(read_row.read);
        assert!(!read_row.write);
        assert!(!read_row.status.is_empty());

        let write_row = row_map.get("wss://write.example.com").unwrap();
        assert!(!write_row.read);
        assert!(write_row.write);
        assert!(!write_row.status.is_empty());

        let both_row = row_map.get("wss://both.example.com").unwrap();
        assert!(both_row.read);
        assert!(both_row.write);
        assert!(!both_row.status.is_empty());
    }
}
