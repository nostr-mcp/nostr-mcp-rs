use nostr::nips::nip11::RelayInformationDocument;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RelayInfoResult {
    pub relay_url: String,
    pub http_url: String,
    pub status: u16,
    #[schemars(with = "serde_json::Value")]
    pub document: RelayInformationDocument,
}

#[cfg(test)]
mod tests {
    use super::RelayInfoArgs;

    #[test]
    fn timeout_defaults_to_ten_seconds() {
        let args = RelayInfoArgs {
            relay_url: "wss://relay.example.com".to_string(),
            timeout_secs: None,
        };

        assert_eq!(args.timeout(), 10);
    }

    #[test]
    fn timeout_uses_explicit_value() {
        let args = RelayInfoArgs {
            relay_url: "wss://relay.example.com".to_string(),
            timeout_secs: Some(18),
        };

        assert_eq!(args.timeout(), 18);
    }
}
