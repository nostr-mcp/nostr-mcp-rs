use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip05ResolveResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub pubkey_npub: String,
    pub relays: Vec<String>,
    pub nip46_relays: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Nip05VerifyResult {
    pub identifier: String,
    pub url: String,
    pub pubkey_hex: String,
    pub valid: bool,
}

#[cfg(test)]
mod tests {
    use super::{Nip05ResolveArgs, Nip05VerifyArgs};

    #[test]
    fn timeout_helpers_default_to_ten_seconds() {
        let resolve = Nip05ResolveArgs {
            identifier: "alice@example.com".to_string(),
            timeout_secs: None,
        };
        let verify = Nip05VerifyArgs {
            identifier: "alice@example.com".to_string(),
            pubkey: "pubkey".to_string(),
            timeout_secs: None,
        };

        assert_eq!(resolve.timeout(), 10);
        assert_eq!(verify.timeout(), 10);
    }

    #[test]
    fn timeout_helpers_use_explicit_values() {
        let resolve = Nip05ResolveArgs {
            identifier: "alice@example.com".to_string(),
            timeout_secs: Some(16),
        };
        let verify = Nip05VerifyArgs {
            identifier: "alice@example.com".to_string(),
            pubkey: "pubkey".to_string(),
            timeout_secs: Some(17),
        };

        assert_eq!(resolve.timeout(), 16);
        assert_eq!(verify.timeout(), 17);
    }
}
