use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    ReadPublicData,
    ReadLocalState,
    ManageIdentity,
    ManageRelays,
    ManageMetadata,
    ManageFollows,
    ModerateGroups,
    BuildUnsignedEvents,
    PreviewEvents,
    SignEvents,
    PublishEvents,
    EncryptNip44,
    DecryptNip44,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SignerMethod {
    Connect,
    GetPublicKey,
    SignEvent,
    Nip44Encrypt,
    Nip44Decrypt,
    SwitchRelays,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoringAction {
    BuildUnsigned,
    Preview,
    Sign,
    Publish,
}

impl AuthoringAction {
    pub const fn requires_signer(self) -> bool {
        matches!(self, Self::Sign | Self::Publish)
    }

    pub const fn requires_network_write(self) -> bool {
        matches!(self, Self::Publish)
    }

    pub const fn capability_scope(self) -> CapabilityScope {
        match self {
            Self::BuildUnsigned => CapabilityScope::BuildUnsignedEvents,
            Self::Preview => CapabilityScope::PreviewEvents,
            Self::Sign => CapabilityScope::SignEvents,
            Self::Publish => CapabilityScope::PublishEvents,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "mode", content = "kinds")]
pub enum EventKindScope {
    Any,
    Explicit(Vec<u16>),
}

impl EventKindScope {
    pub fn explicit(mut kinds: Vec<u16>) -> Self {
        kinds.sort_unstable();
        kinds.dedup();
        Self::Explicit(kinds)
    }

    pub fn kinds(&self) -> Option<&[u16]> {
        match self {
            Self::Any => None,
            Self::Explicit(kinds) => Some(kinds.as_slice()),
        }
    }
}

impl Default for EventKindScope {
    fn default() -> Self {
        Self::Explicit(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "mode", content = "relays")]
pub enum RelayTargetScope {
    Any,
    Allowlist(Vec<String>),
}

impl RelayTargetScope {
    pub fn allowlist(mut relays: Vec<String>) -> Self {
        relays.retain(|relay| !relay.trim().is_empty());
        relays.sort();
        relays.dedup();
        Self::Allowlist(relays)
    }

    pub fn relays(&self) -> Option<&[String]> {
        match self {
            Self::Any => None,
            Self::Allowlist(relays) => Some(relays.as_slice()),
        }
    }
}

impl Default for RelayTargetScope {
    fn default() -> Self {
        Self::Allowlist(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthoringAction, EventKindScope, RelayTargetScope};

    #[test]
    fn authoring_actions_preserve_build_preview_sign_publish_boundary() {
        assert!(!AuthoringAction::BuildUnsigned.requires_signer());
        assert!(!AuthoringAction::BuildUnsigned.requires_network_write());
        assert!(!AuthoringAction::Preview.requires_signer());
        assert!(!AuthoringAction::Preview.requires_network_write());
        assert!(AuthoringAction::Sign.requires_signer());
        assert!(!AuthoringAction::Sign.requires_network_write());
        assert!(AuthoringAction::Publish.requires_signer());
        assert!(AuthoringAction::Publish.requires_network_write());
        assert_eq!(
            AuthoringAction::BuildUnsigned.capability_scope(),
            super::CapabilityScope::BuildUnsignedEvents
        );
        assert_eq!(
            AuthoringAction::Preview.capability_scope(),
            super::CapabilityScope::PreviewEvents
        );
        assert_eq!(
            AuthoringAction::Sign.capability_scope(),
            super::CapabilityScope::SignEvents
        );
        assert_eq!(
            AuthoringAction::Publish.capability_scope(),
            super::CapabilityScope::PublishEvents
        );
    }

    #[test]
    fn event_kind_scope_explicit_normalizes_kind_list() {
        let scope = EventKindScope::explicit(vec![1, 30023, 1, 7]);

        assert_eq!(scope.kinds(), Some([1, 7, 30023].as_slice()));
    }

    #[test]
    fn event_kind_scope_any_exposes_unbounded_kinds() {
        assert_eq!(EventKindScope::Any.kinds(), None);
    }

    #[test]
    fn relay_target_scope_allowlist_normalizes_relays() {
        let scope = RelayTargetScope::allowlist(vec![
            "wss://relay.example.com".to_string(),
            String::new(),
            "wss://relay.example.com".to_string(),
            "wss://relay.radroots.org".to_string(),
        ]);

        assert_eq!(
            scope.relays(),
            Some(
                [
                    "wss://relay.example.com".to_string(),
                    "wss://relay.radroots.org".to_string(),
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn relay_target_scope_any_exposes_unbounded_relays() {
        assert_eq!(RelayTargetScope::Any.relays(), None);
    }
}
