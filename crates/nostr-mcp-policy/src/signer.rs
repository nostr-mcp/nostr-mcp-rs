use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::baseline::{PolicyBaseline, baseline_policy};
use crate::capability::{
    AuthoringAction, CapabilityScope, EventKindScope, RelayTargetScope, SignerMethod,
};
use crate::identity::{IdentityClass, SignerBackend};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignerPolicy {
    pub baseline: PolicyBaseline,
    pub identity_class: IdentityClass,
    pub signer_backend: SignerBackend,
    #[serde(default)]
    pub capability_scopes: Vec<CapabilityScope>,
    #[serde(default)]
    pub signer_methods: Vec<SignerMethod>,
    #[serde(default)]
    pub authoring_actions: Vec<AuthoringAction>,
    #[serde(default)]
    pub event_kind_scope: EventKindScope,
    #[serde(default)]
    pub relay_target_scope: RelayTargetScope,
}

impl Default for SignerPolicy {
    fn default() -> Self {
        default_signer_policy()
    }
}

pub fn default_signer_policy() -> SignerPolicy {
    SignerPolicy {
        baseline: baseline_policy(),
        identity_class: IdentityClass::RemoteSignerSession,
        signer_backend: SignerBackend::Nip46Remote,
        capability_scopes: Vec::new(),
        signer_methods: Vec::new(),
        authoring_actions: Vec::new(),
        event_kind_scope: EventKindScope::default(),
        relay_target_scope: RelayTargetScope::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SignerPolicy, default_signer_policy};
    use crate::baseline::{DefaultPolicyAction, ProductionSignerMode};
    use crate::capability::{
        AuthoringAction, CapabilityScope, EventKindScope, RelayTargetScope, SignerMethod,
    };
    use crate::identity::{IdentityClass, SignerBackend};

    #[test]
    fn default_signer_policy_is_default_deny_and_nip46_only() {
        let policy = default_signer_policy();

        assert_eq!(policy.baseline.default_action, DefaultPolicyAction::Deny);
        assert_eq!(
            policy.baseline.production_signer_mode,
            ProductionSignerMode::Nip46Only
        );
        assert_eq!(policy.identity_class, IdentityClass::RemoteSignerSession);
        assert_eq!(policy.signer_backend, SignerBackend::Nip46Remote);
        assert!(policy.capability_scopes.is_empty());
        assert!(policy.signer_methods.is_empty());
        assert!(policy.authoring_actions.is_empty());
        assert_eq!(
            policy.event_kind_scope,
            EventKindScope::Explicit(Vec::new())
        );
        assert_eq!(
            policy.relay_target_scope,
            RelayTargetScope::Allowlist(Vec::new())
        );
        assert_eq!(policy, SignerPolicy::default());
    }

    #[test]
    fn signer_policy_round_trips_through_json() {
        let policy = SignerPolicy {
            capability_scopes: vec![
                CapabilityScope::BuildUnsignedEvents,
                CapabilityScope::PreviewEvents,
                CapabilityScope::SignEvents,
                CapabilityScope::PublishEvents,
            ],
            signer_methods: vec![
                SignerMethod::GetPublicKey,
                SignerMethod::SignEvent,
                SignerMethod::SwitchRelays,
            ],
            authoring_actions: vec![
                AuthoringAction::BuildUnsigned,
                AuthoringAction::Preview,
                AuthoringAction::Sign,
            ],
            event_kind_scope: EventKindScope::explicit(vec![1, 30023, 1]),
            relay_target_scope: RelayTargetScope::allowlist(vec![
                "wss://relay.radroots.org".to_string(),
                "wss://relay.radroots.org".to_string(),
            ]),
            ..default_signer_policy()
        };
        let json = serde_json::to_string(&policy).expect("serialize signer policy");
        let round_trip: SignerPolicy =
            serde_json::from_str(&json).expect("deserialize signer policy");

        assert_eq!(round_trip, policy);
    }
}
