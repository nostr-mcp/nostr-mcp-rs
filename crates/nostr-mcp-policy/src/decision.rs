use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::{AuthoringAction, CapabilityScope, SignerMethod};
use crate::identity::{IdentityClass, SignerBackend};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PolicyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_scope: Option<CapabilityScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_method: Option<SignerMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_action: Option<AuthoringAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_identity_class: Option<IdentityClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_signer_backend: Option<SignerBackend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_targets: Vec<String>,
}

impl PolicyRequest {
    pub fn with_relay_targets(mut self, mut relay_targets: Vec<String>) -> Self {
        relay_targets.retain(|relay| !relay.trim().is_empty());
        relay_targets.sort();
        relay_targets.dedup();
        self.relay_targets = relay_targets;
        self
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionEffect {
    Allow,
    Deny,
    Escalate,
}

impl PolicyDecisionEffect {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Escalate)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionReason {
    ExplicitPolicyGrant,
    DefaultDeny,
    MissingCapabilityScope,
    MissingSignerMethod,
    MissingAuthoringPermission,
    EventKindOutOfScope,
    RelayTargetOutOfScope,
    IdentityClassMismatch,
    SignerBackendMismatch,
    ManualApprovalRequired,
    RequestTimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyDecision {
    pub effect: PolicyDecisionEffect,
    pub reason: PolicyDecisionReason,
    pub request: PolicyRequest,
}

impl PolicyDecision {
    pub fn allow(reason: PolicyDecisionReason, request: PolicyRequest) -> Self {
        Self {
            effect: PolicyDecisionEffect::Allow,
            reason,
            request,
        }
    }

    pub fn deny(reason: PolicyDecisionReason, request: PolicyRequest) -> Self {
        Self {
            effect: PolicyDecisionEffect::Deny,
            reason,
            request,
        }
    }

    pub fn escalate(reason: PolicyDecisionReason, request: PolicyRequest) -> Self {
        Self {
            effect: PolicyDecisionEffect::Escalate,
            reason,
            request,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyDecision, PolicyDecisionEffect, PolicyDecisionReason, PolicyRequest};
    use crate::capability::{AuthoringAction, CapabilityScope, SignerMethod};

    #[test]
    fn policy_request_normalizes_relay_targets() {
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(1),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: Vec::new(),
        }
        .with_relay_targets(vec![
            "wss://relay.radroots.org".to_string(),
            String::new(),
            "wss://relay.example.com".to_string(),
            "wss://relay.radroots.org".to_string(),
        ]);

        assert_eq!(
            request.relay_targets,
            vec![
                "wss://relay.example.com".to_string(),
                "wss://relay.radroots.org".to_string(),
            ]
        );
    }

    #[test]
    fn policy_decision_constructors_preserve_effect_and_reason() {
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::SignEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Sign),
            event_kind: Some(30023),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: Vec::new(),
        };

        let allow =
            PolicyDecision::allow(PolicyDecisionReason::ExplicitPolicyGrant, request.clone());
        let deny = PolicyDecision::deny(PolicyDecisionReason::DefaultDeny, request.clone());
        let escalate = PolicyDecision::escalate(
            PolicyDecisionReason::ManualApprovalRequired,
            request.clone(),
        );

        assert_eq!(allow.effect, PolicyDecisionEffect::Allow);
        assert_eq!(allow.reason, PolicyDecisionReason::ExplicitPolicyGrant);
        assert_eq!(allow.request, request);
        assert!(allow.effect.is_terminal());

        assert_eq!(deny.effect, PolicyDecisionEffect::Deny);
        assert_eq!(deny.reason, PolicyDecisionReason::DefaultDeny);
        assert!(deny.effect.is_terminal());

        assert_eq!(escalate.effect, PolicyDecisionEffect::Escalate);
        assert_eq!(
            escalate.reason,
            PolicyDecisionReason::ManualApprovalRequired
        );
        assert!(!escalate.effect.is_terminal());
    }
}
