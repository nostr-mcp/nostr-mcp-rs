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
    pub manual_approval_actions: Vec<AuthoringAction>,
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
        manual_approval_actions: Vec::new(),
        event_kind_scope: EventKindScope::default(),
        relay_target_scope: RelayTargetScope::default(),
    }
}

impl SignerPolicy {
    fn allows_capability_scope(&self, capability_scope: CapabilityScope) -> bool {
        self.capability_scopes.contains(&capability_scope)
    }

    fn allows_signer_method(&self, signer_method: SignerMethod) -> bool {
        self.signer_methods.contains(&signer_method)
    }

    fn allows_authoring_action(&self, authoring_action: AuthoringAction) -> bool {
        self.authoring_actions.contains(&authoring_action)
    }

    fn requires_manual_approval(&self, authoring_action: AuthoringAction) -> bool {
        self.manual_approval_actions.contains(&authoring_action)
    }

    fn event_kind_is_allowed(&self, event_kind: u16) -> bool {
        match &self.event_kind_scope {
            EventKindScope::Any => true,
            EventKindScope::Explicit(kinds) => kinds.contains(&event_kind),
        }
    }

    fn relay_targets_are_allowed(&self, relay_targets: &[String]) -> bool {
        match &self.relay_target_scope {
            RelayTargetScope::Any => true,
            RelayTargetScope::Allowlist(allowlist) => relay_targets
                .iter()
                .all(|relay_target| allowlist.contains(relay_target)),
        }
    }

    pub fn evaluate_request(
        &self,
        request: crate::decision::PolicyRequest,
    ) -> crate::decision::PolicyDecision {
        use crate::decision::{PolicyDecision, PolicyDecisionReason};

        if let Some(required_identity_class) = request.required_identity_class
            && self.identity_class != required_identity_class
        {
            return PolicyDecision::deny(PolicyDecisionReason::IdentityClassMismatch, request);
        }

        if let Some(required_signer_backend) = request.required_signer_backend
            && self.signer_backend != required_signer_backend
        {
            return PolicyDecision::deny(PolicyDecisionReason::SignerBackendMismatch, request);
        }

        if let Some(capability_scope) = request.capability_scope
            && !self.allows_capability_scope(capability_scope)
        {
            return PolicyDecision::deny(PolicyDecisionReason::MissingCapabilityScope, request);
        }

        if let Some(signer_method) = request.signer_method
            && !self.allows_signer_method(signer_method)
        {
            return PolicyDecision::deny(PolicyDecisionReason::MissingSignerMethod, request);
        }

        if let Some(authoring_action) = request.authoring_action {
            if !self.allows_authoring_action(authoring_action) {
                return PolicyDecision::deny(
                    PolicyDecisionReason::MissingAuthoringPermission,
                    request,
                );
            }

            if !self.allows_capability_scope(authoring_action.capability_scope()) {
                return PolicyDecision::deny(PolicyDecisionReason::MissingCapabilityScope, request);
            }

            if self.requires_manual_approval(authoring_action) {
                return PolicyDecision::escalate(
                    PolicyDecisionReason::ManualApprovalRequired,
                    request,
                );
            }
        }

        if let Some(event_kind) = request.event_kind
            && !self.event_kind_is_allowed(event_kind)
        {
            return PolicyDecision::deny(PolicyDecisionReason::EventKindOutOfScope, request);
        }

        if !request.relay_targets.is_empty()
            && !self.relay_targets_are_allowed(&request.relay_targets)
        {
            return PolicyDecision::deny(PolicyDecisionReason::RelayTargetOutOfScope, request);
        }

        crate::decision::PolicyDecision::allow(
            crate::decision::PolicyDecisionReason::ExplicitPolicyGrant,
            request,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{SignerPolicy, default_signer_policy};
    use crate::baseline::{DefaultPolicyAction, ProductionSignerMode};
    use crate::capability::{
        AuthoringAction, CapabilityScope, EventKindScope, RelayTargetScope, SignerMethod,
    };
    use crate::decision::{PolicyDecisionEffect, PolicyDecisionReason, PolicyRequest};
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
        assert!(policy.manual_approval_actions.is_empty());
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
            manual_approval_actions: vec![AuthoringAction::Publish],
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

    fn publish_policy() -> SignerPolicy {
        SignerPolicy {
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
                AuthoringAction::Publish,
            ],
            event_kind_scope: EventKindScope::explicit(vec![1, 7, 30023]),
            relay_target_scope: RelayTargetScope::allowlist(vec![
                "wss://relay.example.com".to_string(),
                "wss://relay.radroots.org".to_string(),
            ]),
            ..default_signer_policy()
        }
    }

    #[test]
    fn evaluate_request_allows_matching_policy_request() {
        let policy = publish_policy();
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(30023),
            required_identity_class: Some(IdentityClass::RemoteSignerSession),
            required_signer_backend: Some(SignerBackend::Nip46Remote),
            relay_targets: vec!["wss://relay.radroots.org".to_string()],
        };
        let decision = policy.evaluate_request(request);

        assert_eq!(decision.effect, PolicyDecisionEffect::Allow);
        assert_eq!(decision.reason, PolicyDecisionReason::ExplicitPolicyGrant);
    }

    #[test]
    fn evaluate_request_denies_missing_capability_scope() {
        let mut policy = publish_policy();
        policy
            .capability_scopes
            .retain(|scope| *scope != CapabilityScope::PublishEvents);
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(1),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: vec!["wss://relay.radroots.org".to_string()],
        };
        let decision = policy.evaluate_request(request);

        assert_eq!(decision.effect, PolicyDecisionEffect::Deny);
        assert_eq!(
            decision.reason,
            PolicyDecisionReason::MissingCapabilityScope
        );
    }

    #[test]
    fn evaluate_request_escalates_manual_approval_action() {
        let mut policy = publish_policy();
        policy.manual_approval_actions = vec![AuthoringAction::Publish];
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(1),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: vec!["wss://relay.radroots.org".to_string()],
        };
        let decision = policy.evaluate_request(request);

        assert_eq!(decision.effect, PolicyDecisionEffect::Escalate);
        assert_eq!(
            decision.reason,
            PolicyDecisionReason::ManualApprovalRequired
        );
    }

    #[test]
    fn evaluate_request_denies_event_kind_out_of_scope() {
        let policy = publish_policy();
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(42),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: vec!["wss://relay.radroots.org".to_string()],
        };
        let decision = policy.evaluate_request(request);

        assert_eq!(decision.effect, PolicyDecisionEffect::Deny);
        assert_eq!(decision.reason, PolicyDecisionReason::EventKindOutOfScope);
    }

    #[test]
    fn evaluate_request_denies_relay_target_out_of_scope() {
        let policy = publish_policy();
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(1),
            required_identity_class: None,
            required_signer_backend: None,
            relay_targets: vec!["wss://relay.unauthorized.example".to_string()],
        };
        let decision = policy.evaluate_request(request);

        assert_eq!(decision.effect, PolicyDecisionEffect::Deny);
        assert_eq!(decision.reason, PolicyDecisionReason::RelayTargetOutOfScope);
    }

    #[test]
    fn evaluate_request_denies_identity_or_backend_mismatch() {
        let policy = publish_policy();
        let identity_mismatch = policy.evaluate_request(PolicyRequest {
            capability_scope: Some(CapabilityScope::SignEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Sign),
            event_kind: Some(1),
            required_identity_class: Some(IdentityClass::SignerBacked),
            required_signer_backend: None,
            relay_targets: Vec::new(),
        });
        let backend_mismatch = policy.evaluate_request(PolicyRequest {
            capability_scope: Some(CapabilityScope::SignEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Sign),
            event_kind: Some(1),
            required_identity_class: None,
            required_signer_backend: Some(SignerBackend::LocalTestOnly),
            relay_targets: Vec::new(),
        });

        assert_eq!(identity_mismatch.effect, PolicyDecisionEffect::Deny);
        assert_eq!(
            identity_mismatch.reason,
            PolicyDecisionReason::IdentityClassMismatch
        );
        assert_eq!(backend_mismatch.effect, PolicyDecisionEffect::Deny);
        assert_eq!(
            backend_mismatch.reason,
            PolicyDecisionReason::SignerBackendMismatch
        );
    }
}
