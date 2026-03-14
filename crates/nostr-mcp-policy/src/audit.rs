use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::decision::{PolicyDecision, PolicyRequest};
use crate::identity::{IdentityClass, SignerBackend};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAuditEventKind {
    SignerRequestCreated,
    SignerRequestApproved,
    SignerRequestDenied,
    SignerRequestTimedOut,
    PublishRequestApproved,
    PublishRequestDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyAuditEvent {
    pub kind: PolicyAuditEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub identity_class: IdentityClass,
    pub signer_backend: SignerBackend,
    pub request: PolicyRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<PolicyDecision>,
}

impl PolicyAuditEvent {
    pub fn signer_request_created(
        request_id: Option<String>,
        identity_class: IdentityClass,
        signer_backend: SignerBackend,
        request: PolicyRequest,
    ) -> Self {
        Self {
            kind: PolicyAuditEventKind::SignerRequestCreated,
            request_id,
            identity_class,
            signer_backend,
            request,
            decision: None,
        }
    }

    pub fn from_decision(
        kind: PolicyAuditEventKind,
        request_id: Option<String>,
        identity_class: IdentityClass,
        signer_backend: SignerBackend,
        decision: PolicyDecision,
    ) -> Self {
        Self {
            kind,
            request_id,
            identity_class,
            signer_backend,
            request: decision.request.clone(),
            decision: Some(decision),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyAuditEvent, PolicyAuditEventKind};
    use crate::capability::{AuthoringAction, CapabilityScope, SignerMethod};
    use crate::decision::{PolicyDecision, PolicyDecisionReason, PolicyRequest};
    use crate::identity::{IdentityClass, SignerBackend};

    #[test]
    fn signer_request_created_omits_decision_payload() {
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::SignEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Sign),
            event_kind: Some(1),
            relay_targets: Vec::new(),
        };
        let event = PolicyAuditEvent::signer_request_created(
            Some("req-1".to_string()),
            IdentityClass::RemoteSignerSession,
            SignerBackend::Nip46Remote,
            request,
        );
        let value = serde_json::to_value(&event).expect("serialize audit event");

        assert_eq!(event.kind, PolicyAuditEventKind::SignerRequestCreated);
        assert!(event.decision.is_none());
        assert!(value.get("decision").is_none());
    }

    #[test]
    fn decision_audit_events_round_trip_with_structured_decision() {
        let request = PolicyRequest {
            capability_scope: Some(CapabilityScope::PublishEvents),
            signer_method: Some(SignerMethod::SignEvent),
            authoring_action: Some(AuthoringAction::Publish),
            event_kind: Some(30023),
            relay_targets: vec!["wss://relay.radroots.org".to_string()],
        };
        let decision = PolicyDecision::deny(PolicyDecisionReason::RelayTargetOutOfScope, request);
        let event = PolicyAuditEvent::from_decision(
            PolicyAuditEventKind::PublishRequestDenied,
            Some("req-2".to_string()),
            IdentityClass::RemoteSignerSession,
            SignerBackend::Nip46Remote,
            decision,
        );
        let json = serde_json::to_string(&event).expect("serialize audit event");
        let round_trip: PolicyAuditEvent =
            serde_json::from_str(&json).expect("deserialize audit event");

        assert_eq!(round_trip, event);
        assert_eq!(round_trip.kind, PolicyAuditEventKind::PublishRequestDenied);
        assert_eq!(
            round_trip.decision.expect("decision payload").reason,
            PolicyDecisionReason::RelayTargetOutOfScope
        );
    }
}
