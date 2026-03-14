#![forbid(unsafe_code)]

pub mod audit;
pub mod baseline;
pub mod capability;
pub mod decision;
pub mod identity;
pub mod signer;

pub use audit::{PolicyAuditEvent, PolicyAuditEventKind};
pub use baseline::{
    DefaultPolicyAction, POLICY_VERSION, PolicyBaseline, ProductionSignerMode, baseline_policy,
};
pub use capability::{
    AuthoringAction, CapabilityScope, EventKindScope, RelayTargetScope, SignerMethod,
};
pub use decision::{PolicyDecision, PolicyDecisionEffect, PolicyDecisionReason, PolicyRequest};
pub use identity::{IdentityClass, SignerBackend};
pub use signer::{SignerPolicy, default_signer_policy};
