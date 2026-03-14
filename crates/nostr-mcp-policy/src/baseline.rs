use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const POLICY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicyAction {
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSignerMode {
    Nip46Only,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyBaseline {
    pub policy_version: String,
    pub default_action: DefaultPolicyAction,
    pub production_signer_mode: ProductionSignerMode,
    pub local_signer_allowed_in_published_crates: bool,
}

impl Default for PolicyBaseline {
    fn default() -> Self {
        baseline_policy()
    }
}

pub fn baseline_policy() -> PolicyBaseline {
    PolicyBaseline {
        policy_version: POLICY_VERSION.to_string(),
        default_action: DefaultPolicyAction::Deny,
        production_signer_mode: ProductionSignerMode::Nip46Only,
        local_signer_allowed_in_published_crates: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultPolicyAction, POLICY_VERSION, PolicyBaseline, ProductionSignerMode, baseline_policy,
    };

    #[test]
    fn baseline_policy_defaults_to_deny_and_nip46_only() {
        let baseline = baseline_policy();

        assert_eq!(baseline.policy_version, POLICY_VERSION);
        assert_eq!(baseline.default_action, DefaultPolicyAction::Deny);
        assert_eq!(
            baseline.production_signer_mode,
            ProductionSignerMode::Nip46Only
        );
        assert!(!baseline.local_signer_allowed_in_published_crates);
        assert_eq!(baseline, PolicyBaseline::default());
    }

    #[test]
    fn baseline_policy_round_trips_through_json() {
        let baseline = baseline_policy();
        let json = serde_json::to_string(&baseline).expect("serialize policy baseline");
        let round_trip: PolicyBaseline =
            serde_json::from_str(&json).expect("deserialize policy baseline");

        assert_eq!(round_trip, baseline);
    }
}
