use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClass {
    WatchOnly,
    SignerBacked,
    RemoteSignerSession,
    AgentSessionKey,
}

impl IdentityClass {
    pub const fn can_sign_user_events(self) -> bool {
        matches!(self, Self::SignerBacked | Self::RemoteSignerSession)
    }

    pub const fn requires_external_user_signer(self) -> bool {
        matches!(self, Self::RemoteSignerSession)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SignerBackend {
    Nip46Remote,
    LocalTestOnly,
}

impl SignerBackend {
    pub const fn keeps_long_lived_user_secret_outside_mcp(self) -> bool {
        matches!(self, Self::Nip46Remote)
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityClass, SignerBackend};

    #[test]
    fn identity_class_makes_signing_boundary_explicit() {
        assert!(!IdentityClass::WatchOnly.can_sign_user_events());
        assert!(IdentityClass::SignerBacked.can_sign_user_events());
        assert!(IdentityClass::RemoteSignerSession.can_sign_user_events());
        assert!(!IdentityClass::AgentSessionKey.can_sign_user_events());
        assert!(!IdentityClass::WatchOnly.requires_external_user_signer());
        assert!(IdentityClass::RemoteSignerSession.requires_external_user_signer());
    }

    #[test]
    fn signer_backend_marks_secret_exfiltration_boundary() {
        assert!(SignerBackend::Nip46Remote.keeps_long_lived_user_secret_outside_mcp());
        assert!(!SignerBackend::LocalTestOnly.keeps_long_lived_user_secret_outside_mcp());
    }
}
