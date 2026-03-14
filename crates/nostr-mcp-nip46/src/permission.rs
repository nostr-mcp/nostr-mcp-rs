use core::fmt;
use core::str::FromStr;

use nostr::Kind;
use serde::{Deserialize, Serialize};

use crate::error::Nip46Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nip46Method {
    Connect,
    GetPublicKey,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
    Ping,
    SwitchRelays,
}

impl fmt::Display for Nip46Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Connect => "connect",
            Self::GetPublicKey => "get_public_key",
            Self::SignEvent => "sign_event",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Ping => "ping",
            Self::SwitchRelays => "switch_relays",
        };
        f.write_str(value)
    }
}

impl FromStr for Nip46Method {
    type Err = Nip46Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "connect" => Ok(Self::Connect),
            "get_public_key" => Ok(Self::GetPublicKey),
            "sign_event" => Ok(Self::SignEvent),
            "nip04_encrypt" => Ok(Self::Nip04Encrypt),
            "nip04_decrypt" => Ok(Self::Nip04Decrypt),
            "nip44_encrypt" => Ok(Self::Nip44Encrypt),
            "nip44_decrypt" => Ok(Self::Nip44Decrypt),
            "ping" => Ok(Self::Ping),
            "switch_relays" => Ok(Self::SwitchRelays),
            other => Err(Nip46Error::invalid_permission(format!(
                "unsupported method `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nip46Permission {
    pub method: Nip46Method,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_event_kind: Option<Kind>,
}

impl Nip46Permission {
    pub const fn new(method: Nip46Method) -> Self {
        Self {
            method,
            sign_event_kind: None,
        }
    }

    pub const fn sign_event(kind: Option<Kind>) -> Self {
        Self {
            method: Nip46Method::SignEvent,
            sign_event_kind: kind,
        }
    }
}

impl fmt::Display for Nip46Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sign_event_kind {
            Some(kind) if self.method == Nip46Method::SignEvent => {
                write!(f, "{}:{}", self.method, kind.as_u16())
            }
            _ => self.method.fmt(f),
        }
    }
}

impl FromStr for Nip46Permission {
    type Err = Nip46Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.splitn(2, ':');
        let method = parts
            .next()
            .ok_or_else(|| Nip46Error::invalid_permission("missing permission method"))?;
        let method = Nip46Method::from_str(method)?;

        match parts.next() {
            Some(scope) if method != Nip46Method::SignEvent => Err(Nip46Error::invalid_permission(
                format!("method `{method}` does not accept parameter `{scope}`"),
            )),
            Some(scope) => {
                let value: u16 = scope.parse().map_err(|_| {
                    Nip46Error::invalid_permission(format!(
                        "invalid sign_event kind scope `{scope}`"
                    ))
                })?;
                Ok(Self::sign_event(Some(Kind::from_u16(value))))
            }
            None if method == Nip46Method::SignEvent => Ok(Self::sign_event(None)),
            None => Ok(Self::new(method)),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip46PermissionSet {
    pub permissions: Vec<Nip46Permission>,
}

impl Nip46PermissionSet {
    pub fn new(permissions: Vec<Nip46Permission>) -> Self {
        let mut normalized = Vec::new();
        for permission in permissions {
            if !normalized.contains(&permission) {
                normalized.push(permission);
            }
        }
        Self {
            permissions: normalized,
        }
    }

    pub fn parse_csv(value: &str) -> Result<Self, Nip46Error> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }

        let mut permissions = Vec::new();
        for part in value.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            permissions.push(Nip46Permission::from_str(trimmed)?);
        }
        Ok(Self::new(permissions))
    }

    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Nip46Permission> {
        self.permissions.iter()
    }
}

impl fmt::Display for Nip46PermissionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined = self
            .permissions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        f.write_str(&joined)
    }
}

impl From<Vec<Nip46Permission>> for Nip46PermissionSet {
    fn from(permissions: Vec<Nip46Permission>) -> Self {
        Self::new(permissions)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use nostr::Kind;

    use super::{Nip46Method, Nip46Permission, Nip46PermissionSet};

    #[test]
    fn permission_parses_sign_event_kind_scope() {
        let permission = Nip46Permission::from_str("sign_event:1059").unwrap();
        assert_eq!(permission.method, Nip46Method::SignEvent);
        assert_eq!(permission.sign_event_kind, Some(Kind::from_u16(1059)));
        assert_eq!(permission.to_string(), "sign_event:1059");
    }

    #[test]
    fn permission_rejects_non_sign_event_params() {
        let err = Nip46Permission::from_str("ping:1").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid permission: method `ping` does not accept parameter `1`"
        );
    }

    #[test]
    fn permission_set_round_trips_and_dedupes() {
        let set = Nip46PermissionSet::parse_csv(
            "nip44_encrypt,sign_event:13,sign_event:13,switch_relays",
        )
        .unwrap();

        let permissions = set.iter().cloned().collect::<Vec<_>>();
        assert_eq!(
            permissions,
            vec![
                Nip46Permission::new(Nip46Method::Nip44Encrypt),
                Nip46Permission::sign_event(Some(Kind::from_u16(13))),
                Nip46Permission::new(Nip46Method::SwitchRelays),
            ]
        );
        assert_eq!(set.to_string(), "nip44_encrypt,sign_event:13,switch_relays");
    }

    #[test]
    fn empty_permission_csv_is_empty_set() {
        let set = Nip46PermissionSet::parse_csv("").unwrap();
        assert!(set.is_empty());
        assert_eq!(set.to_string(), "");
    }
}
