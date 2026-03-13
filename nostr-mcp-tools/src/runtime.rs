use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrMcpPaths {
    pub config_root: PathBuf,
    pub index_path: PathBuf,
    pub settings_path: PathBuf,
    pub keystore_secret_path: PathBuf,
}

impl NostrMcpPaths {
    pub fn from_root(config_root: PathBuf) -> Self {
        Self {
            index_path: config_root.join("keys.enc"),
            settings_path: config_root.join("settings.enc"),
            keystore_secret_path: config_root.join("keystore.secret"),
            config_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrMcpRuntime {
    pub server_name: String,
    pub keyring_service: String,
    pub paths: NostrMcpPaths,
}

impl NostrMcpRuntime {
    pub fn new<S, T>(server_name: S, keyring_service: T, config_root: PathBuf) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        Self {
            server_name: server_name.into(),
            keyring_service: keyring_service.into(),
            paths: NostrMcpPaths::from_root(config_root),
        }
    }

    pub fn with_config_root(&self, config_root: PathBuf) -> Self {
        Self {
            server_name: self.server_name.clone(),
            keyring_service: self.keyring_service.clone(),
            paths: NostrMcpPaths::from_root(config_root),
        }
    }
}

impl Default for NostrMcpRuntime {
    fn default() -> Self {
        Self::new("nostr-mcp", "nostr-mcp", default_config_root())
    }
}

pub fn default_config_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("nostr-mcp")
}

pub fn parse_config_root(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Path::new(trimmed).to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::{NostrMcpPaths, NostrMcpRuntime, default_config_root};
    use std::path::PathBuf;

    #[test]
    fn default_runtime_is_host_neutral() {
        let runtime = NostrMcpRuntime::default();
        assert_eq!(runtime.server_name, "nostr-mcp");
        assert_eq!(runtime.keyring_service, "nostr-mcp");
        assert_eq!(
            runtime.paths,
            NostrMcpPaths::from_root(default_config_root())
        );
        assert!(
            runtime
                .paths
                .config_root
                .ends_with(PathBuf::from(".config").join("nostr-mcp"))
        );
    }

    #[test]
    fn runtime_recomputes_paths_from_new_root() {
        let runtime = NostrMcpRuntime::new("host", "service", PathBuf::from("/tmp/original"));
        let updated = runtime.with_config_root(PathBuf::from("/tmp/custom"));

        assert_eq!(updated.server_name, "host");
        assert_eq!(updated.keyring_service, "service");
        assert_eq!(updated.paths.config_root, PathBuf::from("/tmp/custom"));
        assert_eq!(
            updated.paths.index_path,
            PathBuf::from("/tmp/custom/keys.enc")
        );
        assert_eq!(
            updated.paths.settings_path,
            PathBuf::from("/tmp/custom/settings.enc")
        );
        assert_eq!(
            updated.paths.keystore_secret_path,
            PathBuf::from("/tmp/custom/keystore.secret")
        );
    }
}
