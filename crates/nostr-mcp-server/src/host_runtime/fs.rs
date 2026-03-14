use super::error::{HostRuntimeError, HostRuntimeResult};
use std::path::Path;

pub fn ensure_parent_dir(path: &Path) -> HostRuntimeResult<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| HostRuntimeError::io(format!("creating {}: {e}", dir.display())))?;
    }
    Ok(())
}
