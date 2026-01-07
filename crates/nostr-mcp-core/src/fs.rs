use crate::error::CoreError;
use std::path::Path;

pub fn ensure_parent_dir(path: &Path) -> Result<(), CoreError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| CoreError::Io(format!("creating {}: {e}", dir.display())))?;
    }
    Ok(())
}
