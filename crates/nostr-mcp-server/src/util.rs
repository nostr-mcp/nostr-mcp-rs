use crate::host_runtime::error::HostRuntimeResult;
use crate::host_runtime::keystore;
use std::path::Path;

pub(crate) fn ensure_keystore_secret(path: &Path) -> HostRuntimeResult<Vec<u8>> {
    keystore::ensure_keystore_secret(path)
}
