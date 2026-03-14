#![forbid(unsafe_code)]

pub mod catalog;
pub mod host_runtime;
pub mod runtime;
pub mod service;
pub mod util;

pub use catalog::{HOST_LOCAL_TOOL_NAMES, NostrMcpServerCatalog, is_host_local_tool};
pub use runtime::{
    NostrMcpExecutionBudgets, NostrMcpPaths, NostrMcpRuntime, default_config_root,
    default_runtime_signer_policy,
};
pub use service::NostrMcpServerServices;
