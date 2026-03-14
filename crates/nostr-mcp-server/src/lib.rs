#![forbid(unsafe_code)]

pub mod catalog;

pub use catalog::{HOST_LOCAL_TOOL_NAMES, NostrMcpServerCatalog, is_host_local_tool};
