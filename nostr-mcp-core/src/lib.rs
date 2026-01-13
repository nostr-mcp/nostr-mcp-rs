#![forbid(unsafe_code)]

pub mod error;
mod fs;
pub mod client;
pub mod events;
pub mod follows;
pub mod relays;
pub mod publish;
pub mod metadata;
pub mod replies;
pub mod polls;
pub mod groups;
pub mod nip01;
pub mod nip05;
pub mod nip19;
pub mod nip30;
pub mod nip58;
pub mod nip89;
pub mod nip44;
pub mod references;
pub mod relay_info;
pub mod keys;
pub mod key_store;
pub mod keystore;
pub mod secrets;
pub mod settings;
pub mod storage;

pub use error::CoreError;
