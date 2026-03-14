#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod event_filters;
pub mod events;
pub mod follows;
mod fs;
pub mod groups;
pub mod key_store;
pub mod keys;
pub mod keystore;
pub mod metadata;
pub mod nip01;
pub mod nip05;
pub mod nip19;
pub mod nip30;
pub mod nip44;
pub mod nip58;
pub mod nip89;
pub mod polls;
pub mod publish;
pub mod reference_parser;
pub mod relay_info;
pub mod relays;
pub mod replies;
pub mod secrets;
pub mod settings;
pub mod storage;

pub use error::CoreError;
