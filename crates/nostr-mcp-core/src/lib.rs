#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod event_authoring_service;
pub mod event_filters;
pub mod events;
pub mod follows;
pub mod follows_service;
mod fs;
pub mod group_moderation_service;
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
pub mod profile_service;
pub mod protocol_publishing_service;
pub mod publish;
pub mod reference_parser;
pub mod relay_info;
pub mod relays;
pub mod replies;
pub mod secrets;
pub mod settings;
pub mod storage;

pub use error::CoreError;
