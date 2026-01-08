#![forbid(unsafe_code)]

pub mod error;
mod fs;
pub mod client;
pub mod events;
pub mod follows;
pub mod relays;
pub mod metadata;
pub mod keys;
pub mod key_store;
pub mod keystore;
pub mod secrets;
pub mod settings;
pub mod storage;

pub use error::CoreError;
