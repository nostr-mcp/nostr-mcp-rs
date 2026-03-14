#![forbid(unsafe_code)]

pub mod error;
pub mod permission;
pub mod session;
pub mod uri;

pub use error::Nip46Error;
pub use permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};
pub use session::{Nip46ConnectionMode, Nip46SessionProfile};
pub use uri::{
    NIP46_BUNKER_URI_SCHEME, NIP46_CLIENT_URI_SCHEME, Nip46ClientMetadata, Nip46ConnectUri,
};
