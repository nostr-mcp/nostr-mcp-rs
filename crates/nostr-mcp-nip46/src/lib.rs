#![forbid(unsafe_code)]

pub mod connect;
pub mod error;
pub mod message;
pub mod permission;
pub mod session;
pub mod uri;

pub use connect::{Nip46ConnectRequest, Nip46ConnectResponse, Nip46ConnectResult};
pub use error::Nip46Error;
pub use message::{
    Nip46Message, Nip46Request, Nip46RequestId, Nip46RequestMessage, Nip46ResponseMessage,
};
pub use permission::{Nip46Method, Nip46Permission, Nip46PermissionSet};
pub use session::{Nip46ConnectionMode, Nip46PendingSession, Nip46Session, Nip46SessionProfile};
pub use uri::{
    NIP46_BUNKER_URI_SCHEME, NIP46_CLIENT_URI_SCHEME, Nip46ClientMetadata, Nip46ConnectUri,
};
