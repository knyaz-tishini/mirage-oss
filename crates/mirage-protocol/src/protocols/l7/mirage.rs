//! Mirage, one application protocol.
//!
//! TCP and UDP are carriers of this protocol. They are not a second protocol.
//! The handshake and the AEAD frames live in [`crate::auth::v9`] and [`crate::cores`].

pub use crate::auth::v9;
pub use crate::cores::handshake;
pub use crate::cores::tunnel;
pub use crate::cores::udp_handshake;
pub use crate::cores::udp_tunnel;

/// How a Mirage session is carried. The protocol is the same on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Carrier {
    Tcp,
    Udp,
}
