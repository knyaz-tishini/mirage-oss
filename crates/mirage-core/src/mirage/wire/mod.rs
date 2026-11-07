//! Mirage wire plane — data-path types.

pub mod aead_suite;
pub mod auth;
pub mod credential_scheme;
pub mod camouflage;
pub mod exit_mode;
pub mod framing;
pub mod layer_spec;
pub mod listener_kind;
pub mod listener_spec;
pub mod protocol;
pub mod protocol_id;
pub mod relay_mode;
pub mod supported_axes;
pub mod transport;

pub use aead_suite::AeadSuite;
pub use auth::AuthMode;
pub use credential_scheme::CredentialScheme;
pub use camouflage::TransportCamouflage;
pub use exit_mode::ExitMode;
pub use framing::Framing;
pub use layer_spec::LayerSpec;
pub use listener_kind::MirageListenerKind;
pub use listener_spec::{
    ChainRole, DecoyRef, EntryHop, ListenerId, ListenerRole, MirageListenerSpec, SpecFingerprint,
    UpstreamRef,
};
pub use protocol::{MirageCamouflage, Protocol};
pub use protocol_id::{MirageCarrier, ProtocolId, TcpProtocolId, UdpProtocolId};
pub use relay_mode::{ByteCipherMode, ObfuscationAlgorithm, RelayMode};
pub use supported_axes::{
    byte_cipher_kind, camouflage_kind, ByteCipherKind, CamouflageKind, ExitModeKind, RelayModeKind,
    SupportedAxes,
};
pub use transport::TransportKind;
