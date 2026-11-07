//! The protocol chain the leg is spoken over.

use mirage_core::config::{
    AuthMode, MirageEndpointConfig, TcpProtocolId, TransportCamouflage, TransportKind,
};
use mirage_protocol::driver::ClientCredential;
use mirage_protocol::endpoint_protocol::EndpointProtocol;
use mirage_protocol::negotiation::ProtocolChain;
use mirage_protocol::traits::TcpProtocol;

/// The wire version the leg speaks.
///
/// V9 is the version the fleet's own edge speaks, and the version the node
/// accepts — V8 has no credential slot, and a leg without a credential is a
/// leg the hop refuses.
pub const LEG_WIRE_VERSION: u8 = 9;

/// Build the protocol chain the leg is spoken over.
///
/// The camouflage is `None` here on purpose: the leg's OUTER disguise is the
/// entry hop's own published face, and it is applied by the onion builder,
/// not by the handshake.
pub fn build_protocol_chain(
    mesh_id: &[u8],
    credential: Option<ClientCredential>,
) -> ProtocolChain {
    let config = MirageEndpointConfig {
        transport: TransportKind::Tcp,
        auth: AuthMode::Blake3,
        camouflage: TransportCamouflage::None,
        byte_cipher: None,
        byte_cipher_mode: None,
    };
    let proto: Box<dyn TcpProtocol> = Box::new(
        EndpointProtocol::new(config, TcpProtocolId::Mirage, mesh_id.to_vec())
            .with_wire_version(LEG_WIRE_VERSION)
            .with_credential(credential),
    );
    ProtocolChain::new(vec![proto])
}
