//! The compatibility facade over the protocol cores.
//!
//! The protocol cores moved to [`crate::cores`]. The names here still work —
//! they are the paths the fleet has used since the beginning — so nothing
//! downstream had to change in one go. New code should use
//! `mirage_protocol::cores::*`.
//!
//! What stayed here is the mshd plumbing: the RPC frames and the end-to-end
//! stream of the management shell. That is not a protocol core — it is the
//! shell's own transport.

pub mod dgram_chain_addr;
pub mod mshd_e2e;
pub mod mshd_rpc;

pub use crate::cores::handshake;
pub use crate::cores::tunnel;
pub use crate::cores::udp_handshake;
pub use crate::cores::udp_tunnel;

pub use handshake::{
    run_client_handshake, run_client_handshake_v9,
    run_server_handshake, run_server_handshake_v9, run_server_handshake_with_auth,
    ClientHandshakeResult, ServerHandshakeResult, ClientAuthContext,
};
pub use udp_handshake::{
    run_client_handshake_v9_datagram, run_client_handshake_v9_datagram_with_credential,
    run_server_handshake_v9_datagram, ServerHelloCache, MAX_CREDENTIAL_LEN_DATAGRAM,
};
pub use mshd_e2e::{
    opbox_open_session, mshd_accept_session,
    RelayE2eStream, RelayFrame, SessionId, MESH_E2E_LABEL,
};
pub use mshd_rpc::{
    read_mcp_frame, read_mcp_frame_with_keepalive, write_mcp_frame, McpError, McpRequest,
    McpResponse,
    MSHD_RPC_CHUNK_SIZE, MSHD_RPC_MAX_FRAME,
};
pub use tunnel::MirageCoreTunnel;
pub use udp_tunnel::{MirageCoreUdpTunnel, UdpTunnelReceiver, UdpTunnelSender};
