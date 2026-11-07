//! The config files.
//!
//! # The server
//!
//! ```json
//! {
//!   "private_key": "<base64>",
//!   "peers": [
//!     { "name": "laptop", "public_key": "<base64>" }
//!   ],
//!   "listeners": {
//!     "mkvik": { "bind": "0.0.0.0:51821" },
//!     "tunnel": "0.0.0.0:51822"
//!   },
//!   "exit": { "mode": "direct" }
//! }
//! ```
//!
//! The two listeners are two ways into the same server:
//!
//! - `mkvik` -- the QUIC endpoint of MirageQUIC. One endpoint, many peers. It
//!   is the plane: the peer sends whole IP packets, and the box's own TUN
//!   device carries them out.
//! - `tunnel` -- the TCP port where a session arrives **through a SOCKS5
//!   proxy**. The proxy opens a CONNECT tunnel to this port, and the session
//!   runs inside it. It is the way to the server when the server cannot be
//!   reached directly.
//!
//! The exit is where the flows go:
//!
//! - `{ "mode": "direct" }` -- the server opens the connections itself.
//! - `{ "mode": "socks5", "proxy": "127.0.0.1:1080" }` -- the server hands
//!   every flow to a local SOCKS5 proxy. That is how the server's own system
//!   TUN is used: the TUN service exposes its chains as SOCKS5 listeners.
//!
//! # The client
//!
//! ```json
//! {
//!   "private_key": "<base64>",
//!   "server_public_key": "<base64>",
//!   "transport": { "kind": "mwg", "server": "203.0.113.7:51820" },
//!   "socks5_listen": "127.0.0.1:1080"
//! }
//! ```
//!
//! The transport is one of `mwg`, `mkvik` or `tunnel`. The `tunnel` one takes
//! a proxy as well:
//!
//! ```json
//! { "kind": "tunnel", "server": "vpn.example.com:51822", "proxy": "127.0.0.1:1080" }
//! ```
//!
//! The name of the server in a `tunnel` transport is resolved **by the proxy**:
//! the client never learns the server's address.

use std::net::SocketAddr;
use std::path::Path;

use mirage_core::config::{
    AuthMode as EndpointAuthMode, MirageEndpointConfig, TransportCamouflage, TransportKind,
};
use mirage_core::crypto::KeyPair;
use serde::Deserialize;

use crate::Error;

/// The config of the server.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// The node's own key, base64.
    pub private_key: String,
    /// The peers that are allowed to come.
    #[serde(default)]
    pub peers: Vec<ServerPeer>,
    /// Where the server listens.
    #[serde(default)]
    pub listeners: Listeners,
    /// The id both ends bake into the handshake.
    #[serde(default = "default_mesh_id")]
    pub mesh_id: String,
    /// Where the exit sends the flows.
    #[serde(default)]
    pub exit: Exit,
    /// Where the metrics endpoint listens. Absent = the endpoint is off.
    #[serde(default)]
    pub metrics: Option<MetricsListener>,
}

/// Where the metrics endpoint listens.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsListener {
    /// The address the endpoint binds to.
    ///
    /// The default is the loopback: the counters are for the operator, and
    /// the operator reaches the box over its own network.
    #[serde(default = "default_metrics_bind")]
    pub bind: SocketAddr,
}

/// One peer of the server.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerPeer {
    /// The peer's public key, base64.
    pub public_key: String,
    /// A name for the operator -- it is only ever a label.
    #[serde(default)]
    pub name: Option<String>,
}

/// Where the server listens.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Listeners {
    /// The QUIC endpoint of MirageQUIC.
    pub mkvik: Option<MkvikListener>,
    /// The TCP port where a session arrives through a SOCKS5 proxy.
    pub tunnel: Option<SocketAddr>,
}

/// The QUIC endpoint of MirageQUIC.
#[derive(Debug, Clone, Deserialize)]
pub struct MkvikListener {
    /// Where the endpoint is.
    pub bind: SocketAddr,
    /// The ALPN the endpoint speaks.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

impl MkvikListener {
    /// The camouflage of this endpoint.
    pub fn camouflage(&self) -> TransportCamouflage {
        TransportCamouflage::Quic {
            alpn: self.alpn.clone(),
            bind_addr: self.bind,
        }
    }
}

/// Where the exit sends the flows.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Exit {
    /// The server opens the connections itself.
    Direct,
    /// The server hands every flow to a local SOCKS5 proxy.
    Socks5 {
        /// The proxy the flows go to.
        proxy: SocketAddr,
    },
}

impl Default for Exit {
    fn default() -> Self {
        Exit::Direct
    }
}

/// The config of the client.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// The client's own key, base64.
    pub private_key: String,
    /// The server's public key, base64.
    pub server_public_key: String,
    /// How the server is reached.
    pub transport: Transport,
    /// Where the local SOCKS5 listens.
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: SocketAddr,
    /// The id both ends bake into the handshake.
    #[serde(default = "default_mesh_id")]
    pub mesh_id: String,
}

/// How the client reaches the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Transport {
    /// MirageWG: UDP with a junk burst.
    Mwg {
        /// Where the server listens.
        server: SocketAddr,
        /// The marker in front of a MWG packet.
        #[serde(default = "default_magic_byte")]
        magic_byte: u8,
        /// How many junk datagrams go out before the handshake.
        #[serde(default = "default_junk_count")]
        junk_count: u8,
        /// The smallest junk datagram.
        #[serde(default = "default_junk_min")]
        junk_min: u16,
        /// The largest junk datagram.
        #[serde(default = "default_junk_max")]
        junk_max: u16,
    },
    /// MirageQUIC: a QUIC connection.
    Mkvik {
        /// Where the server listens.
        server: SocketAddr,
        /// The ALPN the endpoint speaks.
        #[serde(default = "default_alpn")]
        alpn: Vec<String>,
    },
    /// The session inside a SOCKS5 CONNECT tunnel.
    Tunnel {
        /// The server's address. The name is resolved by the proxy.
        server: String,
        /// The proxy the tunnel goes through.
        proxy: SocketAddr,
    },
}

impl Transport {
    /// The camouflage this transport speaks, when it has one.
    ///
    /// The SOCKS5 tube has none: it is not an axis of the protocol, it is a
    /// pipe the session runs through.
    pub fn camouflage(&self) -> Option<TransportCamouflage> {
        match self {
            Transport::Mwg {
                server,
                magic_byte,
                junk_count,
                junk_min,
                junk_max,
            } => Some(TransportCamouflage::WireGuard {
                magic_byte: *magic_byte,
                junk_count: *junk_count,
                junk_min: *junk_min,
                junk_max: *junk_max,
                bind_addr: *server,
            }),
            Transport::Mkvik { server, alpn } => Some(TransportCamouflage::Quic {
                alpn: alpn.clone(),
                bind_addr: *server,
            }),
            Transport::Tunnel { .. } => None,
        }
    }
}

/// The endpoint config of a camouflage carrier.
///
/// The transport is derived from the camouflage, and the auth is the V9
/// mutual one -- the handshake proves the peer, and the frames carry no
/// separate MAC.
pub fn endpoint_config(camouflage: TransportCamouflage) -> MirageEndpointConfig {
    MirageEndpointConfig {
        transport: TransportKind::Udp,
        auth: EndpointAuthMode::Blake3,
        camouflage,
        byte_cipher: None,
        byte_cipher_mode: None,
    }
}

/// Where the client's SOCKS5 listens by default.
fn default_socks5_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1080))
}

/// Where the metrics endpoint listens by default.
///
/// The loopback: the counters are for the operator, and the operator reaches
/// the box over its own network.
fn default_metrics_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
}

/// The id both ends bake into the handshake.
fn default_mesh_id() -> String {
    "mirage-vpn".to_owned()
}

/// The marker in front of a MWG packet.
fn default_magic_byte() -> u8 {
    0x01
}

/// How many junk datagrams go out before the handshake.
fn default_junk_count() -> u8 {
    4
}

/// The smallest junk datagram.
fn default_junk_min() -> u16 {
    10
}

/// The largest junk datagram.
fn default_junk_max() -> u16 {
    20
}

/// The ALPN the QUIC endpoint speaks.
fn default_alpn() -> Vec<String> {
    vec!["h3".to_owned()]
}

impl ServerConfig {
    /// Read a config file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        let config: ServerConfig = serde_json::from_str(&text)?;
        Ok(config)
    }
}

impl ClientConfig {
    /// Read a config file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        let config: ClientConfig = serde_json::from_str(&text)?;
        Ok(config)
    }
}

/// Read a base64 key.
pub fn decode_key(text: &str) -> Result<[u8; 32], Error> {
    let bytes = decode_base64(text)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Config("a key is 32 bytes".to_owned()))?;
    Ok(bytes)
}

/// Read the node's own key.
pub fn decode_keypair(text: &str) -> Result<KeyPair, Error> {
    Ok(KeyPair::from_secret(decode_key(text)?))
}

/// The secret of a key pair, base64.
pub fn encode_secret(keypair: &KeyPair) -> String {
    encode_base64(&keypair.secret.to_bytes())
}

/// The public key of a key pair, base64.
pub fn encode_public(keypair: &KeyPair) -> String {
    encode_base64(keypair.public.as_bytes())
}

/// Decode base64 the way the config files use it.
fn decode_base64(text: &str) -> Result<Vec<u8>, Error> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|err| Error::Key(format!("not base64: {err}")))?;
    Ok(bytes)
}

/// Encode base64 the way the config files use it.
fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Split "host:port" into the two parts.
///
/// The host may be a name: in a tunnel transport the name is resolved by the
/// proxy, not here.
pub fn split_host_port(text: &str) -> Result<(String, u16), Error> {
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| Error::Config(format!("{text} is not host:port")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| Error::Config(format!("{port} is not a port")))?;
    if host.is_empty() {
        return Err(Error::Config("the host is empty".to_owned()));
    }
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_config_is_read() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "peers": [ { "name": "laptop", "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" } ],
            "listeners": { "mkvik": { "bind": "0.0.0.0:51821" } },
            "exit": { "mode": "direct" }
        }"#;
        let config: ServerConfig = serde_json::from_str(text).expect("config");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].name.as_deref(), Some("laptop"));
        let mkvik = config.listeners.mkvik.as_ref().expect("mkvik");
        assert_eq!(mkvik.bind.port(), 51821);
        assert!(config.listeners.tunnel.is_none());
        assert!(matches!(config.exit, Exit::Direct));
        assert_eq!(config.mesh_id, "mirage-vpn");
    }

    #[test]
    fn the_metrics_endpoint_is_off_by_default() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }"#;
        let config: ServerConfig = serde_json::from_str(text).expect("config");
        assert!(config.metrics.is_none());
    }

    #[test]
    fn the_metrics_endpoint_is_read_with_its_default_bind() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "metrics": {}
        }"#;
        let config: ServerConfig = serde_json::from_str(text).expect("config");
        let metrics = config.metrics.as_ref().expect("metrics");
        assert_eq!(metrics.bind, default_metrics_bind());
        assert_eq!(metrics.bind.port(), 9100);
        assert!(metrics.bind.ip().is_loopback());
    }

    #[test]
    fn the_metrics_endpoint_reads_its_own_bind() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "metrics": { "bind": "0.0.0.0:9999" }
        }"#;
        let config: ServerConfig = serde_json::from_str(text).expect("config");
        let metrics = config.metrics.as_ref().expect("metrics");
        assert_eq!(metrics.bind.port(), 9999);
    }

    #[test]
    fn the_exit_through_a_proxy_is_read() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "exit": { "mode": "socks5", "proxy": "127.0.0.1:1080" }
        }"#;
        let config: ServerConfig = serde_json::from_str(text).expect("config");
        match config.exit {
            Exit::Socks5 { proxy } => assert_eq!(proxy.port(), 1080),
            Exit::Direct => panic!("the exit should be the proxy"),
        }
    }

    #[test]
    fn a_client_config_is_read() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "server_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "transport": { "kind": "tunnel", "server": "vpn.example.com:51822", "proxy": "127.0.0.1:1080" }
        }"#;
        let config: ClientConfig = serde_json::from_str(text).expect("config");
        assert_eq!(config.socks5_listen.port(), 1080);
        match config.transport {
            Transport::Tunnel { server, proxy } => {
                assert_eq!(server, "vpn.example.com:51822");
                assert_eq!(proxy.port(), 1080);
            }
            _ => panic!("the transport should be the tunnel"),
        }
    }

    #[test]
    fn the_axis_parameters_have_defaults() {
        let text = r#"{
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "server_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "transport": { "kind": "mwg", "server": "203.0.113.7:51820" }
        }"#;
        let config: ClientConfig = serde_json::from_str(text).expect("config");
        match &config.transport {
            Transport::Mwg {
                magic_byte,
                junk_count,
                junk_min,
                junk_max,
                ..
            } => {
                assert_eq!(*magic_byte, default_magic_byte());
                assert_eq!(*junk_count, default_junk_count());
                assert_eq!(*junk_min, default_junk_min());
                assert_eq!(*junk_max, default_junk_max());
            }
            _ => panic!("the transport should be mwg"),
        }
    }

    #[test]
    fn a_key_pair_round_trips() {
        let keypair = KeyPair::generate();
        let secret = encode_secret(&keypair);
        let public = encode_public(&keypair);
        let read = decode_keypair(&secret).expect("keypair");
        assert_eq!(read.public.as_bytes(), keypair.public.as_bytes());
        assert_eq!(decode_key(&public).expect("key"), *keypair.public.as_bytes());
    }

    #[test]
    fn a_host_and_a_port_are_split() {
        let (host, port) = split_host_port("vpn.example.com:51822").expect("split");
        assert_eq!(host, "vpn.example.com");
        assert_eq!(port, 51822);
        assert!(split_host_port("vpn.example.com").is_err());
        assert!(split_host_port("vpn.example.com:port").is_err());
    }
}
