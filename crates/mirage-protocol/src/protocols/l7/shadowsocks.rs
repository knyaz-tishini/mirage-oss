//! Shadowsocks 2022.
//!
//! The implementation is the official `shadowsocks` crate 1.25.0, MIT.
//! Linked with `aead-cipher-2022` only. DNS resolution and stream ciphers are off.

pub use shadowsocks::config::{ServerConfig, ServerType};
pub use shadowsocks::context::{Context, SharedContext};
pub use shadowsocks::crypto::CipherKind;
pub use shadowsocks::relay::socks5::Address;
pub use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;
pub use shadowsocks::relay::tcprelay::proxy_stream::{ProxyClientStream, ProxyServerStream};
