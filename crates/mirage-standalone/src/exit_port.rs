//! The box's own exit — the local implementation of the OSS exit ports.
//!
//! A fleet box walks a mesh chain to reach an exit: the chain is held, the
//! next hop is dialled with a credential, and the stream rides the onion
//! plane. A standalone box has no chain and no mesh client — **it is the
//! exit**. There is nothing to walk to: the box opens the socket itself.
//!
//! What is NOT local is the policy. The box applies the SAME address policy
//! the fleet's exit applies — the SSRF guard, the resolver, the same target
//! parser — so a standalone box refuses exactly what a fleet exit refuses. A
//! box that skipped the guard would be a box an attacker can point at
//! `127.0.0.1` and `169.254.169.254`; that is the one thing this module must
//! not be.
//!
//! # The three ports
//!
//! | port | who answers it here |
//! |---|---|
//! | [`StreamOpener`] | [`LocalExit`] — a plain TCP socket to the target |
//! | [`DatagramFlowOpener`] | [`LocalExit`] — a plain UDP socket to the target |
//! | [`ExitCountryOracle`] | [`LocalExit`] — the country the operator named |

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mirage_core::error::MirageError;
use mirage_node::client::chain_store::ExitChoice;
use mirage_node::client::exit_port::{
    DatagramFlowError, DatagramFlowOpener, DatagramSinkBox, DatagramSourceBox, ExitCountryOracle,
    MeshStream, StreamOpenError, StreamOpener,
};
use mirage_node::client::udp_flow::{DatagramSink, DatagramSource};
use mirage_node::core::doh::DoHResolver;
use mirage_node::family::mirage::exit::{direct, policy};
use tokio::net::{TcpStream, UdpSocket};

/// The largest datagram the box will relay in either direction.
const MAX_DATAGRAM: usize = 65507;

/// The box's own UDP socket, shared by the two arms of one flow.
type SharedUdpSocket = Arc<tokio::sync::Mutex<UdpSocket>>;

/// The box's own exit.
///
/// Holds the box's resolver — the one its node already uses for its clients'
/// hostnames — so the exit resolves a target exactly the way the rest of the
/// box does.
pub struct LocalExit {
    doh: Option<Arc<DoHResolver>>,
    /// The country the operator named for this box, if any.
    countries: Vec<String>,
    /// Whether private address ranges are valid exit targets.
    ///
    /// The SAME knob the node has (`NodeToml.allow_private_exit_targets`): an
    /// operator who deploys the box as an intranet exit says so, and the box
    /// then serves private ranges. It defaults to OFF — the SSRF guard —
    /// and a missing setting fails CLOSED.
    allow_private: bool,
}

/// The box's own exit, described WITHOUT its resolver's internals.
///
/// The resolver holds DNS-over-HTTPS state and the country list is public
/// information; nothing here is a secret, and nothing here is worth printing
/// in full either.
impl std::fmt::Debug for LocalExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalExit")
            .field("has_resolver", &self.doh.is_some())
            .field("countries", &self.countries)
            .field("allow_private_targets", &self.allow_private)
            .finish()
    }
}

impl LocalExit {
    /// Build the box's exit.
    ///
    /// `doh` is the box's resolver; `country` is the country the operator
    /// named for the box (`MIRAGE_EXIT_COUNTRY`). A box with no named country
    /// serves the "auto" exit choice only.
    pub fn new(doh: Option<Arc<DoHResolver>>, country: Option<&str>) -> Self {
        Self::with_private_targets(doh, country, false)
    }

    /// Build the box's exit, saying whether private ranges are valid targets.
    pub fn with_private_targets(
        doh: Option<Arc<DoHResolver>>,
        country: Option<&str>,
        allow_private: bool,
    ) -> Self {
        Self {
            doh,
            countries: country
                .map(|c| vec![c.trim().to_ascii_uppercase()])
                .filter(|c| !c[0].is_empty())
                .unwrap_or_default(),
            allow_private,
        }
    }

    /// Resolve `host:port` to one address, refusing anything the box's own
    /// address policy blocks.
    ///
    /// EVERY address the name resolves to is inspected, not just the one that
    /// is dialled: a name that mixes a public A-record with a private one
    /// must not be dialled at all, because which of the two the dial would
    /// pick is not ours to decide.
    async fn resolve(&self, target: &str) -> Result<SocketAddr, StreamOpenError> {
        let (host, port) = direct::split_host_port(target).map_err(|e| StreamOpenError::Resolve {
            target: target.to_owned(),
            message: e.to_string(),
        })?;

        let addrs: Vec<SocketAddr> = match self.doh.as_ref() {
            Some(resolver) => {
                let ip = resolver.resolve(host).await.map_err(|e| StreamOpenError::Resolve {
                    target: target.to_owned(),
                    message: e.to_string(),
                })?;
                vec![SocketAddr::new(ip, port)]
            }
            None => tokio::net::lookup_host(target)
                .await
                .map_err(|e| StreamOpenError::Resolve {
                    target: target.to_owned(),
                    message: e.to_string(),
                })?
                .collect(),
        };

        if addrs.is_empty() {
            return Err(StreamOpenError::Resolve {
                target: target.to_owned(),
                message: "no DNS result".to_owned(),
            });
        }
        for addr in &addrs {
            if policy::is_blocked_exit_target(addr.ip(), self.allow_private) {
                return Err(StreamOpenError::Refused {
                    target: target.to_owned(),
                    reason: format!("{} is refused by the box's address policy", addr.ip()),
                });
            }
        }
        Ok(addrs[0])
    }
}

/// The box's own TCP exit.
#[async_trait]
impl StreamOpener for LocalExit {
    async fn open_stream(&self, _exit: &ExitChoice, target: &str) -> Result<MeshStream, StreamOpenError> {
        let addr = self.resolve(target).await?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| StreamOpenError::Dial {
                target: target.to_owned(),
                message: format!("cannot connect to {addr}: {e}"),
            })?;
        Ok(Box::new(stream))
    }
}

/// The box's own UDP exit.
#[async_trait]
impl DatagramFlowOpener for LocalExit {
    async fn open_datagram_flow(
        &self,
        _exit: &ExitChoice,
        target: &str,
    ) -> Result<(DatagramSinkBox, DatagramSourceBox), DatagramFlowError> {
        let addr = self.resolve(target).await.map_err(|e| match e {
            StreamOpenError::Resolve { target, message } => DatagramFlowError::Resolve { target, message },
            StreamOpenError::Refused { target, reason } => DatagramFlowError::Refused { target, reason },
            other => DatagramFlowError::Local {
                target: target.to_owned(),
                message: other.to_string(),
            },
        })?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DatagramFlowError::Local {
                target: target.to_owned(),
                message: format!("cannot bind a local UDP socket: {e}"),
            })?;
        socket.connect(addr).await.map_err(|e| DatagramFlowError::Local {
            target: target.to_owned(),
            message: format!("cannot connect the local UDP socket to {addr}: {e}"),
        })?;

        // One socket, two arms. Tokio does not expose the halves of a UDP
        // socket, so the arms share the socket behind a mutex — the lock is
        // taken per datagram and never held across the other's work.
        let socket = Arc::new(tokio::sync::Mutex::new(socket));
        Ok((
            Box::new(UdpSink {
                socket: Arc::clone(&socket),
            }) as DatagramSinkBox,
            Box::new(UdpSource { socket }) as DatagramSourceBox,
        ))
    }
}

/// The box's own exit countries — the country the operator named.
#[async_trait]
impl ExitCountryOracle for LocalExit {
    async fn servable_exit_countries(&self) -> Vec<String> {
        self.countries.clone()
    }
}

/// The sending half of a local UDP flow.
struct UdpSink {
    socket: SharedUdpSocket,
}

#[async_trait]
impl DatagramSink for UdpSink {
    async fn send_datagram(&mut self, data: &[u8]) -> Result<(), MirageError> {
        if data.len() > MAX_DATAGRAM {
            return Err(MirageError::Protocol(format!(
                "local udp exit: datagram of {} bytes is above the {} byte limit",
                data.len(),
                MAX_DATAGRAM
            )));
        }
        let socket = self.socket.lock().await;
        socket.send(data).await.map(|_| ()).map_err(MirageError::Io)
    }
}

/// The receiving half of a local UDP flow.
struct UdpSource {
    socket: SharedUdpSocket,
}

#[async_trait]
impl DatagramSource for UdpSource {
    async fn next_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let socket = self.socket.lock().await;
        let n = socket.recv(&mut buf).await.map_err(MirageError::Io)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_local_exit_refuses_a_loopback_target() {
        let exit = LocalExit::new(None, None);
        match exit.open_stream(&ExitChoice::Auto, "127.0.0.1:9").await {
            Err(StreamOpenError::Refused { .. }) => {}
            Err(other) => panic!("the refusal is by policy, not by a failed dial — got {other}"),
            // `MeshStream` is a boxed trait object and carries no `Debug`, so
            // the success arm cannot be printed — its existence is the point.
            Ok(_) => panic!("the box's own address policy refuses loopback"),
        }
    }

    #[tokio::test]
    async fn the_local_exit_refuses_a_link_local_target() {
        let exit = LocalExit::new(None, None);
        match exit.open_stream(&ExitChoice::Auto, "169.254.169.254:80").await {
            Err(StreamOpenError::Refused { .. }) => {}
            Err(other) => panic!("the box's own address policy refuses link-local — got {other}"),
            Ok(_) => panic!("the box's own address policy refuses link-local"),
        }
    }

    #[tokio::test]
    async fn the_local_exit_refuses_a_private_target() {
        let exit = LocalExit::new(None, None);
        match exit.open_stream(&ExitChoice::Auto, "10.0.0.1:443").await {
            Err(StreamOpenError::Refused { .. }) => {}
            Err(other) => panic!("the box's own address policy refuses private space — got {other}"),
            Ok(_) => panic!("the box's own address policy refuses private space"),
        }
    }

    #[tokio::test]
    async fn a_box_with_no_named_country_serves_the_auto_choice_only() {
        let exit = LocalExit::new(None, None);
        assert!(exit.servable_exit_countries().await.is_empty());
    }

    #[tokio::test]
    async fn a_box_with_a_named_country_serves_exactly_that_country() {
        let exit = LocalExit::new(None, Some("de"));
        assert_eq!(exit.servable_exit_countries().await, vec!["DE".to_owned()]);
    }
}
