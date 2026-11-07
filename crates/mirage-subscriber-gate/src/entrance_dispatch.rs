//! Post-authentication dispatch primitives for a subscriber tunnel that
//! authenticated on an edge's entrance path (see
//! [`crate::entrance_auth::make_entrance_auth`]): resolving that
//! subscriber's bandwidth cap, and the bidirectional pump that charges it.
//!
//! ## What used to live here, and where it went
//!
//! Before the edge-as-entry cutover
//! (`docs/mirage/plans/2026-09-24-edge-as-entry.md`), an authenticated
//! subscriber tunnel accepted on `mirage-node`'s own entrance path was
//! handed to `dispatch_to_local_socks`, which forwarded it into cli2's
//! edge-client supervisor over a box-local unix channel (a real SOCKS5
//! client handshake, then a `Tunnel`-to-`AsyncRead+AsyncWrite` pump). Both
//! cli2 and that local-SOCKS hand-off are retired: `mirage-edge` now dials
//! the mesh itself, in-process, as the OWNER of its own onion chains — there
//! is no more local hop to splice a subscriber's tunnel into. What remains
//! here is the reusable half: resolving a subscriber's
//! [`ConnectionBandwidthLimiter`] from its captured key, and a pump shaped
//! for `mirage-edge`'s own in-process hand-off, where BOTH ends are now a
//! [`Tunnel`] (the subscriber's accepted tunnel, and the mesh chain's
//! dialled tunnel) rather than one `Tunnel` and one `AsyncRead + AsyncWrite`
//! stream.

use mirage_core::config::SubscriberEntranceConfig;
use mirage_core::error::Result;
use mirage_protocol::traits::Tunnel;
use tracing::{debug, warn};

use crate::bandwidth_cap::{ConnectionBandwidthLimiter, SubscriberBandwidthRegistry};
use crate::subscriber_keys::SubscriberKey;

/// Read/write buffer size for [`copy_tunnel_to_tunnel_capped`]'s pump —
/// matches `mirage-node`'s own `tunnel_io::BUF_SIZE`. Kept as a private copy
/// here rather than shared from that crate: this pump is the one and only
/// place a subscriber's bandwidth cap applies, so it lives beside the cap
/// concept instead of teaching a shared low-level IO helper about it.
const BUF_SIZE: usize = 16 * 1024;

/// Resolve the bandwidth cap for one accepted subscriber connection from its
/// captured key.
///
/// A missing `subscriber_key` should never happen — the entrance auth
/// predicate ([`crate::entrance_auth::make_entrance_auth`]) sets it alongside
/// its own "this was a subscriber" flag in the very same branch — but the
/// cap is a metering safeguard, not a security boundary: failing OPEN here
/// (uncapped, logged once) keeps the customer's connection alive rather than
/// breaking his service over an accounting gap.
pub fn resolve_subscriber_cap(
    subscriber_key: Option<SubscriberKey>,
    cfg: &SubscriberEntranceConfig,
    subscriber_bandwidth: &SubscriberBandwidthRegistry,
) -> Option<ConnectionBandwidthLimiter> {
    match subscriber_key {
        Some(key) => subscriber_bandwidth.connection_limiter(key, cfg),
        None => {
            warn!(
                "entrance: subscriber key accepted but the matched key was not captured \
                 — bandwidth cap skipped for this connection"
            );
            None
        }
    }
}

/// Bidirectional pump between two [`Tunnel`]s — the subscriber's own
/// accepted tunnel and the mesh chain's dialled tunnel `mirage-edge` holds
/// as that chain's owner — charging every chunk (either direction) against
/// `cap` before writing it out. `cap = None` — no bandwidth cap configured
/// for this edge — skips the charge and simply forwards bytes both ways.
///
/// Charging BEFORE the write is what gives this its backpressure: the loop
/// does not read the next chunk off either side until the current one's
/// charge-wait-then-send finishes, so a throttled connection stalls its OWN
/// upstream (each `Tunnel`'s own flow control) instead of buffering
/// unboundedly or dropping anything. Both directions charge the SAME `cap` —
/// "bandwidth sold is bandwidth total": an upload counts exactly like a
/// download.
pub async fn copy_tunnel_to_tunnel_capped(
    mut subscriber: Box<dyn Tunnel>,
    mut mesh_chain: Box<dyn Tunnel>,
    cap: Option<&ConnectionBandwidthLimiter>,
) -> Result<()> {
    let mut sub_buf = vec![0u8; BUF_SIZE];
    let mut mesh_buf = vec![0u8; BUF_SIZE];

    loop {
        tokio::select! {
            // subscriber → mesh chain (an upload, from the subscriber's perspective)
            result = subscriber.recv(&mut sub_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("entrance: subscriber tunnel closed");
                    let _ = mesh_chain.close().await;
                    return Ok(());
                }
                if let Some(cap) = cap {
                    cap.charge(n as u64).await;
                }
                mesh_chain.send(&sub_buf[..n]).await?;
            }
            // mesh chain → subscriber (a download)
            result = mesh_chain.recv(&mut mesh_buf) => {
                let n = result?;
                if n == 0 {
                    debug!("entrance: mesh chain tunnel closed");
                    let _ = subscriber.close().await;
                    return Ok(());
                }
                if let Some(cap) = cap {
                    cap.charge(n as u64).await;
                }
                subscriber.send(&mesh_buf[..n]).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::error::MirageError;
    use mirage_protocol::traits::TransportInfo;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    /// A minimal `Tunnel` backed by a pair of frame-preserving channels —
    /// ONE `send()` call becomes exactly ONE `recv()` return on the other
    /// end, matching `MirageCoreTunnel`'s real per-AEAD-frame semantics.
    struct MockTunnel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
        info: TransportInfo,
    }

    #[async_trait::async_trait]
    impl Tunnel for MockTunnel {
        async fn send(&mut self, data: &[u8]) -> Result<()> {
            self.outbound.send(data.to_vec()).map_err(|_| MirageError::TunnelClosed)
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            match self.inbound.recv().await {
                Some(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }

        async fn close(&mut self) -> Result<()> {
            Ok(())
        }

        fn transport_info(&self) -> &TransportInfo {
            &self.info
        }
    }

    /// The test's stand-in for whatever real caller sits on the other end of
    /// a mock tunnel: sends whole frames the pump will `recv()` one at a
    /// time, and reads back whatever the pump `send()`s.
    struct AppSide {
        to_tunnel: mpsc::UnboundedSender<Vec<u8>>,
        from_tunnel: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl AppSide {
        fn send_frame(&self, data: &[u8]) {
            self.to_tunnel.send(data.to_vec()).expect("pump side must still be reading");
        }

        async fn recv_frame(&mut self) -> Vec<u8> {
            self.from_tunnel.recv().await.expect("pump side closed without forwarding")
        }
    }

    /// A fixed stand-in for a mock tunnel's own remote address — every test
    /// here cares about the pump/cap logic, never about what a particular
    /// tunnel's `TransportInfo` reports.
    fn dummy_transport_addr() -> SocketAddr {
        "127.0.0.1:1".parse().expect("valid addr")
    }

    fn mock_tunnel_pair() -> (AppSide, Box<dyn Tunnel>) {
        let (app_to_tunnel_tx, app_to_tunnel_rx) = mpsc::unbounded_channel();
        let (tunnel_to_app_tx, tunnel_to_app_rx) = mpsc::unbounded_channel();
        let tunnel: Box<dyn Tunnel> = Box::new(MockTunnel {
            inbound: app_to_tunnel_rx,
            outbound: tunnel_to_app_tx,
            info: TransportInfo::tcp_raw(dummy_transport_addr()),
        });
        let app_side = AppSide { to_tunnel: app_to_tunnel_tx, from_tunnel: tunnel_to_app_rx };
        (app_side, tunnel)
    }

    /// A `SubscriberEntranceConfig` with every cap field `None` — an
    /// unconfigured edge, fully uncapped.
    fn uncapped_cfg() -> SubscriberEntranceConfig {
        SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        }
    }

    /// A `SubscriberEntranceConfig` with a flat aggregate rate/burst of
    /// `rate` and nothing else set.
    fn cfg_with_rate(rate: u64) -> SubscriberEntranceConfig {
        SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: Some(rate),
            aggregate_burst_bytes: Some(rate),
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        }
    }

    // ── `resolve_subscriber_cap`: the fail-open wiring. The registry's own
    // cap MATH (defaults, per-connection vs. aggregate, monthly degrade…) has
    // its exhaustive tests in `bandwidth_cap`; these only prove this
    // function calls through to it rather than shortcutting. ──────────────

    /// A missing captured key is a fail-OPEN condition: `resolve_subscriber_cap`
    /// must return `None` (uncapped) rather than erroring, even when the
    /// edge's config carries a cap.
    #[test]
    fn a_missing_captured_key_resolves_to_no_cap() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1);
        assert!(
            resolve_subscriber_cap(None, &cfg, &registry).is_none(),
            "a missing captured key must fail open, uncapped"
        );
    }

    /// A captured key against a configured rate resolves to a real limiter.
    #[test]
    fn a_captured_key_resolves_the_registrys_limiter() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1000);
        let key: SubscriberKey = [0x11; 32];
        assert!(resolve_subscriber_cap(Some(key), &cfg, &registry).is_some());
    }

    /// No configured rate at all resolves to no limiter regardless of the
    /// key — matches [`SubscriberBandwidthRegistry::connection_limiter`]'s
    /// own contract.
    #[test]
    fn no_configured_rate_resolves_to_no_cap_even_with_a_captured_key() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = uncapped_cfg();
        let key: SubscriberKey = [0x22; 32];
        assert!(resolve_subscriber_cap(Some(key), &cfg, &registry).is_none());
    }

    // ── `copy_tunnel_to_tunnel_capped`: the pump, driven over two mock
    // tunnels — one standing in for the subscriber's own accepted tunnel,
    // one for the mesh chain's dialled tunnel. ───────────────────────────

    #[tokio::test]
    async fn pump_forwards_bytes_both_directions_uncapped() {
        let (mut sub_app, subscriber_tunnel) = mock_tunnel_pair();
        let (mut mesh_app, mesh_tunnel) = mock_tunnel_pair();

        let pump = tokio::spawn(copy_tunnel_to_tunnel_capped(subscriber_tunnel, mesh_tunnel, None));

        sub_app.send_frame(b"hello");
        let got = mesh_app.recv_frame().await;
        assert_eq!(got, b"hello", "the mesh side must see the subscriber's upload");

        mesh_app.send_frame(b"world");
        let reply = sub_app.recv_frame().await;
        assert_eq!(reply, b"world", "the subscriber side must see the mesh's download");

        drop(sub_app);
        drop(mesh_app);
        let _ = tokio::time::timeout(Duration::from_secs(2), pump).await;
    }

    /// A real, tight cap measurably delays delivery — proves the charge is
    /// actually wired into the pump, not just constructed and discarded —
    /// and that every byte still arrives once the debt is paid off.
    #[tokio::test]
    async fn a_tight_cap_measurably_delays_delivery_without_losing_bytes() {
        let registry = SubscriberBandwidthRegistry::new();
        let mut cfg = cfg_with_rate(100);
        // 100 B/s with a 10-byte burst: a 50-byte payload spends the whole
        // burst instantly and then owes 40 bytes at 100 B/s — 400ms.
        cfg.aggregate_burst_bytes = Some(10);
        cfg.per_connection_rate_bytes_per_sec = Some(100);
        let key: SubscriberKey = [0x77; 32];
        let cap = registry.connection_limiter(key, &cfg).expect("configured");

        let (sub_app, subscriber_tunnel) = mock_tunnel_pair();
        let (mut mesh_app, mesh_tunnel) = mock_tunnel_pair();

        let payload = vec![0xABu8; 50];
        sub_app.send_frame(&payload);
        // Dropping the sender AFTER the frame is enqueued lets the pump's
        // subscriber side observe a clean close right after delivering the
        // one payload, so the pump returns on its own once the reader below
        // has the bytes — no second frame needed.
        drop(sub_app);

        let reader = tokio::spawn(async move { mesh_app.recv_frame().await });

        let t0 = Instant::now();
        let pump_result = tokio::time::timeout(
            Duration::from_secs(5),
            copy_tunnel_to_tunnel_capped(subscriber_tunnel, mesh_tunnel, Some(&cap)),
        )
        .await;
        pump_result.expect("pump must not hang").expect("pump must complete without error");
        let elapsed = t0.elapsed();

        let received = reader.await.expect("reader task must not panic");
        assert_eq!(received, payload, "every byte must still arrive, just later");
        assert!(
            elapsed >= Duration::from_millis(300),
            "a 50-byte payload at 100 B/s past a 10-byte burst must take roughly 400ms, took {elapsed:?}"
        );
    }
}
