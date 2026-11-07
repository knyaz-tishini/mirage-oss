//! Tunnel establishment through the Mirage chain.

use std::{net::SocketAddr, time::Duration};
#[cfg(test)]
use std::io;
#[cfg(test)]
use tokio::net::TcpStream;

use async_trait::async_trait;
use mirage_core::{
    config::{
        AuthMode, ChainConfig, MirageEndpointConfig, ProtocolId,
        ShapingPreset, TransportCamouflage, TransportKind, UdpProtocolId,
    },
    crypto::{credential::{CredentialParams, EpochEntry}, AeadSuite},
    error::MirageError,
    mirage::{mesh::PeerTable, wire::CredentialScheme},
};
use mirage_protocol::{
    core::{
        dgram_chain_addr::DatagramChainAddress, MirageCoreUdpTunnel, UdpTunnelReceiver,
        UdpTunnelSender,
    },
    driver::{run_client_udp_v9, ClientCredential},
    frame_obfuscation::patterns,
    negotiation::ProtocolChain,
    onion::layer::NextHop,
    traits::{TransportInfo, Tunnel},
    transport::udp::UdpPeerSocket,
};
use tracing::{debug, warn};

use crate::cover_tunnel::CoverTunnel;
use crate::onion_tunnel_fs::OnionFsTunnel;
use crate::onion_tunnel_fs_udp::{OnionFsUdpTunnel, OnionFsUdpTunnelReceiver, OnionFsUdpTunnelSender};
use crate::shaped_tunnel::ShapedTunnel;

/// Current Unix timestamp in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Mint a fresh [`ClientCredential`] from `params` at the current time.
///
/// Picks the first non-expired epoch (`not_after_ms > now_ms`).
///
/// Returns `None` when:
/// - The scheme is not `EpochHmac` (VOPRF is not yet implemented client-side).
/// - No live epoch exists in `params`.
///
/// UNLINKABILITY: a fresh `random_nonce16()` is drawn on every call.
/// The caller in `establish_raw_tunnel` calls this once per dial — never
/// cache or reuse the returned token.
pub fn mint_epoch_hmac_credential(
    params: &CredentialParams,
    now_ms_arg: u64,
) -> Option<ClientCredential> {
    // find the EpochHmac authority (client self-mint only supports the symmetric arm)
    let Some(authority) = params.authorities.iter().find(|a| a.scheme == CredentialScheme::EpochHmac) else {
        warn!(
            "mint_epoch_hmac_credential: no EpochHmac authority configured — dial proceeds without credential"
        );
        return None;
    };
    let entry: &EpochEntry = authority
        .epochs
        .iter()
        .find(|e| e.not_after_ms > now_ms_arg)?;

    let key = mirage_core::crypto::credential::epoch_hmac::EpochHmacKey::from_bytes(entry.secret);
    let nonce = mirage_core::crypto::credential::epoch_hmac::random_nonce16();
    let token = mirage_core::crypto::credential::epoch_hmac::issue_epoch_hmac(&key, entry.epoch_id, nonce);

    debug!(
        epoch_id = entry.epoch_id,
        "minting EpochHmac credential for dial"
    );

    Some(ClientCredential {
        scheme: 0x01, // CredentialScheme::EpochHmac wire byte
        token: token.to_vec(),
    })
}

/// Parse and return the entry-hop dial address from `hops[0].addr`.
///
/// Performs no DNS resolution — the addr string must already be `host:port`
/// with a numeric IP.
fn entry_hop_addr(chain: &ChainConfig) -> Result<SocketAddr, MirageError> {
    let hop = chain.hops.first().ok_or_else(|| {
        MirageError::Config(format!(
            "chain {}: hops list is empty — no entry hop",
            chain.chain_id
        ))
    })?;
    hop.addr.parse::<SocketAddr>().map_err(|e| {
        MirageError::Config(format!(
            "chain {}: invalid entry hop addr '{}': {e}",
            chain.chain_id, hop.addr
        ))
    })
}

/// RFC 8305 Happy Eyeballs v2: race v6 vs v4 probes, v6 gets a 200 ms head-start.
///
/// Returns the address whose probe succeeded first.  Both probes use a 5 s
/// per-address TCP timeout.  `chain_protocols.connect` will re-dial the winner.
///
/// Cancellation: the loser future is dropped at the end of `select!`; the OS
/// TCP stack may have a half-open connection in flight for the loser, which the
/// OS cleans up after its own SYN timeout (~20 s).  This is the standard
/// Happy Eyeballs trade-off — one extra SYN at most, no fd leak on our side.
#[cfg(test)]
async fn happy_eyeballs(v4: SocketAddr, v6: SocketAddr) -> io::Result<SocketAddr> {
    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
    const V6_HEAD_START: Duration = Duration::from_millis(200);

    // Each probe returns `(tag, Result<SocketAddr, io::Error>)`.
    // We spawn both as tasks so we can independently await them and cancel the
    // loser by dropping its JoinHandle.
    let v6_task = tokio::spawn(async move {
        match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(v6)).await {
            Ok(Ok(_stream)) => Ok(v6),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "v6 probe timed out")),
        }
    });
    let v4_task = tokio::spawn(async move {
        tokio::time::sleep(V6_HEAD_START).await;
        match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(v4)).await {
            Ok(Ok(_stream)) => Ok(v4),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "v4 probe timed out")),
        }
    });

    // First winner takes it; loser task is aborted when its JoinHandle is
    // dropped.  At most one stray SYN may be in flight in the OS after abort —
    // standard Happy Eyeballs trade-off.
    let mut v6_done = false;
    let mut v4_done = false;
    let mut errors: Vec<io::Error> = Vec::new();

    tokio::pin!(v6_task);
    tokio::pin!(v4_task);

    loop {
        tokio::select! {
            r = &mut v6_task, if !v6_done => {
                v6_done = true;
                match r {
                    Ok(Ok(addr)) => {
                        debug!(v6 = %addr, "happy eyeballs: v6 probe won");
                        return Ok(addr);
                    }
                    Ok(Err(e)) => {
                        debug!(v6 = %v6, error = %e, "happy eyeballs: v6 probe failed");
                        errors.push(e);
                    }
                    Err(e) => {
                        debug!(v6 = %v6, "happy eyeballs: v6 task panicked: {e}");
                        errors.push(io::Error::new(io::ErrorKind::Other, "v6 task panicked"));
                    }
                }
                if v4_done { break; }
            },
            r = &mut v4_task, if !v4_done => {
                v4_done = true;
                match r {
                    Ok(Ok(addr)) => {
                        debug!(v4 = %addr, "happy eyeballs: v4 probe won");
                        return Ok(addr);
                    }
                    Ok(Err(e)) => {
                        debug!(v4 = %v4, error = %e, "happy eyeballs: v4 probe failed");
                        errors.push(e);
                    }
                    Err(e) => {
                        debug!(v4 = %v4, "happy eyeballs: v4 task panicked: {e}");
                        errors.push(io::Error::new(io::ErrorKind::Other, "v4 task panicked"));
                    }
                }
                if v6_done { break; }
            },
        }
    }

    Err(errors.into_iter().next().unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "no address succeeded")
    }))
}

/// Establish an encrypted tunnel through the entry hop, without sending a
/// target address.
///
/// The only supported path is hops-based: `chain.hops` must be non-empty.
/// When `hops.len() == 1` the chain is a direct single-hop tunnel — the
/// `chain_protocols.connect` handshake uses `hops[0].public_key` and `sni`.
/// When `hops.len() > 1` the onion (telescopic/ephemeral) path is used.
///
/// For UDP chains (`chain.protocol = MirageUdp`) the call is forwarded to
/// `establish_udp_chain_tunnel` which builds the camouflage from
/// `hops[0].camouflage` (single-hop only; multi-hop UDP is an error).
///
/// Returns a boxed [`Tunnel`] ready for a target-address frame followed by
/// bidirectional data transfer.
/// Resolve the X25519 public key for a hop.
///
/// Prefers `hop.public_key` (static override / already-materialized).
/// Falls back to `peer_table` lookup via `hop.node_id` then `hop.display_name`.
/// Returns a `MirageError::Config` if neither yields a valid 64-hex pubkey.
fn resolve_hop_pubkey(
    chain_id: &str,
    hop_idx: usize,
    hop: &mirage_core::config::HopConfig,
    peer_table: &PeerTable,
) -> Result<String, MirageError> {
    if let Some(pk) = hop.public_key.as_deref() {
        return Ok(pk.to_owned());
    }
    let node_id = hop
        .node_id
        .as_deref()
        .or(hop.display_name.as_deref())
        .ok_or_else(|| {
            MirageError::Config(format!(
                "chain {chain_id}: hop[{hop_idx}] has neither public_key nor node_id"
            ))
        })?;
    peer_table
        .lookup_by_str(node_id)
        .map(|e| e.pubkey_hex.clone())
        .ok_or_else(|| {
            MirageError::Config(format!(
                "chain {chain_id}: hop[{hop_idx}] node_id '{node_id}' not in \
                 peer_table — node may not be registered yet"
            ))
        })
}

/// Resolve the outbound camouflage the client should wrap its dial to the
/// ENTRY hop in, from that node's own signed chain face in `peer_table`.
///
/// Camouflage follows the persona, never the reverse: a hop's disguise is
/// the target's own published face, not something a dialer invents or is
/// handed by the chain plan. `hop.camouflage` is consulted first — an
/// explicit `Some(_)` there is a caller that already knows the right
/// wrapper (e.g. `MeshClient::dial_with_camo`'s monitor-mesh candidate
/// probing, which dials a monitor's own signed face by a different
/// mechanism — monitors publish no chain face at all) — and is used
/// as-is, never overridden. Only `None` triggers the peer_table lookup.
///
/// The absent case is a refusal, never a raw-shaped dial:
/// `chain_face: None` means the target has published no chain face at
/// all, so there is nothing dialable — this returns `Err` naming the
/// node. A published face whose own camouflage is
/// `TransportCamouflage::None` (port 22 on every box, for one) is a
/// legitimate raw-shaped face and is returned as
/// `Ok(Some(TransportCamouflage::None))`, dialed raw exactly like any
/// other camouflage. The two must never be confused — that is why
/// `ChainFace` bundles port and camouflage in one struct rather than two
/// `Option`s; see its own doc.
fn resolve_entry_face_camouflage(
    chain_id: &str,
    hop: &mirage_core::config::HopConfig,
    peer_table: &PeerTable,
) -> Result<Option<TransportCamouflage>, MirageError> {
    if hop.camouflage.is_some() {
        return Ok(hop.camouflage.clone());
    }
    let node_id = hop
        .node_id
        .as_deref()
        .or(hop.display_name.as_deref())
        .ok_or_else(|| {
            MirageError::Config(format!(
                "chain {chain_id}: entry hop has neither an explicit camouflage \
                 nor a node_id — cannot resolve its chain face"
            ))
        })?;
    let peer = peer_table.lookup_by_str(node_id).ok_or_else(|| {
        MirageError::Config(format!(
            "chain {chain_id}: entry hop '{node_id}' not in peer_table — \
             cannot resolve its chain face"
        ))
    })?;
    let face = peer.chain_face.as_ref().ok_or_else(|| {
        MirageError::Config(format!(
            "chain {chain_id}: entry hop '{node_id}' has published no chain \
             face — refusing to dial"
        ))
    })?;
    Ok(Some(face.camouflage.clone()))
}

/// Apply [`resolve_entry_face_camouflage`] to `resolved.hops[0]` in place.
///
/// Used before handing a multi-hop chain to [`OnionFsTunnel::connect`],
/// which has no `peer_table` access of its own (it takes only
/// `peer_table_generation: u64`) — the resolution has to happen here, on
/// the caller's side, exactly like [`resolve_chain_pubkeys`] already does
/// for `hop.public_key`.
fn apply_entry_face_camouflage(
    resolved: &mut ChainConfig,
    peer_table: &PeerTable,
) -> Result<(), MirageError> {
    let Some(hop0) = resolved.hops.first() else {
        return Ok(());
    };
    let camouflage = resolve_entry_face_camouflage(&resolved.chain_id, hop0, peer_table)?;
    resolved.hops[0].camouflage = camouflage;
    Ok(())
}

/// Resolve all hop public keys in a chain from the peer_table and return a
/// cloned `ChainConfig` with every `hop.public_key` filled in.
///
/// Hops that already have a `public_key` are passed through unchanged.
/// Hops with `public_key = None` are resolved via `node_id` (or `display_name`)
/// against the peer_table. If any hop cannot be resolved the function returns
/// a `MirageError::Config` error.
///
/// This pre-resolution step is required before passing a chain to
/// `OnionFsTunnel::connect` because the FS onion builder reads
/// `hop.public_key` directly without access to the peer_table. Without
/// pre-resolution, hops with `public_key = None` cause the "hop public_key
/// must be 64 hex chars, got 0" config error.
pub fn resolve_chain_pubkeys(
    chain: &ChainConfig,
    peer_table: &PeerTable,
) -> Result<ChainConfig, MirageError> {
    let mut resolved = chain.clone();
    for (i, hop) in resolved.hops.iter_mut().enumerate() {
        if hop.public_key.is_none() {
            let pubkey = resolve_hop_pubkey(&chain.chain_id, i, hop, peer_table)?;
            hop.public_key = Some(pubkey);
        }
    }
    Ok(resolved)
}

/// Re-resolve hop public keys in a chain, preferring fresh peer_table data over
/// any static `hop.public_key` that may be stale after a node ephemeral-key rotation.
///
/// For each hop that has a `node_id` (or `display_name`) set, the peer_table is
/// queried first.  When the node is found, its current pubkey overwrites whatever
/// was in `hop.public_key` — this ensures reconnect attempts after a node restart
/// always use the freshest key.  When the node is **not** in the peer_table, the
/// existing `hop.public_key` is kept as a fallback (cold-start or peer_table lag).
/// Hops with neither `node_id` nor `public_key` return a `MirageError::Config`.
///
/// Use this instead of [`resolve_chain_pubkeys`] in reconnect loops so that
/// ephemeral-key rotations (node restart → new X25519 keypair → peer_table update)
/// are picked up immediately without waiting for a full `switch_chain`.
pub fn freshen_chain_pubkeys(
    chain: &ChainConfig,
    peer_table: &PeerTable,
) -> Result<ChainConfig, MirageError> {
    let mut resolved = chain.clone();
    for (i, hop) in resolved.hops.iter_mut().enumerate() {
        // Prefer peer_table lookup when node_id is available — gives the live key.
        let node_id_opt = hop
            .node_id
            .as_deref()
            .or(hop.display_name.as_deref());

        if let Some(node_id) = node_id_opt {
            if let Some(entry) = peer_table.lookup_by_str(node_id) {
                // peer_table has a live entry — always use its pubkey (may differ
                // from hop.public_key after ephemeral key rotation).
                hop.public_key = Some(entry.pubkey_hex.clone());
                continue;
            }
            // node_id known but not in peer_table yet — keep static key if set,
            // otherwise error.  This handles the cold-start window where the table
            // is still propagating.
            if hop.public_key.is_none() {
                return Err(MirageError::Config(format!(
                    "chain {}: hop[{i}] node_id '{node_id}' not in \
                     peer_table — node may not be registered yet",
                    chain.chain_id
                )));
            }
            // Static key is the only option right now; use it.
            continue;
        }

        // No node_id — must have a static public_key.
        if hop.public_key.is_none() {
            return Err(MirageError::Config(format!(
                "chain {}: hop[{i}] has neither public_key nor node_id",
                chain.chain_id
            )));
        }
    }
    Ok(resolved)
}

/// Build the onion-only sub-chain for a transparent-relay chain.
///
/// Transparent-relay chains have a leading passthrough hop (Transparent /
/// CryptoVerify) that byte-pumps raw bytes to the exit without any Mirage AEAD
/// layer. The exit listener is configured as a 1-hop onion. We must therefore
/// build the FS onion circuit only for the OnionPeel hops and dial through
/// the passthrough entry.
///
/// Returns `Cow::Borrowed(chain)` when all hops are `OnionPeel` from index 0
/// (normal multi-hop — no patching needed). Returns `Cow::Owned(synthetic)`
/// when leading passthrough hops exist: the synthetic chain contains only the
/// `OnionPeel` hops with the first hop's `addr`, `camouflage`, `node_id`, and
/// `camo_server_pubkey` patched from the passthrough entry hop so that
/// `OnionFsTunnel::connect` dials the entry node rather than the exit.
///
/// `label` is used only in the debug log line (e.g. `""` for raw, `" (mux)"` for mux).
fn build_onion_chain_for_transparent_entry<'a>(
    chain: &'a ChainConfig,
    label: &str,
) -> std::borrow::Cow<'a, ChainConfig> {
    let first_passthrough = chain.hops.iter().position(|h| {
        matches!(h.relay_mode, mirage_core::mirage::wire::RelayMode::OnionPeel)
    });
    match first_passthrough {
        // All hops are OnionPeel from index 0 — use chain as-is.
        Some(0) => std::borrow::Cow::Borrowed(chain),
        // Leading passthrough hops exist at indices 0..first_onion_idx.
        // Build a synthetic chain with only the OnionPeel hops, dialing
        // through the passthrough entry node's address.
        Some(first_onion_idx) => {
            let entry_hop = &chain.hops[0];
            let entry_dial_addr = entry_hop.addr.clone();
            let mut onion_hops: Vec<mirage_core::config::HopConfig> =
                chain.hops[first_onion_idx..].to_vec();
            // Patch the first onion hop's addr, camouflage, and node_id
            // from the passthrough entry hop so that:
            // - OnionFsTunnel::connect dials the entry node's address.
            // - Reality/TLS handshake uses the entry node's camouflage params
            //   (short_id, SNI, ALPN) rather than the exit node's.
            //
            // public_key is NOT patched here — it stays as the exit node's
            // pubkey (filled by freshen_chain_pubkeys before this call) so that
            // the onion AEAD handshake with the exit node uses the correct key.
            //
            // camo_server_pubkey IS set to the entry node's pubkey so that
            // wrap_tcp_client (Reality ECDH) authenticates against the entry
            // node's ephemeral keypair — the TCP server handling the outer
            // camouflage handshake IS the entry node, not the exit.
            onion_hops[0].addr = entry_dial_addr;
            onion_hops[0].camouflage = entry_hop.camouflage.clone();
            onion_hops[0].node_id = entry_hop.node_id.clone();
            onion_hops[0].camo_server_pubkey = entry_hop.public_key.clone();
            let mut synthetic = chain.clone();
            synthetic.hops = onion_hops;
            debug!(
                chain_id = %chain.chain_id,
                total_hops = chain.hops.len(),
                onion_hops = synthetic.hops.len(),
                passthrough_hops = first_onion_idx,
                label,
                "transparent-relay chain: building onion for exit hop only"
            );
            std::borrow::Cow::Owned(synthetic)
        }
        // No OnionPeel hop found — chain_uses_onion is true but no
        // OnionPeel hop exists; this should be unreachable.
        None => std::borrow::Cow::Borrowed(chain),
    }
}

/// Does this chain speak the onion wire — a length-prefixed target and a
/// per-hop peeled envelope — rather than a plain V9 stream?
///
/// **One predicate, every caller.** It used to be spelled `hops.len() > 1`
/// independently in the dialer, in the client's mux pool (twice) and in the
/// operator's probe, and each copy meant "multi-hop". Depth is the wrong
/// question: a one-hop chain reached at a node's chain face is onion-shaped
/// too — it carries a face hello and an envelope, its exit peels a layer, and
/// its target arrives length-prefixed. Callers that answered by depth sent a
/// RAW target into an onion exit, which reads it as a mux marker and closes
/// the tunnel without a byte.
///
/// The rule is the relay mode plus the door: `OnionPeel` hops, and either more
/// than one of them or an entry reached at a published chain face. A dial
/// whose caller supplied the entry camouflage itself is the monitor mesh —
/// monitors publish no chain face — and stays a plain handshake at any depth.
pub fn chain_uses_onion_framing(chain: &ChainConfig, peer_table: &PeerTable) -> bool {
    let any_onion_peel = chain
        .hops
        .iter()
        .any(|h| matches!(h.relay_mode, mirage_core::mirage::wire::RelayMode::OnionPeel));
    if !any_onion_peel {
        return false;
    }
    if chain.hops.len() > 1 {
        return true;
    }
    chain
        .hops
        .first()
        .filter(|h| h.camouflage.is_none())
        .and_then(|h| h.node_id.as_deref().or(h.display_name.as_deref()))
        .and_then(|nid| peer_table.lookup_by_str(nid))
        .map(|peer| peer.chain_face.is_some())
        .unwrap_or(false)
}

pub async fn establish_raw_tunnel(
    chain_protocols: &ProtocolChain,
    chain: &ChainConfig,
    peer_table: &PeerTable,
    mesh_id: &[u8],
    pre_minted: Option<&ClientCredential>,
    credential_params: Option<&CredentialParams>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    if chain.hops.is_empty() {
        return Err(MirageError::Config(format!(
            "chain {}: hops list is empty — cannot establish tunnel",
            chain.chain_id
        )));
    }

    // ── Native UDP chain path ─────────────────────────────────────────────────
    if let ProtocolId::Udp(udp_id) = &chain.protocol {
        return establish_udp_chain_tunnel(chain, *udp_id, peer_table, mesh_id, pre_minted, credential_params).await;
    }

    // ── Onion path — at ANY depth, including one hop ─────────────────────────
    //
    // Gate by RelayMode, not by hops.len(): a chain whose hops are all
    // Transparent / CryptoVerify is NOT an onion chain — onion requires
    // per-hop ECDH layer keys that only OnionPeel hops carry.
    //
    // Depth does NOT decide the shape. It used to: `hops.len() > 1` sent a
    // one-hop chain down the direct V9 handshake instead, and that shape
    // cannot enter a node through its chain face — it writes neither the face
    // hello the perimeter waits for nor the length-prefixed envelope
    // `chain_splice` reads. Measured on a lab mesh: 2, 3 and 4 hops carried bytes
    // end to end while 1 hop died on the entry face with a peek timeout. A
    // client that must not think about depth cannot have depth decide its
    // wire.
    //
    // What DOES decide is which door the entry is reached at. A dial whose
    // entry hop resolves its camouflage from a published chain face is
    // entering the chain data plane and owes it the chain-face protocol. A
    // dial whose caller supplied the camouflage itself is the monitor mesh —
    // monitors publish no chain face, `MeshClient::dial_with_camo` patches
    // `hops[0].camouflage` for exactly that reason, and that path must stay a
    // plain handshake. Same distinction the materializer makes with
    // `HopAddressing`, read here from the fact rather than passed down.
    let chain_uses_onion = chain_uses_onion_framing(chain, peer_table);

    if chain_uses_onion {
        let destination = NextHop::Terminal;

        let onion_chain = build_onion_chain_for_transparent_entry(chain, "");

        debug!(
            chain_id = %chain.chain_id,
            hops = chain.hops.len(),
            "establishing onion tunnel"
        );

        // Pre-resolve all hop pubkeys from peer_table so the onion builder
        // never sees `public_key = None` (it has no peer_table access).
        // Note: for synthetic chains (transparent-relay 2-hop), hop[0].public_key
        // was patched from the entry hop above, so resolve_chain_pubkeys may find
        // it is already Some(entry_pubkey) — that is intentional and correct.
        let mut resolved_chain = resolve_chain_pubkeys(&onion_chain, peer_table).map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                hops = chain.hops.len(),
                error = %e,
                "establish_raw_tunnel: resolve_chain_pubkeys failed"
            );
            e
        })?;

        // Camouflage follows the persona: the entry hop is dialed in
        // whatever ITS OWN target published as its chain face, not
        // something invented from the chain plan. See
        // `apply_entry_face_camouflage`'s doc for the refuse-vs-raw split.
        apply_entry_face_camouflage(&mut resolved_chain, peer_table).map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                error = %e,
                "establish_raw_tunnel: apply_entry_face_camouflage failed"
            );
            e
        })?;

        // Build per-hop suite preferences from peer_table.
        let peer_suite_prefs: Vec<mirage_protocol::onion::builder::PeerSuitePreference> = onion_chain
            .hops
            .iter()
            .filter_map(|h| h.node_id.as_deref().or(h.display_name.as_deref()))
            .filter_map(|nid| peer_table.lookup_by_str(nid).map(|e| (nid, e)))
            .map(|(nid, e)| mirage_protocol::onion::builder::PeerSuitePreference {
                node_id: nid.to_owned(),
                aead_suite_preference: e.aead_suite_preference.clone(),
            })
            .collect();

        // The outer bound has to exceed what the INNER one can legitimately
        // spend, or it fires first and throws away the only message that says
        // why.
        //
        // It was a flat 15 s while `OnionFsTunnel::connect` gives each hop 15 s
        // to answer its `FsCreated`. So a telescopic build that lost one hop
        // was cut off at exactly the moment that hop's own timeout produced its
        // diagnosis — the dialer reported "onion-fs connect timed out", which
        // names neither the hop nor the cause, and the useful error was built
        // and discarded. Measured: a deliberately mis-addressed one-hop dial
        // reported the generic outer message while the specific one, carrying
        // the hop id and the digest to join against that hop's own log, never
        // surfaced.
        //
        // Per hop, plus a margin for the TCP connects and camouflage
        // handshakes between them. A chain that really is slow still fails;
        // it just fails saying which hop and why.
        const ONION_PER_HOP_TIMEOUT: Duration = Duration::from_secs(15);
        const ONION_TIMEOUT_MARGIN: Duration = Duration::from_secs(10);
        let onion_timeout: Duration =
            ONION_PER_HOP_TIMEOUT * (resolved_chain.hops.len().max(1) as u32)
                + ONION_TIMEOUT_MARGIN;
        // `match` (not `if ==`) so a future `HandshakeStrategy` variant fails
        // to compile here instead of silently falling through to a dial that
        // doesn't exist — Telescopic/FS is the only onion handshake left.
        let tunnel: Box<dyn mirage_protocol::traits::Tunnel> = match chain.handshake {
            mirage_core::config::HandshakeStrategy::Telescopic => {
                // Pre-minted credential wins; fall back to client-side EpochHmac mint.
                let cred = pre_minted.cloned()
                    .or_else(|| credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms())));
                let t = tokio::time::timeout(
                    onion_timeout,
                    OnionFsTunnel::connect(
                        &resolved_chain,
                        destination,
                        &[],
                        mesh_id,
                        vec![chain.aead_suite],
                        &peer_suite_prefs,
                        peer_table.generation,
                        cred,
                    ),
                )
                .await
                .map_err(|_| {
                    let e = MirageError::NodeUnreachable(format!(
                        "chain {}: onion-fs connect timed out after {}s",
                        chain.chain_id,
                        onion_timeout.as_secs()
                    ));
                    warn!(chain_id = %chain.chain_id, timeout_secs = onion_timeout.as_secs(), "establish_raw_tunnel: OnionFsTunnel::connect timed out");
                    e
                })
                .and_then(|r| r.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, error = %e, "establish_raw_tunnel: OnionFsTunnel::connect failed");
                    e
                }))?;
                Box::new(t)
            }
        };
        return Ok(tunnel);
    }

    // The raw-relay path that stood here is gone with `RelayMode::Transparent`
    // and `RelayMode::CryptoVerify` (2026-09-02). It dialled an entry hop that
    // ran no Mirage handshake at all — the node stripped the camouflage,
    // optionally peeled one static-keyed ByteCipher skin, and piped the rest.
    // That worked only because the bind port told the node which listener the
    // bytes belonged to, and the port is what this cutover removes. A hop that
    // never terminates cannot read a selector, so it cannot be addressed once
    // the port is gone. `OnionPeel` peels per hop and carries the selector
    // inside its own layer. See `mirage_core::mirage::wire::relay_mode`.
    //
    // The byte-cipher skin did NOT go with it: it rides the onion ENTRY hop as
    // a DPI skin on the client→entry link, written by `OnionFsTunnel` before
    // the envelope. That path is untouched.

    // ── Single-hop direct path (Mirage ECDH handshake) ───────────────────────
    let entry = &chain.hops[0];
    let pubkey_hex = resolve_hop_pubkey(&chain.chain_id, 0, entry, peer_table)?;
    let handshake_pubkey = decode_hex_pubkey(&pubkey_hex)
    .map_err(|e| {
        MirageError::Config(format!(
            "chain {}: entry hop public_key invalid: {e}",
            chain.chain_id
        ))
    })?;
    let handshake_sni = entry.sni.as_deref().unwrap_or("").to_owned();
    let dial_addr = entry_hop_addr(chain)?;
    // Camouflage follows the persona — see `resolve_entry_face_camouflage`'s
    // doc for the refuse-vs-raw split this call makes explicit.
    let entry_camouflage = resolve_entry_face_camouflage(&chain.chain_id, entry, peer_table)?;

    debug!(
        chain_id = %chain.chain_id,
        dial_addr = %dial_addr,
        "establishing single-hop raw tunnel"
    );

    // Mint a fresh credential for this single-hop dial (unlinkability: fresh nonce each call).
    let cred = credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms()));

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    let (_proto_id, tunnel) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        chain_protocols.connect_with_credential(dial_addr, &handshake_pubkey, &handshake_sni, entry_camouflage, cred),
    )
    .await
    .map_err(|_| {
        MirageError::NodeUnreachable(format!(
            "chain {}: connect to {} timed out after {}s",
            chain.chain_id,
            entry.addr,
            CONNECT_TIMEOUT.as_secs()
        ))
    })??;

    debug!(chain_id = %chain.chain_id, "raw tunnel handshake done");

    // Wrap with traffic shaper if configured.
    let tunnel: Box<dyn Tunnel> = match chain.shaping {
        ShapingPreset::None => tunnel,
        ShapingPreset::WebBrowsing => {
            debug!(chain_id = %chain.chain_id, "applying WebBrowsing traffic shaping");
            Box::new(ShapedTunnel::new(tunnel, patterns::web_browsing()))
        }
        ShapingPreset::CloudApi => {
            debug!(chain_id = %chain.chain_id, "applying CloudApi traffic shaping");
            Box::new(ShapedTunnel::new(tunnel, patterns::yandex_cloud_api()))
        }
        ShapingPreset::Streaming => {
            debug!(chain_id = %chain.chain_id, "applying Streaming traffic shaping");
            Box::new(ShapedTunnel::new(tunnel, patterns::video_streaming()))
        }
    };

    // Wrap with cover-traffic injector if enabled.
    let tunnel: Box<dyn Tunnel> = if chain.cover_traffic.enabled {
        debug!(
            chain_id = %chain.chain_id,
            idle_threshold_ms = chain.cover_traffic.idle_threshold_ms,
            "applying cover traffic injection"
        );
        Box::new(CoverTunnel::new(tunnel, chain.cover_traffic.clone()))
    } else {
        tunnel
    };

    Ok(tunnel)
}


/// Magic prefix sent as `initial_user_data` to signal the onion exit that this
/// is a multiplexed session.  Must match `MUX_MAGIC` in `mirage-node`'s
/// `exit/onion.rs` exactly.
pub const ONION_MUX_MAGIC: &[u8] = b"MUX\0";

/// Establish a tunnel for use as a mux session transport.
///
/// For onion chains (`chain.hops` non-empty) the onion envelope is built with
/// `ONION_MUX_MAGIC` as `initial_user_data` so the exit node upgrades to a
/// `SessionHandle::server` instead of the single-envelope TCP proxy.
///
/// For direct chains (no hops) this is identical to [`establish_raw_tunnel`].
pub async fn establish_mux_tunnel(
    chain_protocols: &ProtocolChain,
    chain: &ChainConfig,
    peer_table: &PeerTable,
    mesh_id: &[u8],
    pre_minted: Option<&ClientCredential>,
    credential_params: Option<&CredentialParams>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    // Sprint 3 fix: reply=raw chains must never use the mux path.
    //
    // reply=raw means the exit writes unframed bytes to the client (no per-hop
    // AEAD reply wrapping). The mux exit (`run_mux_server_session_wrapped_v7`)
    // always wraps its replies in `[4B BE len][AEAD(chunk)]` via
    // `WrapForwardingStreamV7`. A client with `raw_mode=true` skips AEAD unwrap
    // and hands those AEAD-framed bytes directly to the mux session parser,
    // which sees garbage framing → immediate EOF.
    //
    // reply=raw chains (transparent-relay 2-hop and single-hop direct) use
    // TunnelPool only. reply=onion chains (full onion multi-hop) use MuxPool.
    use mirage_core::config::ReplyMode;
    if chain.reply == ReplyMode::Raw {
        return establish_raw_tunnel(chain_protocols, chain, peer_table, mesh_id, pre_minted, credential_params).await;
    }

    // Phase 9.7: single-hop chain (post-Phase-8 direct exit shape:
    // hops=[Exit]) takes the raw path, same as the pre-Phase-8
    // hops=[] direct exit. Only multi-hop (>1 hop) chains run the
    // onion+mux protocol. Without this guard the single-hop case
    // tried to onion-wrap a direct exit, which the server's
    // `handle_exit` auto-detector saw as a mux session (first
    // byte 0x00 from the length prefix), and the resulting
    // `mux_compat: tunnel closed` showed up as HTTP/0.9.
    //
    // Also gate by RelayMode: onion+mux requires OnionPeel hops; multi-hop
    // byte_cipher / transparent chains stay on the raw path.
    let chain_uses_onion = chain.hops.iter().any(|h| {
        matches!(h.relay_mode, mirage_core::mirage::wire::RelayMode::OnionPeel)
    }) && chain.hops.len() > 1;

    if chain_uses_onion {
        let destination = NextHop::Terminal;

        let onion_chain_mux = build_onion_chain_for_transparent_entry(chain, " (mux)");

        debug!(
            chain_id = %chain.chain_id,
            hops = chain.hops.len(),
            "establishing onion mux tunnel (MUX magic)"
        );

        // Pre-resolve all hop pubkeys from peer_table before handing the chain
        // to the onion builder. The builder calls `decode_pubkey` directly on
        // `hop.public_key` with no peer_table access; a `None` key produces
        // "hop public_key must be 64 hex chars, got 0".
        let mut resolved_chain = resolve_chain_pubkeys(&onion_chain_mux, peer_table).map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                hops = chain.hops.len(),
                error = %e,
                "establish_mux_tunnel: resolve_chain_pubkeys failed"
            );
            e
        })?;

        // Camouflage follows the persona — see `establish_raw_tunnel`'s
        // identical step and `apply_entry_face_camouflage`'s doc.
        apply_entry_face_camouflage(&mut resolved_chain, peer_table).map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                error = %e,
                "establish_mux_tunnel: apply_entry_face_camouflage failed"
            );
            e
        })?;

        // Build per-hop suite preferences from peer_table.
        let peer_suite_prefs_mux: Vec<mirage_protocol::onion::builder::PeerSuitePreference> =
            onion_chain_mux
                .hops
                .iter()
                .filter_map(|h| h.node_id.as_deref().or(h.display_name.as_deref()))
                .filter_map(|nid| peer_table.lookup_by_str(nid).map(|e| (nid, e)))
                .map(|(nid, e)| mirage_protocol::onion::builder::PeerSuitePreference {
                    node_id: nid.to_owned(),
                    aead_suite_preference: e.aead_suite_preference.clone(),
                })
                .collect();

        // Per hop plus a margin — the same reasoning as the raw path above: a
        // flat outer bound equal to the per-hop one fires first and discards
        // the message that names the hop and the cause.
        const ONION_PER_HOP_TIMEOUT: Duration = Duration::from_secs(15);
        const ONION_TIMEOUT_MARGIN: Duration = Duration::from_secs(10);
        let onion_timeout: Duration =
            ONION_PER_HOP_TIMEOUT * (resolved_chain.hops.len().max(1) as u32)
                + ONION_TIMEOUT_MARGIN;
        // reply=onion: exit wraps each mux reply chunk in wrap_reply_layer;
        // intermediate hops add their own layers; tunnel recv unwraps N layers.
        // raw_mode stays false (default).
        //
        // `match` (not `if ==`) so a future `HandshakeStrategy` variant fails
        // to compile here instead of silently falling through to a dial that
        // doesn't exist — Telescopic/FS is the only onion handshake left.
        let tunnel: Box<dyn mirage_protocol::traits::Tunnel> = match chain.handshake {
            mirage_core::config::HandshakeStrategy::Telescopic => {
                // Pre-minted credential wins; fall back to client-side EpochHmac mint.
                let cred = pre_minted.cloned()
                    .or_else(|| credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms())));
                let t = tokio::time::timeout(
                    onion_timeout,
                    OnionFsTunnel::connect(
                        &resolved_chain,
                        destination,
                        ONION_MUX_MAGIC,
                        mesh_id,
                        vec![chain.aead_suite],
                        &peer_suite_prefs_mux,
                        peer_table.generation,
                        cred,
                    ),
                )
                .await
                .map_err(|_| {
                    let e = MirageError::NodeUnreachable(format!(
                        "chain {}: onion-fs mux connect timed out after {}s",
                        chain.chain_id,
                        onion_timeout.as_secs()
                    ));
                    warn!(chain_id = %chain.chain_id, timeout_secs = onion_timeout.as_secs(), "establish_mux_tunnel: OnionFsTunnel::connect timed out");
                    e
                })
                .and_then(|r| r.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, error = %e, "establish_mux_tunnel: OnionFsTunnel::connect failed");
                    e
                }))?;
                Box::new(t)
            }
        };
        return Ok(tunnel);
    }

    establish_raw_tunnel(chain_protocols, chain, peer_table, mesh_id, pre_minted, credential_params).await
}

/// Decode a 64-character hex string into a 32-byte X25519 public key.
pub(crate) fn decode_hex_pubkey(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

/// Establish a UDP chain tunnel by dialing `hops[0]` via
/// `mirage_protocol::driver::run_client_udp`.
///
/// This is the STREAM-over-UDP adapter path: it runs the ordinary byte-stream
/// V9 handshake (`run_client_udp_v9`) over a UDP camouflage layer, the same
/// shape `establish_raw_tunnel`/`establish_mux_tunnel` use to onion+mux-wrap
/// TCP chains. **Single-hop only, still — correcting the reason, not the
/// rule.** U5 (`docs/mirage/plans/u5-datagram-telescopic-design-2026-09-09.md`)
/// proved a forward-secret multi-hop UDP path exists now
/// (`OnionFsUdpTunnel`, reached through `establish_udp_datagram_tunnel`), so
/// "multi-hop UDP has no onion model" is no longer true in general. It stays
/// true FOR THIS FUNCTION: the FS telescopic exchange is one raw frame per
/// datagram with no `[4B len]` wrapper and no mux marker byte (design
/// decision (A) — see the doc's opening section), and this function's own
/// model — a byte stream, wrapped in `ONION_MUX_MAGIC` for mux sessions —
/// cannot carry it. A multi-hop chain therefore still has no home here; it
/// has one elsewhere. `hops[0]` carries the dial address, public key, and
/// optionally an SNI.  The `TransportCamouflage` variant comes from
/// `hops[0].camouflage`; when `None` the camouflage falls back to `RawUdp`.
///
/// `udp_id` selects the wire (currently only `MirageUdp`) — kept as a
/// parameter so the call-site `match` in `establish_raw_tunnel` compiles.
async fn establish_udp_chain_tunnel(
    chain: &ChainConfig,
    _udp_id: UdpProtocolId,
    peer_table: &PeerTable,
    mesh_id: &[u8],
    pre_minted: Option<&ClientCredential>,
    credential_params: Option<&CredentialParams>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    // Multi-hop UDP onion path: any chain whose hops use OnionPeel relay_mode.
    let chain_uses_onion = chain.hops.iter().any(|h| {
        matches!(h.relay_mode, mirage_core::mirage::wire::RelayMode::OnionPeel)
    }) && chain.hops.len() > 1;

    if chain_uses_onion {
        // Corrected reason (U5 landed): a forward-secret multi-hop UDP path
        // now exists — `OnionFsUdpTunnel::connect`, dispatched from
        // `establish_udp_datagram_tunnel`, proven at 1 and 2 hops
        // (`onion_tunnel_fs_udp.rs`'s own loopback tests) and end-to-end on
        // the node side (`mirage2node`'s `try_handle_fs_chain` +
        // `udp_fs_peel`/`udp_fs` exit test). It is NOT reachable from this
        // function and must not become reachable here: FS-chain frames ride
        // raw, one per datagram, with no length prefix and no
        // `ONION_MUX_MAGIC` marker — this function's byte-stream + mux model
        // has no way to carry that shape, and bolting one on would duplicate
        // `OnionFsUdpTunnel` rather than reuse it. Refuse by name, naming
        // where the real path lives, rather than silently widening this one.
        return Err(MirageError::Config(format!(
            "chain {}: multi-hop UDP onion is not reachable through the stream-adapter \
             dial (establish_udp_chain_tunnel) — it rides raw FS frames with no \
             [4B len]/mux framing this path can carry. Dial through \
             establish_udp_datagram_tunnel (OnionFsUdpTunnel) instead",
            chain.chain_id
        )));
    }

    // Single-hop UDP path (no onion).
    let entry = chain.hops.first().ok_or_else(|| {
        MirageError::Config(format!(
            "chain {}: UDP chain requires at least one hop",
            chain.chain_id
        ))
    })?;

    if chain.hops.len() > 1 {
        // A multi-hop UDP chain with no OnionPeel hop at all — not the FS
        // path above (that requires OnionPeel) and not a stream chain this
        // function knows how to onion-wrap either. Still refused; the
        // message no longer implies "add OnionPeel and this function will
        // carry it" — it will not, see the doc comment above.
        return Err(MirageError::Config(format!(
            "chain {}: multi-hop UDP has no path through establish_udp_chain_tunnel \
             regardless of relay_mode (hops.len() = {}) — OnionPeel multi-hop UDP is \
             carried by establish_udp_datagram_tunnel instead, never by this function",
            chain.chain_id,
            chain.hops.len()
        )));
    }

    let dial_addr = entry_hop_addr(chain)?;

    let pubkey_hex = resolve_hop_pubkey(&chain.chain_id, 0, entry, peer_table)?;
    let server_pubkey = decode_hex_pubkey(&pubkey_hex)
    .map_err(|e| {
        MirageError::Config(format!(
            "chain {}: entry hop public_key invalid: {e}",
            chain.chain_id
        ))
    })?;
    let sni = entry.sni.clone().unwrap_or_else(|| "www.example.com".to_owned());

    // Camouflage is specified per-hop by the monitor via `HopConfig.camouflage`.
    // Fall back to RawUdp if unset.
    let camouflage = entry.camouflage.clone().unwrap_or(TransportCamouflage::RawUdp { bind_addr: dial_addr });

    let endpoint = MirageEndpointConfig {
        transport: TransportKind::Udp,
        auth: AuthMode::Blake3,
        camouflage,
        byte_cipher: None,
        byte_cipher_mode: entry.byte_cipher.clone(),
    };

    debug!(
        chain_id = %chain.chain_id,
        addr = %dial_addr,
        "establishing UDP chain tunnel"
    );

    // Generate a per-dial ephemeral client static key for V9 (Option A: unlinkable).
    // Never stored — used only to compute client_proof in the handshake.
    let mut client_static_priv = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut client_static_priv);
    }
    // Pre-minted credential wins; fall back to client-side EpochHmac mint.
    let cred = pre_minted.cloned()
        .or_else(|| credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms())));

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    let tunnel = tokio::time::timeout(
        CONNECT_TIMEOUT,
        run_client_udp_v9(&endpoint, dial_addr, &server_pubkey, &client_static_priv, &sni, mesh_id, cred.as_ref()),
    )
    .await
    .map_err(|_| {
        MirageError::NodeUnreachable(format!(
            "chain {}: UDP connect to {} timed out after {}s",
            chain.chain_id,
            dial_addr,
            CONNECT_TIMEOUT.as_secs()
        ))
    })??;

    debug!(chain_id = %chain.chain_id, "UDP chain tunnel handshake done");
    Ok(tunnel)
}

/// Dial `dial_addr` and complete the datagram-native V9 handshake directly
/// over a bound [`UdpPeerSocket`], returning a live, concrete
/// [`MirageCoreUdpTunnel`].
///
/// This is the datagram-shaped counterpart of [`establish_udp_chain_tunnel`]
/// above, which stays exactly as it is and keeps serving every current
/// client: that function reaches its endpoint through a stream adapter
/// (`UdpCamouflageLayer`) and runs the ordinary byte-stream V9 handshake
/// (`run_client_udp_v9`) over it. This function shares none of that — it
/// binds a socket, hands it straight to
/// [`run_client_handshake_v9_datagram_with_credential`],
/// and builds the tunnel from the result. That handshake function owns its
/// own bounded `ClientHello` retransmit and the adoption of the server's
/// reply port (`UdpPeerSocket::recv_handshake_from_host`, called inside it);
/// nothing is added here on top of either — see its own module doc for the
/// exact retransmit bound.
///
/// Returns the concrete `MirageCoreUdpTunnel`, never `Box<dyn Tunnel>`. This
/// is deliberate, not an oversight: on the node side the framed exit takes
/// `Box<dyn Tunnel>` and the datagram exit takes the concrete type, so a
/// datagram tunnel cannot structurally reach the framed path. Boxing at this
/// door would erase that guarantee for every caller downstream — see
/// `mirage-node`'s `exit/direct.rs` doc ("Two exits, two types").
///
/// # What the caller gets, and does not get
///
/// After this returns, every `send` / `recv_datagram` on the tunnel is one
/// whole UDP datagram, exactly as the peer sent it — loss, reordering and
/// duplication all pass through unchanged past the handshake, because
/// `MirageCoreUdpTunnel` itself adds none of those guarantees (see its own
/// module doc). There is no retransmission, no ordering guarantee and no
/// reassembly of any kind once this function returns. A caller that needs
/// those belongs on the stream-adapter path (`establish_udp_chain_tunnel`)
/// instead, not here.
///
/// `AuthMode::Hmac` (the `mirage_protocol` enum, not `mirage_core`'s
/// config-level one already imported under that name in this file) is
/// hardcoded rather than a parameter: it is the one `MirageCoreUdpTunnel`
/// mode whose sliding HMAC receive window tolerates the reordering and
/// duplication named above without desyncing (see `core::udp_tunnel`'s own
/// doc) — the only mode this function can correctly pair with a transport
/// that behaves this way, and the mode the wire's server-side counterpart
/// uses for the identical reason.
///
/// No target string, no first-datagram convention of any kind is sent here
/// — this function's job ends at a live, empty tunnel. What the first
/// datagram means, if anything, is entirely the caller's decision.
///
/// `credential` is carried through unchanged to
/// `run_client_handshake_v9_datagram_with_credential` — `Some(cred)` appends
/// `cred.token` (scheme `cred.scheme`) to the `ClientHello` in the same
/// datagram; `None` maps to that entry point's own no-credential case
/// (`cred_scheme = 0x00`, empty token), which is byte-identical to what this
/// function sent before credential carriage existed. This function does not
/// mint: it has no `CredentialParams` to mint from — minting stays with
/// whichever caller eventually supplies a credential here.
pub async fn establish_native_udp_tunnel(
    dial_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    credential: Option<&ClientCredential>,
) -> Result<MirageCoreUdpTunnel, MirageError> {
    establish_native_udp_tunnel_addressed(
        dial_addr,
        server_static_pub,
        client_static_priv,
        mesh_id,
        suite_prefs,
        credential,
        None,
    )
    .await
}

/// The same dial, naming which chain hop the datagram session is for.
///
/// With `chain_address = None` this is byte-for-byte
/// [`establish_native_udp_tunnel`]. With `Some(_)` the hop's selector rides
/// on the `ClientHello` and the node resolves the listener from it instead
/// of from the mesh id — see
/// [`mirage_protocol::core::dgram_chain_addr`] for the wire shape and why it
/// rides the handshake rather than the tunnel's data phase.
///
/// Sending an address to a node that has no chain listener under that
/// selector is a dial that gets NOTHING back, by design, and times out. So
/// the caller decides whether to send one; see
/// [`entry_chain_address`] for the rule.
#[allow(clippy::too_many_arguments)]
pub async fn establish_native_udp_tunnel_addressed(
    dial_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    credential: Option<&ClientCredential>,
    chain_address: Option<&DatagramChainAddress>,
) -> Result<MirageCoreUdpTunnel, MirageError> {
    let mut socket = UdpPeerSocket::bind_client(dial_addr).await?;

    let (cred_scheme, cred_token): (u8, &[u8]) = credential
        .map(|c| (c.scheme, c.token.as_slice()))
        .unwrap_or((0x00, &[]));

    let result = mirage_protocol::core::udp_handshake::run_client_handshake_v9_datagram_with_chain(
        &mut socket,
        server_static_pub,
        client_static_priv,
        mesh_id,
        suite_prefs,
        chain_address,
        cred_scheme,
        cred_token,
    )
    .await?;

    let info = TransportInfo::udp_raw(socket.remote_addr());
    Ok(MirageCoreUdpTunnel::new(
        socket,
        &result.session_keys,
        true,
        info,
        mirage_protocol::auth::AuthMode::Hmac,
    ))
}

/// Resolve the dial address for a single-hop datagram-native UDP chain's
/// entry from its published DATAGRAM chain face (`chain_face_udp`).
///
/// Same `node_id` / `display_name` lookup rule as
/// [`resolve_entry_face_camouflage`], but reads the peer's *datagram* face
/// rather than its stream one — the two are different ports on the same
/// node (see [`mirage_core::mirage::mesh::ChainFace`]'s own doc on why a
/// node publishes both) and must never be confused. The found face's
/// camouflage must be [`TransportCamouflage::RawUdp`] — the only shape
/// [`establish_native_udp_tunnel`] can dial, since it never strips a
/// camouflage of any kind (see that function's own doc on why
/// `AuthMode::Hmac` is hardcoded there). Anything else is refused by name,
/// naming the chain, the node, and what was actually found.
///
/// The face's PORT is authoritative for the dial address — `hops[0].addr`'s
/// host is kept, its port is replaced by `chain_face_udp.port` — mirroring
/// how the monitor already addresses a `Transport::Udp` chain's hops (see
/// this function's own caller for the reference).
///
/// # The one case that never consults the table
///
/// When `hop.camouflage` is already `Some(TransportCamouflage::RawUdp {
/// .. })` — set explicitly by the caller — the hop is dialed exactly as
/// given (`hops[0].addr` unchanged, port included) and the peer_table is
/// never consulted, even when the node is entirely absent from it. This is
/// the shape tests and hand-written configs use; every other case in this
/// function refuses rather than guesses. An explicit camouflage of any
/// OTHER shape is still refused — this dial path only ever pairs with
/// RawUdp.
fn resolve_entry_face_udp(
    chain: &ChainConfig,
    hop: &mirage_core::config::HopConfig,
    peer_table: &PeerTable,
) -> Result<SocketAddr, MirageError> {
    let hop_addr = entry_hop_addr(chain)?;

    if let Some(cam) = &hop.camouflage {
        return match cam {
            TransportCamouflage::RawUdp { .. } => Ok(hop_addr),
            other => Err(MirageError::Config(format!(
                "chain {}: entry hop has explicit camouflage {other:?}, but \
                 establish_udp_datagram_tunnel only pairs with RawUdp",
                chain.chain_id
            ))),
        };
    }

    let node_id = hop
        .node_id
        .as_deref()
        .or(hop.display_name.as_deref())
        .ok_or_else(|| {
            MirageError::Config(format!(
                "chain {}: entry hop has neither an explicit RawUdp camouflage \
                 nor a node_id — cannot resolve its datagram chain face",
                chain.chain_id
            ))
        })?;
    let peer = peer_table.lookup_by_str(node_id).ok_or_else(|| {
        MirageError::Config(format!(
            "chain {}: entry hop '{node_id}' not in peer_table — cannot \
             resolve its datagram chain face",
            chain.chain_id
        ))
    })?;
    let face = peer.chain_face_udp.as_ref().ok_or_else(|| {
        MirageError::Config(format!(
            "chain {}: entry hop '{node_id}' has published no datagram chain \
             face (chain_face_udp) — refusing to dial",
            chain.chain_id
        ))
    })?;
    if !matches!(face.camouflage, TransportCamouflage::RawUdp { .. }) {
        return Err(MirageError::Config(format!(
            "chain {}: entry hop '{node_id}' published a datagram chain face \
             with camouflage {:?}, but establish_udp_datagram_tunnel only \
             pairs with RawUdp",
            chain.chain_id, face.camouflage
        )));
    }
    Ok(SocketAddr::new(hop_addr.ip(), face.port))
}

/// The chain address a datagram dial should put on its `ClientHello`, if any.
///
/// # Why this is a decision and not "always send it"
///
/// A node resolves a chain-addressed datagram through its chain routing
/// table and answers a miss with silence. A plain direct UDP exit is
/// registered with no `chain_role` at all, so addressing one would resolve
/// to nothing and turn a working dial into a timeout. The client therefore
/// sends a block only when it actually holds something finer than the mesh
/// to say.
///
/// That signal is the minted selector token. The monitor mints one per hop
/// and puts it on both halves — the listener spec the node binds under and
/// the hop config the client dials with — so a hop the client can NAME is
/// exactly a hop the node registered under that name. A chain without one is
/// either a direct exit or a chain from a monitor that predates minting, and
/// in both cases the mesh-id path is what the node still answers on.
///
/// # Depth
///
/// `chain_position` is the entry's, always 0 here, and `chain_length` is the
/// chain's real depth rather than a constant: the block is built the same
/// way at any depth, and what still refuses depth > 1 is the caller, because
/// no relay leg exists yet to forward past the entry. When that lands, this
/// function needs no change — only the loop that calls it once per hop.
fn entry_chain_address(
    chain: &ChainConfig,
    entry: &mirage_core::config::HopConfig,
) -> Result<Option<DatagramChainAddress>, MirageError> {
    let token = crate::onion_tunnel_fs::hop_selector_token(
        &chain.chain_id,
        0,
        entry.selector_token_hex.as_deref(),
    )?;
    if token.is_empty() {
        return Ok(None);
    }
    Ok(Some(DatagramChainAddress {
        chain_id: chain.chain_id.as_bytes().to_vec(),
        chain_position: 0,
        chain_length: u8::try_from(chain.hops.len()).map_err(|_| {
            MirageError::Config(format!(
                "chain {}: {} hops does not fit the one-byte chain_length a datagram chain \
                 address carries",
                chain.chain_id,
                chain.hops.len()
            ))
        })?,
        selector_token: token,
    }))
}

/// The datagram-native chain tunnel returned by
/// [`establish_udp_datagram_tunnel`]: a direct single-hop
/// [`MirageCoreUdpTunnel`] for the pre-U5 path, or a multi-hop
/// [`OnionFsUdpTunnel`] telescopic FS circuit for U5 Slice 7's addition.
///
/// # Why an enum, not `Box<dyn Tunnel>`
///
/// `Box<dyn Tunnel>` was tried first here and rejected. The two branches
/// build structurally different concrete types, so returning `Box<dyn
/// Tunnel>` would still let every caller drive `send`/`recv`/`close`/
/// `transport_info` — but `mirage-client-core`'s own
/// `socks5.rs::run_datagram_udp_session` needs `into_split()` on the dialed
/// tunnel: `send` and `recv_datagram` both take `&mut self`, and that
/// function has to write from its main loop while a spawned task reads
/// concurrently — a split, deliberately NOT a `Mutex` around the whole
/// tunnel (see its own doc for why). `into_split` consumes `self` by value
/// and returns two DIFFERENT concrete types depending on which variant it
/// started from; a `dyn Tunnel` vtable has no slot for a self-consuming,
/// type-changing method, so boxing here would have compiled cleanly while
/// silently removing the one capability the caller actually needed. This
/// enum keeps both concrete variants named at this one dispatch point
/// instead — the same axis rule `mirage2web/CLAUDE.md` states for AEAD/
/// wire/camouflage: an enum whose variants are visible at every call site,
/// never a trait object, when the set of shapes is small and known.
///
/// `Tunnel` is still implemented for this type below, so every EXISTING
/// caller that only needs `send`/`recv`/`close`/`transport_info` is
/// unaffected — only [`Self::into_split`] requires matching (or, more
/// commonly, calling it and using the returned [`DatagramTunnelSender`] /
/// [`DatagramTunnelReceiver`], which stay enums for the identical reason).
pub enum DatagramTunnel {
    /// Single-hop datagram-native tunnel, dialed straight against the
    /// entry's published `chain_face_udp` — [`establish_udp_datagram_tunnel`]'s
    /// path unchanged since before U5.
    Direct(MirageCoreUdpTunnel),
    /// Multi-hop telescopic FS circuit over UDP — [`OnionFsUdpTunnel::connect`],
    /// dispatched from [`establish_udp_datagram_tunnel`] for any chain with
    /// more than one hop (U5 Slice 7).
    Onion(OnionFsUdpTunnel),
}

#[async_trait]
impl Tunnel for DatagramTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        match self {
            DatagramTunnel::Direct(t) => t.send(data).await,
            DatagramTunnel::Onion(t) => t.send(data).await,
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        match self {
            DatagramTunnel::Direct(t) => t.recv(buf).await,
            DatagramTunnel::Onion(t) => t.recv(buf).await,
        }
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        match self {
            DatagramTunnel::Direct(t) => t.close().await,
            DatagramTunnel::Onion(t) => t.close().await,
        }
    }

    fn transport_info(&self) -> &TransportInfo {
        match self {
            DatagramTunnel::Direct(t) => t.transport_info(),
            DatagramTunnel::Onion(t) => t.transport_info(),
        }
    }
}

impl DatagramTunnel {
    /// Split into an owned send half and an owned receive half — the
    /// capability `Box<dyn Tunnel>` could not offer; see this type's own
    /// doc. Delegates to whichever concrete variant's own `into_split`:
    /// [`MirageCoreUdpTunnel::into_split`] for [`DatagramTunnel::Direct`],
    /// [`OnionFsUdpTunnel::into_split`] for [`DatagramTunnel::Onion`] — both
    /// documented there, including why each is sound with no lock.
    pub fn into_split(self) -> (DatagramTunnelSender, DatagramTunnelReceiver) {
        match self {
            DatagramTunnel::Direct(t) => {
                let (sender, receiver) = t.into_split();
                (DatagramTunnelSender::Direct(sender), DatagramTunnelReceiver::Direct(receiver))
            }
            DatagramTunnel::Onion(t) => {
                let (sender, receiver) = t.into_split();
                (DatagramTunnelSender::Onion(sender), DatagramTunnelReceiver::Onion(receiver))
            }
        }
    }

    /// Receive one whole datagram.
    ///
    /// Both variants carry this inherently — `MirageCoreUdpTunnel` and
    /// `OnionFsUdpTunnel` each expose it — and it is NOT the same thing as
    /// `Tunnel::recv`, which fills a caller's buffer and can therefore
    /// report a partial read. On this plane one datagram is one message, so
    /// a caller that wants the message wants this, and a caller forced to
    /// use `Tunnel::recv` instead would have to reconstruct a boundary the
    /// transport already preserved.
    ///
    /// Delegated here rather than left to the split halves because a caller
    /// that never splits — a probe doing one send and one receive, say —
    /// should not have to split just to read a datagram.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        match self {
            DatagramTunnel::Direct(t) => t.recv_datagram().await,
            DatagramTunnel::Onion(t) => t.recv_datagram().await,
        }
    }
}

/// Owned send half of a [`DatagramTunnel`], produced by
/// [`DatagramTunnel::into_split`]. Wraps whichever concrete sender half the
/// source tunnel's variant produced — see each field's own type for the
/// exact wire behaviour of `send`.
pub enum DatagramTunnelSender {
    Direct(UdpTunnelSender),
    Onion(OnionFsUdpTunnelSender),
}

impl DatagramTunnelSender {
    /// Send one whole UDP datagram — delegates to whichever concrete
    /// sender half this wraps.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        match self {
            DatagramTunnelSender::Direct(s) => s.send(data).await,
            DatagramTunnelSender::Onion(s) => s.send(data).await,
        }
    }
}

/// Owned receive half of a [`DatagramTunnel`], produced by
/// [`DatagramTunnel::into_split`]. Wraps whichever concrete receiver half
/// the source tunnel's variant produced — see each field's own type for the
/// exact framing of `recv_datagram`.
pub enum DatagramTunnelReceiver {
    Direct(UdpTunnelReceiver),
    Onion(OnionFsUdpTunnelReceiver),
}

impl DatagramTunnelReceiver {
    /// Receive one whole, decrypted, authenticated datagram — delegates to
    /// whichever concrete receiver half this wraps.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        match self {
            DatagramTunnelReceiver::Direct(r) => r.recv_datagram().await,
            DatagramTunnelReceiver::Onion(r) => r.recv_datagram().await,
        }
    }

    /// The tunnel's transport metadata — delegates to whichever concrete
    /// receiver half this wraps.
    pub fn transport_info(&self) -> &TransportInfo {
        match self {
            DatagramTunnelReceiver::Direct(r) => r.transport_info(),
            DatagramTunnelReceiver::Onion(r) => r.transport_info(),
        }
    }
}

/// Establish a datagram-native chain tunnel: single-hop via
/// [`establish_native_udp_tunnel`] (the direct V9 datagram handshake against
/// the entry's published `chain_face_udp`), multi-hop via
/// [`OnionFsUdpTunnel::connect`] (the telescopic FS circuit — one raw frame
/// per datagram, U5 design decision (A)).
///
/// # Why multi-hop is no longer refused here
///
/// It used to be, unconditionally — "UDP has no onion model" — because
/// nothing on either side of the wire understood a multi-hop FS datagram
/// session. That is no longer true, proven end to end by two independent
/// pieces of already-shipped code rather than by this function alone:
/// `mirage2web`'s own [`OnionFsUdpTunnel::connect`] completes real
/// per-hop ntor key agreement and a reply round-trip at 1 and 2 hops
/// against a hand-rolled peer (`onion_tunnel_fs_udp.rs`'s
/// `onion_fs_udp_tunnel_establishes_key_agreement_and_a_reply_round_trip_at_{one,two}_hops`),
/// and `mirage2node`'s relay/exit handlers (`udp_fs_peel.rs`, `exit/udp_fs.rs`,
/// `try_handle_fs_chain`) carry real bytes entry → relay → exit → a real UDP
/// target and back through both onion layers in an end-to-end test. Lifting
/// the refusal here is the last step named by the design doc's own ordered
/// slice list (U5, Slice 7) for exactly this reason: everything the dial
/// depends on was proven first.
///
/// # Routing rule — depth alone, and why that is not a shortcut here
///
/// This function follows [`chain_uses_onion_framing`]'s own precedent of
/// asking "is the hop onion-capable", not "is `hops.len() > 1`" — the same
/// question, checked against what the two axes that could answer it
/// currently carry. Both come back tautological:
///
/// - `h.relay_mode` — [`mirage_core::mirage::wire::RelayMode`] was cut to its
///   one surviving variant, `OnionPeel`, on 2026-09-02 (the module's own doc:
///   "There is one."; `Transparent`/`CryptoVerify` are gone because neither
///   terminated the tunnel, so neither could carry a selector once the
///   listener port that used to distinguish them was removed). A `HopConfig`
///   in this workspace cannot construct anything else — `.all(|h|
///   matches!(h.relay_mode, RelayMode::OnionPeel))` over a non-empty
///   `chain.hops` is true by construction, not by observation.
/// - `chain.handshake` — `HandshakeStrategy` has exactly one variant,
///   `Telescopic`, today (see its own doc: "the only onion-handshake path").
///
/// Writing either check anyway would add a branch this codebase's own
/// `no-guard-in-loop-scrutinee` discipline rejects: one that cannot evaluate
/// false against any value the type system lets a caller construct — that is
/// not caution, it is a branch nothing can ever take, which reads as a live
/// discriminator to the next person who edits this function and is not one.
/// `chain.hops.len() > 1` is therefore the whole rule, honestly: it is not
/// "depth as a shortcut for a check we skipped", it is depth because the
/// other two axes currently offer no second value to check against.
///
/// **This is a fact about today's types, not a permanent guarantee** — if
/// `RelayMode` or `HandshakeStrategy` ever regains a second variant, this is
/// the dispatch point that needs a real second check, and
/// [`OnionFsUdpTunnel::connect`] would need its own transparent-entry
/// handling first: unlike the stream plane's onion builder (guarded by
/// [`build_onion_chain_for_transparent_entry`], which strips a leading run
/// of passthrough hops before onion-wrapping), it walks every hop in
/// `chain.hops` as an onion hop unconditionally today, with no adapter to
/// skip one that is not.
///
/// # What does NOT change
///
/// The single-hop body below is untouched — same peer-table `chain_face_udp`
/// resolution ([`resolve_entry_face_udp`]), same pubkey resolution
/// ([`resolve_hop_pubkey`]), same per-dial ephemeral client key, same
/// credential rule, same 15s connect timeout, same wire calls. Multi-hop
/// dispatches to [`establish_udp_datagram_onion_tunnel`] before any of that
/// single-hop-specific code runs, so this change cannot alter a byte of the
/// live single-hop path.
///
/// Returns [`DatagramTunnel`] rather than the concrete `MirageCoreUdpTunnel`
/// this function returned before U5 Slice 7 — required because the two
/// branches construct structurally different types (`MirageCoreUdpTunnel`
/// vs `OnionFsUdpTunnel`) and there is no third type that is both. `Box<dyn
/// Tunnel>` was tried first here and reverted: `mirage-client-core`'s
/// `socks5.rs::run_datagram_udp_session` calls `into_split()` on the dialed
/// tunnel — a self-consuming, type-changing method a `dyn Tunnel` vtable
/// cannot express — to get an owned send half and an owned receive half so
/// it can write from its main loop while a spawned task reads concurrently,
/// with no `Mutex` around the whole tunnel. Boxing would have kept
/// `send`/`recv`/`close`/`transport_info` working and silently taken away
/// exactly the capability that caller chose on purpose. See
/// [`DatagramTunnel`]'s own doc for the full reasoning and its
/// [`DatagramTunnel::into_split`] for how both branches keep offering it.
pub async fn establish_udp_datagram_tunnel(
    chain: &ChainConfig,
    peer_table: &PeerTable,
    mesh_id: &[u8],
    pre_minted: Option<&ClientCredential>,
    credential_params: Option<&CredentialParams>,
) -> Result<DatagramTunnel, MirageError> {
    if chain.hops.len() > 1 {
        return establish_udp_datagram_onion_tunnel(
            chain,
            peer_table,
            mesh_id,
            pre_minted,
            credential_params,
        )
        .await;
    }
    let entry = chain.hops.first().ok_or_else(|| {
        MirageError::Config(format!(
            "chain {}: UDP datagram chain requires at least one hop",
            chain.chain_id
        ))
    })?;

    let dial_addr = resolve_entry_face_udp(chain, entry, peer_table)?;
    let chain_address = entry_chain_address(chain, entry)?;

    let pubkey_hex = resolve_hop_pubkey(&chain.chain_id, 0, entry, peer_table)?;
    let server_pubkey = decode_hex_pubkey(&pubkey_hex).map_err(|e| {
        MirageError::Config(format!(
            "chain {}: entry hop public_key invalid: {e}",
            chain.chain_id
        ))
    })?;

    debug!(
        chain_id = %chain.chain_id,
        addr = %dial_addr,
        "establishing datagram-native UDP tunnel"
    );

    // Generate a per-dial ephemeral client static key for V9 (Option A:
    // unlinkable). Never stored — used only to compute client_proof in the
    // handshake, exactly as `establish_udp_chain_tunnel` does.
    let mut client_static_priv = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut client_static_priv);
    }
    // Pre-minted credential wins; fall back to client-side EpochHmac mint —
    // the same rule as every other dial site in this module.
    let cred = pre_minted
        .cloned()
        .or_else(|| credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms())));

    const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm];
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

    let tunnel = tokio::time::timeout(
        CONNECT_TIMEOUT,
        establish_native_udp_tunnel_addressed(
            dial_addr,
            &server_pubkey,
            &client_static_priv,
            mesh_id,
            SUITE_PREFS,
            cred.as_ref(),
            chain_address.as_ref(),
        ),
    )
    .await
    .map_err(|_| {
        MirageError::NodeUnreachable(format!(
            "chain {}: UDP datagram connect to {} timed out after {}s",
            chain.chain_id,
            dial_addr,
            CONNECT_TIMEOUT.as_secs()
        ))
    })??;

    debug!(chain_id = %chain.chain_id, "datagram-native UDP tunnel handshake done");
    Ok(DatagramTunnel::Direct(tunnel))
}

/// Establish a multi-hop datagram-native chain tunnel via
/// [`OnionFsUdpTunnel::connect`] — the telescopic FS circuit, one raw frame
/// per datagram, no `[4B len]` wrapper (U5 design decision (A)).
///
/// Split out of [`establish_udp_datagram_tunnel`] so the single-hop body
/// above never executes a line of this function and vice versa — see that
/// function's own doc for why the split exists and what it guarantees.
///
/// # What this does NOT do that the single-hop branch does
///
/// It never calls [`resolve_entry_face_udp`] or [`entry_chain_address`]: a
/// multi-hop FS chain's entry address comes straight from `hops[0].addr`
/// (parsed or DNS-resolved inside [`OnionFsUdpTunnel::connect`] itself, via
/// `resolve_hop_addr_fs` — the same address source the stream-carriage FS
/// twin uses for its own hop 0), never from the peer table's published
/// `chain_face_udp`. The two are genuinely different sources for a reason:
/// `chain_face_udp` names a *listener*, resolved because the client has
/// nothing more specific to address a direct exit by; a chain plan already
/// names its own entry hop's dial address directly, and the FS onion frames
/// that follow carry their own authoritative `chain_id`/`chain_position`
/// (U5 design doc Q4) — there is nothing left for a chain-face lookup to
/// contribute on this path, only a second, redundant place for the address
/// to disagree with the one the frames already carry.
async fn establish_udp_datagram_onion_tunnel(
    chain: &ChainConfig,
    peer_table: &PeerTable,
    mesh_id: &[u8],
    pre_minted: Option<&ClientCredential>,
    credential_params: Option<&CredentialParams>,
) -> Result<DatagramTunnel, MirageError> {
    // No relay_mode/handshake gate here — see the caller's own doc, "Routing
    // rule" section: both axes are single-variant today, so `hops.len() > 1`
    // (already true, or this function would not have been called) is the
    // whole rule. `OnionFsUdpTunnel::connect` walks every hop in
    // `chain.hops` as an onion hop unconditionally; that is only safe
    // because every constructible `HopConfig` already IS one.

    // Pre-resolve every hop's pubkey from peer_table, exactly like
    // `establish_raw_tunnel` does before handing a chain to the stream FS
    // builder (`resolve_chain_pubkeys`'s own doc). `OnionFsUdpTunnel::connect`
    // reads `hop.public_key` directly with no peer_table access of its own.
    let resolved_chain = resolve_chain_pubkeys(chain, peer_table).map_err(|e| {
        warn!(
            chain_id = %chain.chain_id,
            hops = chain.hops.len(),
            error = %e,
            "establish_udp_datagram_onion_tunnel: resolve_chain_pubkeys failed"
        );
        e
    })?;

    // Per-hop suite preferences from peer_table — same construction as
    // `establish_mux_tunnel`'s `peer_suite_prefs_mux`.
    let peer_suite_prefs: Vec<mirage_protocol::onion::builder::PeerSuitePreference> =
        resolved_chain
            .hops
            .iter()
            .filter_map(|h| h.node_id.as_deref().or(h.display_name.as_deref()))
            .filter_map(|nid| peer_table.lookup_by_str(nid).map(|e| (nid, e)))
            .map(|(nid, e)| mirage_protocol::onion::builder::PeerSuitePreference {
                node_id: nid.to_owned(),
                aead_suite_preference: e.aead_suite_preference.clone(),
            })
            .collect();

    // Pre-minted credential wins; fall back to client-side EpochHmac mint —
    // the same rule as every other dial site in this module.
    let cred = pre_minted
        .cloned()
        .or_else(|| credential_params.and_then(|p| mint_epoch_hmac_credential(p, now_ms())));

    // Outer bound sized off OnionFsUdpTunnel's OWN per-hop retry bound
    // (`FS_STEP_RETRANSMIT_TIMEOUT * (FS_STEP_MAX_RETRANSMITS + 1)`), not a
    // fresh guess — it already fully bounds each hop's worst case, so this
    // is a margin against socket/DNS overhead outside that loop, not a
    // second independent timeout racing the first. Multiplied by hop count,
    // same shape as `establish_mux_tunnel`'s `onion_timeout`: scales with
    // `N`, never names `N` as a ceiling.
    // The steps are not equal, so the outer bound is their SUM, not the
    // deepest one multiplied by N.
    //
    // Step `i` waits `FS_STEP_RETRANSMIT_TIMEOUT * (i + 1)` per attempt —
    // the answer crosses `i` relays on its way back — so building a chain of
    // N hops costs the base times `1 + 2 + ... + N`, which is
    // `N * (N + 1) / 2`, not `N`. Sizing this as `per_hop_bound * N` counted
    // every step as if it were the shallowest and came out roughly three
    // times short at four hops.
    //
    // Measured on a lab mesh 2026-09-09: 1- and 2-hop dials completed in 633ms
    // and 834ms, while 3- and 4-hop dials were cut off by an outer bound
    // that expired while the client was still inside its own legitimate
    // per-step budget — the same mistake as the per-step bound itself, one
    // level up.
    const OUTER_MARGIN_PER_HOP: Duration = Duration::from_secs(5);
    let hops = resolved_chain.hops.len().max(1) as u32;
    let step_attempts = crate::onion_tunnel_fs_udp::FS_STEP_MAX_RETRANSMITS + 1;
    let triangular = hops * (hops + 1) / 2;
    let onion_timeout = crate::onion_tunnel_fs_udp::FS_STEP_RETRANSMIT_TIMEOUT
        * step_attempts
        * triangular
        + OUTER_MARGIN_PER_HOP * hops;

    debug!(
        chain_id = %chain.chain_id,
        hops = resolved_chain.hops.len(),
        "establishing datagram-native onion (FS) UDP tunnel"
    );

    // No initial_user_data: this function's job ends at a live, empty
    // tunnel, exactly like the single-hop branch above and
    // `establish_native_udp_tunnel`'s own documented contract — what the
    // first datagram means, if anything, is the caller's decision.
    let tunnel = tokio::time::timeout(
        onion_timeout,
        OnionFsUdpTunnel::connect(
            &resolved_chain,
            &[],
            mesh_id,
            vec![chain.aead_suite],
            &peer_suite_prefs,
            peer_table.generation,
            cred,
        ),
    )
    .await
    .map_err(|_| {
        let e = MirageError::NodeUnreachable(format!(
            "chain {}: onion-fs udp connect timed out after {}s",
            chain.chain_id,
            onion_timeout.as_secs()
        ));
        warn!(
            chain_id = %chain.chain_id,
            timeout_secs = onion_timeout.as_secs(),
            "establish_udp_datagram_onion_tunnel: OnionFsUdpTunnel::connect timed out"
        );
        e
    })
    .and_then(|r| {
        r.map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                error = %e,
                "establish_udp_datagram_onion_tunnel: OnionFsUdpTunnel::connect failed"
            );
            e
        })
    })?;

    debug!(chain_id = %chain.chain_id, "onion-fs udp tunnel handshake done");
    Ok(DatagramTunnel::Onion(tunnel))
}

#[cfg(test)]
mod tests {
    use mirage_core::config::{
        ChainConfig, HandshakeStrategy, HopConfig, HopRole, ProtocolId, TcpProtocolId,
    };

    // ── Peer-table resolution tests ───────────────────────────────────────────

    /// `resolve_chain_pubkeys` must fill in `public_key` from peer_table when the
    /// hop has `public_key = None` and a matching `node_id` entry in the table.
    #[test]
    fn resolve_chain_pubkeys_fills_from_peer_table() {
        use mirage_core::mirage::mesh::peer_table::{PeerTable, PeerTableEntry};
        use super::resolve_chain_pubkeys;

        let pubkey = "a".repeat(64);
        let peer_table = PeerTable {
            generation: 1,
            peers: vec![PeerTableEntry {
                mesh_id: "test".into(),
                responsible_monitor_id: String::new(),
                node_id: "v2-entry".into(),
                pubkey_hex: pubkey.clone(),
                addr: "1.2.3.4:7000".into(),
                labels: vec![],
                updated_at_ms: 0,
                aead_suite_preference: Vec::new(),
                chain_face: None,
                chain_face_udp: None,
            }],
        };

        let chain = ChainConfig {
            chain_id: "test-resolve".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: None,
                node_id: Some("v2-entry".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let resolved = resolve_chain_pubkeys(&chain, &peer_table)
            .expect("resolve_chain_pubkeys must succeed when node_id is in peer_table");
        assert_eq!(
            resolved.hops[0].public_key.as_deref(),
            Some(pubkey.as_str()),
            "resolved hop must have the pubkey from peer_table"
        );
    }

    /// `resolve_chain_pubkeys` must return an error when `public_key = None` and
    /// the `node_id` is not present in the peer_table.
    #[test]
    fn resolve_chain_pubkeys_errors_when_node_id_missing() {
        use mirage_core::mirage::mesh::PeerTable;
        use super::resolve_chain_pubkeys;

        let chain = ChainConfig {
            chain_id: "test-missing".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: None,
                node_id: Some("v2-entry".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let result = resolve_chain_pubkeys(&chain, &PeerTable::empty());
        assert!(
            result.is_err(),
            "must error when node_id is not in peer_table"
        );
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("not in peer_table") || msg.contains("peer_table"),
            "error must mention peer_table, got: {msg}"
        );
    }

    // ── Additional resolve_chain_pubkeys edge cases ───────────────────────────

    /// Regression guard: the "not in peer_table" error must contain the exact
    /// node_id that failed lookup, so operators can pinpoint which hop is not
    /// registered yet.
    ///
    /// Error wording from `resolve_hop_pubkey`:
    /// `"chain X: hop[0] node_id 'Y' not in peer_table — node may not be registered yet"`
    #[test]
    fn resolve_chain_pubkeys_error_contains_node_id() {
        use mirage_core::mirage::mesh::peer_table::{PeerTable, PeerTableEntry};
        use super::resolve_chain_pubkeys;

        // Peer_table has one entry with a DIFFERENT node_id to simulate a
        // partially-populated table where our hop's node is not yet registered.
        let pt = PeerTable {
            generation: 1,
            peers: vec![PeerTableEntry {
                mesh_id: "test".into(),
                responsible_monitor_id: String::new(),
                node_id: "other-node".into(),
                pubkey_hex: "c".repeat(64),
                addr: "1.2.3.4:7001".into(),
                labels: vec![],
                updated_at_ms: 0,
                aead_suite_preference: Vec::new(),
                chain_face: None,
                chain_face_udp: None,
            }],
        };

        let chain = ChainConfig {
            chain_id: "test-error-msg".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: None,
                node_id: Some("missing-node-id".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let result = resolve_chain_pubkeys(&chain, &pt);
        assert!(result.is_err(), "must fail when node_id is absent from peer_table");
        let msg = format!("{:?}", result.unwrap_err());
        // The exact wording callers depend on (pool smoke tests, log scraping).
        assert!(
            msg.contains("not in peer_table"),
            "error must contain 'not in peer_table': {msg}"
        );
        assert!(
            msg.contains("missing-node-id"),
            "error must name the failing node_id: {msg}"
        );
    }

    /// When `hop.public_key` is already `Some(hex)`, `resolve_chain_pubkeys`
    /// must pass it through unchanged without touching the peer_table at all.
    ///
    /// We verify this by passing an empty peer_table — if the function
    /// erroneously tried to look up the hop in the table it would fail.
    #[test]
    fn resolve_chain_pubkeys_static_pubkey_skips_peer_table_lookup() {
        use mirage_core::mirage::mesh::PeerTable;
        use super::resolve_chain_pubkeys;

        let static_pubkey = "9".repeat(64);
        let chain = ChainConfig {
            chain_id: "test-static-key".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                // Already set — peer_table lookup must be skipped.
                public_key: Some(static_pubkey.clone()),
                node_id: Some("some-node".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        // Empty peer_table — would fail if lookup was attempted.
        let result = resolve_chain_pubkeys(&chain, &PeerTable::empty());
        assert!(
            result.is_ok(),
            "must succeed when hop.public_key is already set, even with empty peer_table"
        );
        let resolved = result.unwrap();
        assert_eq!(
            resolved.hops[0].public_key.as_deref(),
            Some(static_pubkey.as_str()),
            "static pubkey must be preserved unchanged"
        );
    }

    // ── freshen_chain_pubkeys tests (Phase 10.2.1 — UDP rotation recovery) ──────

    /// Core regression guard: when a hop has BOTH a stale static `public_key`
    /// AND a `node_id` that IS in the peer_table, `freshen_chain_pubkeys` must
    /// override the static key with the peer_table entry.
    ///
    /// This is the root cause of the UDP pool not recovering after node ephemeral
    /// key rotation: the chain stored in `pool.inner.chain` has `hop.public_key =
    /// Some(old_key)`.  After rotation the peer_table gets the new key, but
    /// `resolve_chain_pubkeys` (used in establish_raw_tunnel) skips lookup when
    /// `public_key` is already `Some`.  `freshen_chain_pubkeys` fixes this by
    /// always querying peer_table first when `node_id` is set.
    #[test]
    fn freshen_chain_pubkeys_overrides_stale_static_key_from_peer_table() {
        use mirage_core::mirage::mesh::peer_table::{PeerTable, PeerTableEntry};
        use super::freshen_chain_pubkeys;

        let stale_key = "a".repeat(64);
        let new_key   = "b".repeat(64);

        let chain = ChainConfig {
            chain_id: "test-freshen".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                // Stale static key baked in from initial config.
                public_key: Some(stale_key.clone()),
                // node_id enables peer_table resolution.
                node_id: Some("v2-entry".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let pt = PeerTable {
            generation: 2,
            peers: vec![PeerTableEntry {
                mesh_id: "test".into(),
                responsible_monitor_id: String::new(),
                node_id: "v2-entry".into(),
                // New key after rotation.
                pubkey_hex: new_key.clone(),
                addr: "1.2.3.4:7000".into(),
                labels: vec![],
                updated_at_ms: 0,
                aead_suite_preference: Vec::new(),
                chain_face: None,
                chain_face_udp: None,
            }],
        };

        let result = freshen_chain_pubkeys(&chain, &pt)
            .expect("freshen_chain_pubkeys must succeed when node_id is in peer_table");

        assert_eq!(
            result.hops[0].public_key.as_deref(),
            Some(new_key.as_str()),
            "freshen must replace stale static key with fresh peer_table key after rotation"
        );
        assert_ne!(
            result.hops[0].public_key.as_deref(),
            Some(stale_key.as_str()),
            "stale static key must NOT be kept after rotation"
        );
    }

    /// When node_id is set but the node is NOT yet in the peer_table,
    /// `freshen_chain_pubkeys` must fall back to the existing static key.
    ///
    /// This covers the cold-start / peer_table propagation lag window: the table
    /// may not have the entry yet, but the static key from the initial config is
    /// still valid.
    #[test]
    fn freshen_chain_pubkeys_falls_back_to_static_when_node_not_in_peer_table() {
        use mirage_core::mirage::mesh::PeerTable;
        use super::freshen_chain_pubkeys;

        let static_key = "c".repeat(64);
        let chain = ChainConfig {
            chain_id: "test-freshen-fallback".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: Some(static_key.clone()),
                node_id: Some("v2-entry".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        // Empty peer_table — node not registered yet.
        let result = freshen_chain_pubkeys(&chain, &PeerTable::empty())
            .expect("must succeed: node not in peer_table, static key present as fallback");

        assert_eq!(
            result.hops[0].public_key.as_deref(),
            Some(static_key.as_str()),
            "must retain static key when peer_table has no entry for node_id"
        );
    }

    /// When hop has no node_id AND no public_key,
    /// `freshen_chain_pubkeys` must return a config error.
    #[test]
    fn freshen_chain_pubkeys_errors_when_neither_node_id_nor_pubkey() {
        use mirage_core::mirage::mesh::PeerTable;
        use super::freshen_chain_pubkeys;

        let chain = ChainConfig {
            chain_id: "test-freshen-nokey".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: None,
                node_id: None,
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let result = freshen_chain_pubkeys(&chain, &PeerTable::empty());
        assert!(result.is_err(), "must error when hop has neither public_key nor node_id");
    }

    /// When hop has no node_id but has static public_key (e.g. hardcoded relay),
    /// `freshen_chain_pubkeys` must pass through unchanged.
    #[test]
    fn freshen_chain_pubkeys_passthrough_when_no_node_id_with_static_pubkey() {
        use mirage_core::mirage::mesh::PeerTable;
        use super::freshen_chain_pubkeys;

        let static_key = "d".repeat(64);
        let chain = ChainConfig {
            chain_id: "test-freshen-static".into(),
            hops: vec![HopConfig {
                addr: "1.2.3.4:7000".into(),
                public_key: Some(static_key.clone()),
                node_id: None,  // no node_id — no peer_table lookup possible
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let result = freshen_chain_pubkeys(&chain, &PeerTable::empty())
            .expect("must succeed: no node_id means static key is the only option");

        assert_eq!(
            result.hops[0].public_key.as_deref(),
            Some(static_key.as_str()),
            "static key without node_id must be preserved unchanged"
        );
    }

    // ── Happy Eyeballs tests ──────────────────────────────────────────────────

    use std::net::SocketAddr;
    use super::happy_eyeballs;

    /// Bind two local TCP listeners (v4 + v6) and verify v6 wins the race.
    ///
    /// Both listeners are ready before the race starts, so v6 wins because it
    /// has no 200 ms delay.
    #[tokio::test]
    async fn happy_eyeballs_prefers_v6() {
        let v4_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v6_listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();

        let v4_addr: SocketAddr = v4_listener.local_addr().unwrap();
        let v6_addr: SocketAddr = v6_listener.local_addr().unwrap();

        let winner = happy_eyeballs(v4_addr, v6_addr).await.unwrap();
        assert_eq!(winner, v6_addr, "v6 should win when both are reachable");
    }

    /// v4-only path: `happy_eyeballs` with two identical v4 addresses succeeds
    /// and returns the bound address.
    #[tokio::test]
    async fn happy_eyeballs_v4_only() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v4_addr: SocketAddr = listener.local_addr().unwrap();

        // Both candidates are the same v4 address — first to connect wins.
        let winner = happy_eyeballs(v4_addr, v4_addr).await.unwrap();
        assert_eq!(winner, v4_addr);
    }

    /// When v6 is unreachable (unrouted documentation address 2001:db8::1),
    /// the race should fall back to v4 and succeed.
    ///
    /// Uses a short per-probe timeout so the test completes quickly.  The
    /// 2001:db8:: prefix is IANA-reserved and never routed — connect returns
    /// an error quickly (network unreachable) or times out within the 5 s probe
    /// window.  Either way, v4 must win before the overall test timeout.
    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_v4() {
        let v4_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v4_addr: SocketAddr = v4_listener.local_addr().unwrap();

        // 2001:db8::1 — documentation range, never routed.
        // Port 1 is almost certainly closed on any system.
        let v6_addr: SocketAddr = "[2001:db8::1]:1".parse().unwrap();

        let winner = happy_eyeballs(v4_addr, v6_addr).await.unwrap();
        assert_eq!(winner, v4_addr, "v4 must win when v6 is unreachable");
    }

    // ── UDP reproducer: MirageUdp / RawUdp single-hop round-trip ─────────────

    /// Reproducer for Track 3 — UDP handshake timeout on staging-v2.
    ///
    /// Spawns an in-process `run_server_udp` listener with `RawUdp` camouflage
    /// and dials it via `establish_raw_tunnel` with a matching `MirageUdp` chain.
    /// The round-trip must complete in under 2 seconds.
    ///
    /// If this test times out (> 2 s) → the bug is in the client/server
    /// protocol exchange itself (framing, AEAD, handshake sequence).
    /// If this test passes but staging still fails → the bug is network-level
    /// on the Mac path (NAT return path, firewall) and a tcpdump is needed.
    #[tokio::test]
    async fn udp_raw_single_hop_round_trip() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();

        use mirage_core::{
            config::{
                AuthMode, ChainConfig, HopConfig, HopRole, MirageEndpointConfig,
                ProtocolId, TransportCamouflage, TransportKind, UdpProtocolId,
                HandshakeStrategy,
            },
            crypto::KeyPair,
            mirage::mesh::PeerTable,
        };
        use mirage_protocol::{driver::run_server_udp, traits::Tunnel};
        use std::net::SocketAddr;
        use tokio::sync::mpsc;

        // ── Generate server keypair ───────────────────────────────────────────
        let server_kp = KeyPair::generate();
        let server_pubkey_hex = server_kp.public.to_bytes()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                write!(s, "{b:02x}").unwrap();
                s
            });

        // ── Bind server on ephemeral UDP port ─────────────────────────────────
        // Bind to port 0 and immediately find out the OS-assigned port.
        // We release the socket before passing the address to run_server_udp
        // so the driver can re-bind it. The OS port stays reserved via
        // TIME_WAIT long enough for the driver to claim it.
        let tmp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let raw_udp_camouflage = TransportCamouflage::RawUdp { bind_addr: server_addr };
        let server_config = MirageEndpointConfig {
            transport: TransportKind::Udp,
            auth: AuthMode::Blake3,
            camouflage: raw_udp_camouflage,
            byte_cipher: None,
            byte_cipher_mode: None,
        };

        let mesh_id = b"test-mesh".to_vec();

        // ── Start server listener task ────────────────────────────────────────
        let (tunnel_tx, mut tunnel_rx) = mpsc::channel::<Box<dyn Tunnel>>(4);
        let server_kp_clone = server_kp.clone();
        let server_config_clone = server_config.clone();
        let mesh_id_server = mesh_id.clone();
        let _server_task = tokio::spawn(async move {
            let _ = run_server_udp(
                &server_config_clone,
                &server_kp_clone,
                server_addr,
                tunnel_tx,
                &mesh_id_server,
                true, // allow_legacy_v8=true in test to accept V8 fallback
            )
            .await;
        });

        // Small delay so server binds before client dials.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // ── Build client chain config ─────────────────────────────────────────
        let chain = ChainConfig {
            chain_id: "test-udp-raw".into(),
            hops: vec![HopConfig {
                addr: server_addr.to_string(),
                public_key: Some(server_pubkey_hex),
                node_id: None,
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: Some(TransportCamouflage::RawUdp { bind_addr: server_addr }),
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: mirage_core::config::ReplyMode::Raw,
            protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        // ── Dial via establish_raw_tunnel ─────────────────────────────────────
        // chain_protocols is unused for UDP path — pass an empty stub.
        // establish_raw_tunnel detects ProtocolId::Udp and routes to
        // establish_udp_chain_tunnel bypassing chain_protocols entirely.
        use mirage_protocol::negotiation::ProtocolChain;
        use mirage_protocol::traits::TcpProtocol;
        use mirage_core::config::{CamouflageMode, TcpProtocolId};

        // Stub TcpProtocol that always errors — never called for UDP path.
        struct NeverConnectProtocol;
        #[async_trait::async_trait]
        impl TcpProtocol for NeverConnectProtocol {
            async fn connect(
                &self,
                _addr: SocketAddr,
                _server_pubkey: &[u8; 32],
                _sni: &str,
                _camouflage: CamouflageMode,
            ) -> Result<Box<dyn Tunnel>, mirage_core::error::MirageError> {
                Err(mirage_core::error::MirageError::Config(
                    "NeverConnectProtocol: should not be called on UDP path".into(),
                ))
            }
            async fn accept(
                &self,
                _stream: tokio::net::TcpStream,
                _peeked: &[u8],
            ) -> Result<mirage_protocol::traits::AcceptResult, mirage_core::error::MirageError> {
                Err(mirage_core::error::MirageError::Config(
                    "NeverConnectProtocol: accept not implemented".into(),
                ))
            }
            fn id(&self) -> TcpProtocolId { TcpProtocolId::Mirage }
            fn probe_resistant(&self) -> bool { false }
        }

        let chain_protocols = std::sync::Arc::new(ProtocolChain::new(vec![
            Box::new(NeverConnectProtocol) as Box<dyn TcpProtocol>,
        ]));
        let pt = PeerTable::empty();

        let dial_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::establish_raw_tunnel(&chain_protocols, &chain, &pt, &mesh_id, None, None),
        )
        .await;

        match dial_result {
            Err(_elapsed) => {
                panic!(
                    "UDP handshake timed out after 2s — \
                     packet did not reach server dispatcher or handshake got stuck. \
                     Enable RUST_LOG=mirage_protocol=debug and check raw_udp dispatcher logs."
                );
            }
            Ok(Err(e)) => {
                panic!("establish_raw_tunnel failed: {e:?}");
            }
            Ok(Ok(_tunnel)) => {
                // Success: verify the server also received a tunnel.
                let server_tunnel = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    tunnel_rx.recv(),
                )
                .await
                .expect("server tunnel_rx recv timed out")
                .expect("tunnel_rx closed unexpectedly");
                drop(server_tunnel);
            }
        }
    }

    // ── mint_epoch_hmac_credential unit tests ─────────────────────────────────

    fn make_cred_params(epoch_id: u32, not_after_ms: u64) -> mirage_core::crypto::credential::CredentialParams {
        use mirage_core::crypto::credential::{CredentialParams, EpochEntry};
        use mirage_core::mirage::wire::CredentialScheme;
        CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(epoch_id, not_after_ms, [0x42u8; 32])],
        )
    }

    #[test]
    fn mint_epoch_hmac_empty_epochs_returns_none() {
        use mirage_core::crypto::credential::CredentialParams;
        use mirage_core::mirage::wire::CredentialScheme;
        let params = CredentialParams::single(1, CredentialScheme::EpochHmac, vec![]);
        assert!(super::mint_epoch_hmac_credential(&params, 0).is_none());
    }

    #[test]
    fn mint_epoch_hmac_all_expired_returns_none() {
        let params = make_cred_params(1, 1000); // expires at ms=1000
        // now_ms=2000 > not_after_ms
        assert!(super::mint_epoch_hmac_credential(&params, 2000).is_none());
    }

    #[test]
    fn mint_epoch_hmac_live_epoch_returns_some_scheme_01() {
        let params = make_cred_params(7, u64::MAX);
        let cred = super::mint_epoch_hmac_credential(&params, 0).expect("live epoch must produce credential");
        assert_eq!(cred.scheme, 0x01);
        assert_eq!(cred.token.len(), 52); // EPOCH_HMAC_TOKEN_LEN
    }

    #[test]
    fn mint_epoch_hmac_two_calls_produce_different_tokens() {
        let params = make_cred_params(3, u64::MAX);
        let c1 = super::mint_epoch_hmac_credential(&params, 0).unwrap();
        let c2 = super::mint_epoch_hmac_credential(&params, 0).unwrap();
        // Different nonces → different tokens (bytes 4..20 differ with overwhelming probability).
        assert_ne!(c1.token, c2.token, "tokens must differ due to random nonce per dial");
    }

    #[test]
    fn mint_epoch_hmac_roundtrip_verify() {
        use mirage_core::crypto::credential::verify_credential;
        let params = make_cred_params(5, u64::MAX);
        let cred = super::mint_epoch_hmac_credential(&params, 0).unwrap();
        // verify_credential should accept the freshly minted token.
        let result = verify_credential(&params, cred.scheme, &cred.token, 0);
        assert!(result.is_ok(), "verify_credential failed: {:?}", result.err());
    }

    #[test]
    fn mint_epoch_hmac_signed_capability_scheme_returns_none() {
        use mirage_core::crypto::credential::{CredentialParams, EpochEntry};
        use mirage_core::mirage::wire::CredentialScheme;
        let params = CredentialParams::single(
            1,
            CredentialScheme::SignedCapability,
            vec![EpochEntry::with_secret(1, u64::MAX, [0x11u8; 32])],
        );
        // SignedCapability is asymmetric (issuer-minted) — client cannot self-mint,
        // so the EpochHmac client-mint helper must return None (not panic).
        assert!(super::mint_epoch_hmac_credential(&params, 0).is_none());
    }

    // ── Native UDP datagram dial (`establish_native_udp_tunnel`) ─────────────
    //
    // Two loopback proofs, matching what this function's own doc promises:
    // the handshake it wraps derives session keys that genuinely agree (not
    // merely "both calls returned Ok"), and the tunnel it hands back
    // actually carries data — whole, byte-identical, zero-length included —
    // in both directions. Every socket below binds `127.0.0.1:0` only.
    //
    // The server side has no wrapper in this crate to call — every test
    // plays the rendezvous reader by hand and calls
    // `run_server_handshake_v9_datagram` directly on the already-received
    // `ClientHello`, exactly as that function's own doc describes.

    fn native_udp_loopback(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
    }

    /// 1. The handshake `establish_native_udp_tunnel` wraps derives
    /// IDENTICAL session keys on both sides, over real loopback sockets.
    ///
    /// This drives the same two calls the function makes internally
    /// (`UdpPeerSocket::bind_client` then `run_client_handshake_v9_datagram`)
    /// directly, rather than through the wrapper, specifically so the raw
    /// key material — which `MirageCoreUdpTunnel` deliberately never exposes
    /// once a tunnel is built — can be asserted here byte for byte, rather
    /// than merely inferred from two `Ok`s. The next test proves the wrapper
    /// itself produces a live tunnel; this one proves the keys underneath it
    /// actually agree.
    #[tokio::test]
    async fn native_udp_handshake_derives_identical_session_keys() {
        use mirage_core::crypto::{AeadSuite, KeyPair};
        use mirage_protocol::auth::v9::CLIENT_HELLO_LEN;
        use mirage_protocol::core::{run_server_handshake_v9_datagram, ServerHelloCache};
        use mirage_protocol::transport::udp::UdpPeerSocket;
        use tokio::net::UdpSocket;

        const MESH_ID: &[u8] = b"test-mesh-native-udp-keys";
        const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

        let server_kp = KeyPair::generate();
        let server_static_pub = server_kp.public.to_bytes();
        let client_static_priv = KeyPair::generate().secret.to_bytes();

        let fixed = UdpSocket::bind(native_udp_loopback(0))
            .await
            .expect("bind fixed rendezvous socket on loopback");
        let fixed_addr = fixed.local_addr().expect("fixed socket local addr");

        let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
            .await
            .expect("bind client UdpPeerSocket — the same call establish_native_udp_tunnel makes");

        let cache = ServerHelloCache::new();

        let client_fut = mirage_protocol::core::run_client_handshake_v9_datagram(
            &mut client_socket,
            &server_static_pub,
            &client_static_priv,
            MESH_ID,
            SUITE_PREFS,
        );

        let server_fut = async {
            let mut raw = [0u8; CLIENT_HELLO_LEN];
            let (n, client_addr) = fixed
                .recv_from(&mut raw)
                .await
                .expect("recv ClientHello on the fixed rendezvous socket");
            assert_eq!(n, CLIENT_HELLO_LEN, "ClientHello datagram must be exactly CLIENT_HELLO_LEN bytes");

            let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
                .await
                .expect("bind server per-peer ephemeral socket");
            run_server_handshake_v9_datagram(
                &mut server_socket,
                &server_kp,
                MESH_ID,
                SUITE_PREFS,
                |_ctx| true,
                &raw,
                &cache,
            )
            .await
            .expect("server handshake I/O must not error")
            .expect("server must accept the ClientHello")
        };

        let (client_result, server_result) = tokio::join!(client_fut, server_fut);
        let client_result = client_result.expect("client datagram handshake must succeed");

        assert_eq!(
            *client_result.session_keys.client_write_key,
            *server_result.session_keys.client_write_key,
            "client_write_key must match on both sides"
        );
        assert_eq!(
            *client_result.session_keys.server_write_key,
            *server_result.session_keys.server_write_key,
            "server_write_key must match on both sides"
        );
        assert_eq!(
            client_result.session_keys.suite, server_result.session_keys.suite,
            "negotiated AEAD suite must match on both sides"
        );
    }

    /// 2. Data crosses the tunnel `establish_native_udp_tunnel` actually
    /// returns, in both directions, whole and byte-identical — including a
    /// zero-length datagram, which is a legitimate authenticated message on
    /// this tunnel type (see `MirageCoreUdpTunnel`'s own doc), never an
    /// end-of-stream signal.
    #[tokio::test]
    async fn native_udp_tunnel_carries_data_both_directions_including_empty_datagram() {
        use mirage_core::crypto::{AeadSuite, KeyPair};
        use mirage_protocol::auth::v9::CLIENT_HELLO_LEN;
        use mirage_protocol::core::{run_server_handshake_v9_datagram, ServerHelloCache};
        use mirage_protocol::traits::{TransportInfo, Tunnel};
        use mirage_protocol::transport::udp::UdpPeerSocket;
        use tokio::net::UdpSocket;

        const MESH_ID: &[u8] = b"test-mesh-native-udp-data";
        const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

        let server_kp = KeyPair::generate();
        let server_static_pub = server_kp.public.to_bytes();
        let client_static_priv = KeyPair::generate().secret.to_bytes();

        let fixed = UdpSocket::bind(native_udp_loopback(0))
            .await
            .expect("bind fixed rendezvous socket on loopback");
        let fixed_addr = fixed.local_addr().expect("fixed socket local addr");

        let cache = ServerHelloCache::new();

        // The client leg goes through the actual function under test.
        // No credential — asserts the same no-credential behaviour this test
        // asserted before credential carriage existed.
        let client_fut = super::establish_native_udp_tunnel(
            fixed_addr,
            &server_static_pub,
            &client_static_priv,
            MESH_ID,
            SUITE_PREFS,
            None,
        );

        let server_fut = async {
            let mut raw = [0u8; CLIENT_HELLO_LEN];
            let (n, client_addr) = fixed
                .recv_from(&mut raw)
                .await
                .expect("recv ClientHello on the fixed rendezvous socket");
            assert_eq!(n, CLIENT_HELLO_LEN, "ClientHello datagram must be exactly CLIENT_HELLO_LEN bytes");

            let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
                .await
                .expect("bind server per-peer ephemeral socket");
            let result = run_server_handshake_v9_datagram(
                &mut server_socket,
                &server_kp,
                MESH_ID,
                SUITE_PREFS,
                |_ctx| true,
                &raw,
                &cache,
            )
            .await
            .expect("server handshake I/O must not error")
            .expect("server must accept the ClientHello");

            let info = TransportInfo::udp_raw(server_socket.remote_addr());
            super::MirageCoreUdpTunnel::new(
                server_socket,
                &result.session_keys,
                false,
                info,
                mirage_protocol::auth::AuthMode::Hmac,
            )
        };

        let (client_result, mut server_tunnel) = tokio::join!(client_fut, server_fut);
        let mut client_tunnel = client_result.expect("establish_native_udp_tunnel must succeed");

        // client -> server, whole payload.
        let client_to_server = b"hello from the native udp dial, client to server";
        client_tunnel.send(client_to_server).await.expect("client send must succeed");
        let got = server_tunnel.recv_datagram().await.expect("server recv_datagram must succeed");
        assert_eq!(got, client_to_server, "server must receive the exact client payload");

        // server -> client, whole payload.
        let server_to_client = b"hello back from the server, over the same tunnel";
        server_tunnel.send(server_to_client).await.expect("server send must succeed");
        let got = client_tunnel.recv_datagram().await.expect("client recv_datagram must succeed");
        assert_eq!(got, server_to_client, "client must receive the exact server payload");

        // A zero-length datagram, client -> server: a legitimate empty
        // message, not an end-of-stream marker.
        client_tunnel.send(&[]).await.expect("client zero-length send must succeed");
        let got = server_tunnel
            .recv_datagram()
            .await
            .expect("server must decode the zero-length datagram");
        assert_eq!(got, Vec::<u8>::new(), "server must receive an exact zero-length payload");

        // And the reverse direction, to prove it is not one-way.
        server_tunnel.send(&[]).await.expect("server zero-length send must succeed");
        let got = client_tunnel
            .recv_datagram()
            .await
            .expect("client must decode the zero-length datagram");
        assert_eq!(got, Vec::<u8>::new(), "client must receive an exact zero-length payload");
    }

    // ── establish_udp_datagram_tunnel (chain-level datagram-native dial) ─────

    /// Success path: the entry's peer_table `chain_face_udp` resolves to a
    /// real loopback server (played by hand, exactly like the
    /// `native_udp_*` tests above), and `establish_udp_datagram_tunnel`
    /// completes a live tunnel that actually carries data — not merely
    /// returns `Ok`.
    ///
    /// `hops[0].addr` is given a deliberately WRONG port (`1`) so a passing
    /// test proves the face's own port was actually used, not the hop's.
    #[tokio::test]
    async fn establish_udp_datagram_tunnel_completes_via_peer_table_chain_face_udp() {
        use mirage_core::config::{
            ChainConfig, HandshakeStrategy, HopConfig, HopRole, ProtocolId, ReplyMode,
            TransportCamouflage, UdpProtocolId,
        };
        use mirage_core::crypto::{AeadSuite, KeyPair};
        use mirage_core::mirage::mesh::peer_table::{ChainFace, PeerTable, PeerTableEntry};
        use mirage_protocol::auth::v9::CLIENT_HELLO_LEN;
        use mirage_protocol::core::{run_server_handshake_v9_datagram, ServerHelloCache};
        use mirage_protocol::traits::Tunnel;
        use mirage_protocol::transport::udp::UdpPeerSocket;
        use std::fmt::Write;
        use tokio::net::UdpSocket;

        let server_kp = KeyPair::generate();
        let server_pubkey_hex =
            server_kp.public.to_bytes().iter().fold(String::with_capacity(64), |mut s, b| {
                write!(s, "{b:02x}").expect("writing to a String cannot fail");
                s
            });

        let fixed = UdpSocket::bind(native_udp_loopback(0))
            .await
            .expect("bind fixed rendezvous socket on loopback");
        let server_face_addr = fixed.local_addr().expect("fixed socket local addr");

        let hop_addr = SocketAddr::new(server_face_addr.ip(), 1);
        let chain = ChainConfig {
            chain_id: "test-udp-datagram-tunnel".into(),
            hops: vec![HopConfig {
                addr: hop_addr.to_string(),
                public_key: Some(server_pubkey_hex.clone()),
                node_id: Some("v9-dgram-entry".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Raw,
            protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let peer_table = PeerTable {
            generation: 1,
            peers: vec![PeerTableEntry {
                mesh_id: "test".into(),
                responsible_monitor_id: String::new(),
                node_id: "v9-dgram-entry".into(),
                pubkey_hex: server_pubkey_hex,
                addr: hop_addr.to_string(),
                labels: vec![],
                updated_at_ms: 0,
                aead_suite_preference: Vec::new(),
                chain_face: None,
                chain_face_udp: Some(ChainFace {
                    port: server_face_addr.port(),
                    camouflage: TransportCamouflage::RawUdp { bind_addr: server_face_addr },
                }),
            }],
        };

        let mesh_id = b"test-mesh-udp-datagram-tunnel".to_vec();
        let cache = ServerHelloCache::new();
        const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm];

        let client_fut =
            super::establish_udp_datagram_tunnel(&chain, &peer_table, &mesh_id, None, None);

        let server_fut = async {
            let mut raw = [0u8; CLIENT_HELLO_LEN];
            let (n, client_addr) = fixed
                .recv_from(&mut raw)
                .await
                .expect("recv ClientHello on the fixed rendezvous socket");
            assert_eq!(n, CLIENT_HELLO_LEN, "ClientHello datagram must be exactly CLIENT_HELLO_LEN bytes");

            let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
                .await
                .expect("bind server per-peer ephemeral socket");
            let result = run_server_handshake_v9_datagram(
                &mut server_socket,
                &server_kp,
                &mesh_id,
                SUITE_PREFS,
                |_ctx| true,
                &raw,
                &cache,
            )
            .await
            .expect("server handshake I/O must not error")
            .expect("server must accept the ClientHello");

            let info = mirage_protocol::traits::TransportInfo::udp_raw(server_socket.remote_addr());
            super::MirageCoreUdpTunnel::new(
                server_socket,
                &result.session_keys,
                false,
                info,
                mirage_protocol::auth::AuthMode::Hmac,
            )
        };

        let (client_result, mut server_tunnel) = tokio::join!(client_fut, server_fut);
        let mut client_tunnel = client_result.expect(
            "establish_udp_datagram_tunnel must resolve the entry's chain_face_udp \
             and complete the handshake against it",
        );

        let ping = b"ping over establish_udp_datagram_tunnel";
        client_tunnel.send(ping).await.expect("client send must succeed");
        let got = server_tunnel
            .recv_datagram()
            .await
            .expect("server recv_datagram must succeed");
        assert_eq!(
            got, ping,
            "server must receive the exact payload over the peer-table-resolved dial \
             (proves the face's port, not the hop's wrong one, was actually dialed)"
        );
    }

    /// Refusal path: the entry has published only its STREAM chain face
    /// (`chain_face`), never a datagram one — `establish_udp_datagram_tunnel`
    /// must refuse by name rather than fall back to the stream face or fail
    /// silently.
    #[tokio::test]
    async fn establish_udp_datagram_tunnel_refuses_when_only_stream_face_published() {
        use mirage_core::config::{
            ChainConfig, HandshakeStrategy, HopConfig, HopRole, ProtocolId, ReplyMode,
            TransportCamouflage, UdpProtocolId,
        };
        use mirage_core::mirage::mesh::peer_table::{ChainFace, PeerTable, PeerTableEntry};

        let chain = ChainConfig {
            chain_id: "test-udp-datagram-tunnel-refuse".into(),
            hops: vec![HopConfig {
                addr: "127.0.0.1:1".into(),
                public_key: Some("a".repeat(64)),
                node_id: Some("v9-dgram-entry-no-face".into()),
                sni: None,
                role: HopRole::Exit,
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            }],
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Raw,
            protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        let peer_table = PeerTable {
            generation: 1,
            peers: vec![PeerTableEntry {
                mesh_id: "test".into(),
                responsible_monitor_id: String::new(),
                node_id: "v9-dgram-entry-no-face".into(),
                pubkey_hex: "a".repeat(64),
                addr: "127.0.0.1:1".into(),
                labels: vec![],
                updated_at_ms: 0,
                aead_suite_preference: Vec::new(),
                // Only the stream face is published — no chain_face_udp.
                chain_face: Some(ChainFace { port: 1, camouflage: TransportCamouflage::None }),
                chain_face_udp: None,
            }],
        };

        let mesh_id = b"test-mesh-udp-datagram-tunnel-refuse".to_vec();
        let result =
            super::establish_udp_datagram_tunnel(&chain, &peer_table, &mesh_id, None, None).await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("must refuse when only a stream chain face is published"),
        };
        let msg = format!("{err:?}");
        assert!(
            msg.contains("chain_face_udp"),
            "error must name the missing datagram chain face: {msg}"
        );
        assert!(
            msg.contains("v9-dgram-entry-no-face"),
            "error must name the failing node_id: {msg}"
        );
    }

    /// U5 Slice 7: `establish_udp_datagram_tunnel` must no longer return the
    /// removed single-hop-only refusal for a multi-hop OnionPeel chain — it
    /// must dispatch to [`super::OnionFsUdpTunnel::connect`] and actually
    /// complete the telescopic handshake against a real (hand-rolled)
    /// two-hop peer, proving the dial reaches the telescopic path through
    /// THIS function's own dispatch rather than only when
    /// `OnionFsUdpTunnel::connect` is called directly (already covered by
    /// `onion_tunnel_fs_udp.rs`'s own tests).
    ///
    /// The simulator mirrors `onion_tunnel_fs_udp.rs`'s own
    /// `run_fs_udp_simulator` (Slice 3's proof) — same shape, same
    /// assertions on the datagrams it reads — because that IS the shape a
    /// real two-hop FS UDP peer produces; duplicating it here proves the
    /// dispatch reaches that shape, not a different one.
    #[tokio::test]
    async fn establish_udp_datagram_tunnel_routes_a_multi_hop_chain_to_the_telescopic_dial_instead_of_refusing_it() {
        use mirage_core::config::{
            ChainConfig, HandshakeStrategy, HopConfig, HopRole, ProtocolId, ReplyMode,
            UdpProtocolId,
        };
        use mirage_core::crypto::{AeadSuite, KeyPair};
        use mirage_core::mirage::mesh::peer_table::PeerTable;
        use mirage_protocol::core::udp_handshake::is_fs_chain_hello;
        use mirage_protocol::onion::builder::{compute_fs_transcript_base, peel_onion_fs_layer};
        use mirage_protocol::onion::fs_frame::{
            FsCreatedFrame, FsCreatedStatus, FsExtendFrame, FsInitFrame,
        };
        use mirage_protocol::onion::layer::peel_layer_v7;
        use mirage_protocol::traits::Tunnel;
        use rand::rngs::OsRng;
        use tokio::net::UdpSocket;
        use x25519_dalek::EphemeralSecret;

        fn hex_encode_pub(b: &[u8; 32]) -> String {
            b.iter().map(|x| format!("{:02x}", x)).collect()
        }

        const N: usize = 2;
        let node_kps: Vec<KeyPair> = (0..N).map(|_| KeyPair::generate()).collect();
        let node_ids: Vec<String> = (0..N).map(|i| format!("test-multihop-node-{i}")).collect();
        let pubkeys_hex: Vec<String> =
            node_kps.iter().map(|kp| hex_encode_pub(&kp.public.to_bytes())).collect();

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind sim socket");
        let entry_addr = sock.local_addr().expect("sim local addr");

        let hops: Vec<HopConfig> = (0..N)
            .map(|i| HopConfig {
                addr: if i == 0 { entry_addr.to_string() } else { "127.0.0.1:1".into() },
                public_key: Some(pubkeys_hex[i].clone()),
                node_id: Some(node_ids[i].clone()),
                sni: None,
                role: if i == 0 { HopRole::Entry } else { HopRole::Exit },
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: None,
            })
            .collect();

        let chain = ChainConfig {
            chain_id: "test-udp-datagram-tunnel-multihop".into(),
            hops,
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Onion,
            protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
            priority: 0,
            shaping: Default::default(),
            camouflage: Default::default(),
            cover_traffic: Default::default(),
            socks5_bind: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        // Empty peer_table: every hop already carries its own public_key, so
        // resolve_chain_pubkeys has nothing to resolve, and an unresolved
        // node_id in peer_suite_prefs construction degrades to "no
        // preference", not an error — exactly as it would for a live chain
        // plan whose peer_table snapshot has not caught up yet.
        let peer_table = PeerTable { generation: 0, peers: vec![] };
        let mesh_id = b"test-mesh-udp-datagram-tunnel-multihop".to_vec();

        let sim_node_ids = node_ids.clone();
        let sim_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            let (hn, client_addr) = sock.recv_from(&mut buf).await.expect("sim: recv hello");
            assert!(
                is_fs_chain_hello(&buf[..hn]),
                "sim: datagram 1 must be a shaped FS-chain classifier hello"
            );

            let (n0, from0) = sock.recv_from(&mut buf).await.expect("sim: recv FsInitFrame");
            assert_eq!(from0, client_addr, "sim: step 0 frame must come from the hello's own peer");
            let (init, _) = FsInitFrame::decode(&buf[..n0]).expect("sim: FsInitFrame decode");
            assert_eq!(init.chain_position, 0);
            assert_eq!(init.chain_length as usize, N, "sim: FsInitFrame must carry the real chain depth");

            let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(N);
            let mut layer_suites: Vec<AeadSuite> = Vec::with_capacity(N);
            let mut prev_transcript = compute_fs_transcript_base(&init.mesh_id, &init.chain_id);
            let mut client_eph_pub = init.client_eph_pub;
            let mut suite = *init.client_suites.first().expect("sim: no suites offered");

            for i in 0..N {
                if i > 0 {
                    let (nx, fromx) = sock.recv_from(&mut buf).await.expect("sim: recv extend frame");
                    assert_eq!(fromx, client_addr, "sim: extend frame must come from the same peer");
                    let mut current = buf[..nx].to_vec();
                    for (j, key) in layer_keys.iter().enumerate().take(i) {
                        let (_next_hop, inner) = peel_layer_v7(layer_suites[j], &current, key)
                            .expect("sim: peel extend layer");
                        current = inner;
                    }
                    let (extend, _) = FsExtendFrame::decode(&current).expect("sim: FsExtendFrame decode");
                    assert_eq!(extend.chain_position as usize, i);
                    client_eph_pub = extend.client_eph_pub;
                    suite = *extend.client_suites.first().expect("sim: extend no suites");
                    prev_transcript = extend.prev_transcript;
                }

                let s = EphemeralSecret::random_from_rng(OsRng);
                let (key, s_pub, t, auth_tag) = peel_onion_fs_layer(
                    s,
                    &node_kps[i],
                    &client_eph_pub,
                    i as u8,
                    &prev_transcript,
                    &sim_node_ids[i],
                    suite,
                );
                let created = FsCreatedFrame {
                    chain_position: i as u8,
                    suite,
                    status: FsCreatedStatus::Ok,
                    server_eph_pub: s_pub,
                    transcript_hash: t,
                    auth_tag,
                };
                sock.send_to(&created.encode(), client_addr).await.expect("sim: send FsCreatedFrame");

                layer_keys.push(key);
                layer_suites.push(suite);
                prev_transcript = t;
            }
        });

        let result = super::establish_udp_datagram_tunnel(&chain, &peer_table, &mesh_id, None, None).await;
        sim_handle.await.expect("simulator task must not panic");

        let err_text = match &result {
            Ok(_) => String::new(),
            Err(e) => format!("{e:?}"),
        };
        assert!(
            !err_text.contains("single-hop only"),
            "the removed single-hop-only refusal must never fire for a multi-hop chain: {err_text}"
        );
        let tunnel = result.expect(
            "establish_udp_datagram_tunnel must dispatch a multi-hop chain to \
             OnionFsUdpTunnel::connect and complete the telescopic handshake, not refuse it",
        );
        // Reaching a live Tunnel object at all — through this function's own
        // dispatch, not a direct OnionFsUdpTunnel::connect call — is the
        // property under test; transport_info() touches it without needing
        // a second live peer for a send/recv round trip (already proven by
        // onion_tunnel_fs_udp.rs's own tests at this exact depth).
        let _ = tunnel.transport_info();
    }

    // -- Datagram chain addressing: when the client names a hop ---------------

    mod datagram_chain_addressing {
        use super::super::entry_chain_address;
        use mirage_core::config::{
            ChainConfig, HandshakeStrategy, HopConfig, HopRole, ProtocolId, TcpProtocolId,
        };

        fn chain_with(token_hex: Option<&str>, hops: usize) -> ChainConfig {
            let hop = |i: usize| HopConfig {
                addr: format!("1.2.3.{}:7000", i + 1),
                public_key: None,
                node_id: Some(format!("v2-hop{i}")),
                sni: None,
                role: if i + 1 == hops { HopRole::Exit } else { HopRole::Entry },
                display_name: None,
                camouflage: None,
                byte_cipher: None,
                relay_mode: mirage_core::mirage::wire::RelayMode::OnionPeel,
                camo_server_pubkey: None,
                selector_token_hex: if i == 0 { token_hex.map(str::to_string) } else { None },
            };
            ChainConfig {
                chain_id: "auto-deadbeef".into(),
                hops: (0..hops).map(hop).collect(),
                handshake: HandshakeStrategy::Telescopic,
                reply: mirage_core::config::ReplyMode::Raw,
                protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
                priority: 0,
                shaping: Default::default(),
                camouflage: Default::default(),
                cover_traffic: Default::default(),
                socks5_bind: None,
                aead_suite: mirage_core::crypto::AeadSuite::ChaCha20Poly1305,
                kill_switch: None,
                group: None,
                nature: None,
            }
        }

        /// A chain with no minted token has nothing finer than the mesh to
        /// say, and must send no block. Sending one would address a chain
        /// routing table that has no entry for it, and the node answers a
        /// miss with silence -- turning today's working direct dial into a
        /// timeout.
        #[test]
        fn a_chain_without_a_minted_token_sends_no_block() {
            let chain = chain_with(None, 1);
            let addr = entry_chain_address(&chain, &chain.hops[0])
                .expect("a token-less chain is not an error, it is an absence");
            assert!(addr.is_none());
        }

        /// With a token, the entry is named: position 0, the chain's real
        /// depth, and the token itself as the selector.
        #[test]
        fn a_minted_token_names_the_entry_hop() {
            let chain = chain_with(Some("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"), 3);
            let addr = entry_chain_address(&chain, &chain.hops[0])
                .expect("a well-formed token must build an address")
                .expect("a token-bearing chain must produce a block");
            assert_eq!(addr.chain_id, b"auto-deadbeef".to_vec());
            assert_eq!(addr.chain_position, 0);
            // Depth is read off the chain, not fixed: the block is built the
            // same way at any depth.
            assert_eq!(addr.chain_length, 3);
            assert_eq!(addr.selector_token, vec![0x5Au8; 16]);
            assert_eq!(addr.selector_bytes(), vec![0x5Au8; 16]);
        }

        /// A malformed token is refused rather than dropped to the derived
        /// name. Falling back would dial a hop the node binds under a
        /// different selector, and the dial would die in a timeout with
        /// nothing saying why.
        #[test]
        fn a_malformed_token_is_refused_by_name() {
            for bad in ["abc", "zz5a5a5a"] {
                let chain = chain_with(Some(bad), 1);
                let err = entry_chain_address(&chain, &chain.hops[0])
                    .expect_err("a malformed selector_token_hex must not be silently ignored");
                let text = err.to_string();
                assert!(
                    text.contains("selector_token_hex"),
                    "the refusal must name the field it refused: {text}"
                );
            }
        }
    }
}
