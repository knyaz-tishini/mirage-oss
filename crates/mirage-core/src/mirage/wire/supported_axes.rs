//! `SupportedAxes` — declared capability fingerprint for a Mirage node.
//!
//! Read from `node.toml` at startup, sent to the monitor on register.
//! Monitor uses it to pre-reject specs the node cannot honor. Node MAY
//! enforce on activate as defense-in-depth.
//!
//! Kinds (not values): `ByteCipherKind::ObfuscateAll` says "I can peel
//! ObfuscateAll"; the actual `obf_key` arrives in `LayerSpec.byte_cipher`.

use serde::{Deserialize, Serialize};

use super::{
    ByteCipherMode, MirageListenerSpec, TcpProtocolId, TransportCamouflage, UdpProtocolId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteCipherKind {
    Raw,
    ValidateFirst,
    StripFirst,
    ObfuscateAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CamouflageKind {
    None,
    TlsReal,
    WebSocket,
    Xhttp,
    Reality,
    Quic,
    Http3,
    Hysteria2,
    WireGuard,
    DnsTunnel,
    Ssh,
    Grpc,
    Icmp,
    WebTransport,
    RawUdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayModeKind {
    Transparent,
    CryptoVerify,
    OnionPeel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitModeKind {
    Direct,
    Onion,
    Control,
}

/// Onion handshake variant a node can participate in.
///
/// `EphemeralStatic` = current V8 production (client ephemeral × node static ECDH).
/// `ForwardSecret`   = V9-FS telescopic circuit (both sides ephemeral ECDH per hop).
///
/// Carried in `SupportedAxes.onion_handshakes`; old nodes that don't advertise this
/// field at all are treated as `[]` (supports neither explicitly — picker skips them
/// for FS chains).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnionHandshakeKind {
    /// Current production V8: client ephemeral × node static ECDH. No forward secrecy.
    EphemeralStatic,
    /// V9-FS: both client and node generate per-session ephemerals. Telescopic circuit build.
    /// Requires wire byte `0x0A` (`WIRE_VERSION_FS`) at the node listener.
    ForwardSecret,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupportedAxes {
    pub relay_modes: Vec<RelayModeKind>,
    pub exit_modes: Vec<ExitModeKind>,
    pub wires_tcp: Vec<TcpProtocolId>,
    pub wires_udp: Vec<UdpProtocolId>,
    pub camouflages: Vec<CamouflageKind>,
    /// Byte-cipher variants this node can peel.
    ///
    /// This struct rides the wire on node registration AND is persisted in
    /// `capabilities_json`. Without `#[serde(default)]`, a JSON blob missing
    /// this key fails deserialization OUTRIGHT — not "field is empty", the
    /// whole `SupportedAxes` fails to parse. The `byte_cipher` axis is
    /// scheduled for removal; readers must tolerate its absence BEFORE any
    /// writer stops emitting it, or every node's axes fail to parse and the
    /// picker sees an empty mesh. An empty vec reads as "this node supports
    /// no byte cipher" — the correct, conservative interpretation of an
    /// absent key.
    #[serde(default)]
    pub byte_ciphers: Vec<ByteCipherKind>,
    /// Onion handshake variants this node can serve.
    ///
    /// `#[serde(default)]` so monitors deserializing axes from an OLD node (no
    /// field in JSON) get an empty vec = "no FS support" = correctly excluded
    /// from V9-FS chains. New nodes that added the field will have it populated.
    #[serde(default)]
    pub onion_handshakes: Vec<OnionHandshakeKind>,
    /// `true` iff this node's binary hashes the client-facing label
    /// (`DeclaredIdentity::client_label`/`client_label_or_derive`) — not the
    /// real `node_id` — into its own half of `extend_fs_transcript`
    /// (`docs/mirage/plans/2026-09-25-client-facing-node-label.md`). This is
    /// the rolling-upgrade gate the monitor's `client_facing_id_for` reads
    /// before it will substitute a label for a hop's real `node_id` on any
    /// client-facing surface: a relay that has not rebuilt yet must keep
    /// receiving its real `node_id`, or the transcript hash the client sends
    /// (computed against whatever the monitor told it) stops matching what
    /// that relay itself hashes and the handshake AEAD-fails.
    ///
    /// `#[serde(default)]` so an OLD binary's serialized `capabilities_json`
    /// (which never wrote this key) decodes as `false` — the safe,
    /// conservative "still uses the real node_id" reading, never assumed
    /// true. Written unconditionally `true` by [`SupportedAxes::detect_runtime`]
    /// in every binary built after this field existed — a compile-time fact
    /// about what the binary hashes, not a runtime probe, so it is never
    /// trimmed the way OS-gated axes are.
    #[serde(default)]
    pub fs_transcript_label_capable: bool,
}

impl SupportedAxes {
    /// Detect what this runtime actually supports — conservatively trimming
    /// variants that require OS capabilities not present.
    ///
    /// Falls back to [`Self::fully_featured`] if any detection step panics,
    /// so a capability-check bug never silently drops all axes.
    pub fn detect_runtime() -> Self {
        match std::panic::catch_unwind(detect_runtime_inner) {
            Ok(axes) => axes,
            Err(_) => {
                tracing::warn!("SupportedAxes::detect_runtime panicked; falling back to fully_featured");
                Self::fully_featured()
            }
        }
    }

    /// Capabilities a fully-featured `mirage-node` build can serve.
    pub fn fully_featured() -> Self {
        Self {
            relay_modes: vec![
                RelayModeKind::Transparent,
                RelayModeKind::CryptoVerify,
                RelayModeKind::OnionPeel,
            ],
            exit_modes: vec![
                ExitModeKind::Direct,
                ExitModeKind::Onion,
                ExitModeKind::Control,
            ],
            wires_tcp: vec![TcpProtocolId::Mirage],
            wires_udp: vec![UdpProtocolId::MirageUdp],
            camouflages: vec![
                CamouflageKind::None,
                CamouflageKind::TlsReal,
                CamouflageKind::WebSocket,
                CamouflageKind::Xhttp,
                CamouflageKind::Reality,
                CamouflageKind::Quic,
                CamouflageKind::Http3,
                CamouflageKind::WireGuard,
                CamouflageKind::RawUdp,
            ],
            byte_ciphers: vec![
                ByteCipherKind::Raw,
                ByteCipherKind::ValidateFirst,
                ByteCipherKind::StripFirst,
                ByteCipherKind::ObfuscateAll,
            ],
            // BOTH handshakes, and `ForwardSecret` above all.
            //
            // This used to advertise `EphemeralStatic` alone, on the reasoning
            // that FS should only be claimed once the binary actually carried
            // the V9-FS implementation. Every binary carries it now, and the
            // reasoning inverts as soon as the non-FS path is removed: this
            // function is the PANIC FALLBACK for `detect_runtime`, and it
            // exists so that a bug in capability detection "never silently
            // drops all axes". A fallback advertising only the handshake that
            // no longer exists would do exactly that — the node would announce
            // itself as capable of nothing and be excluded from every chain,
            // silently, which is the failure this fallback is here to prevent.
            //
            // Claiming FS here is truthful, not optimistic: unlike the axes
            // `detect_runtime_inner` trims, forward secrecy needs no OS
            // capability. It is pure crypto, present exactly when the binary
            // is, so there is nothing about a running process that could make
            // it unavailable.
            onion_handshakes: vec![
                OnionHandshakeKind::EphemeralStatic,
                OnionHandshakeKind::ForwardSecret,
            ],
            // Every binary carrying this field hashes the client-facing
            // label into its FS-transcript half — same reasoning as
            // `onion_handshakes` just above: this is a fact about the
            // binary, not the OS it runs on, so the panic fallback must
            // claim it too or a detection bug would silently strand every
            // node on the real-`node_id` transcript path.
            fs_transcript_label_capable: true,
        }
    }

    /// Returns `true` if this node advertises V9-FS forward-secret onion support.
    ///
    /// The monitor topology picker calls this when building chains that use
    /// `HandshakeStrategy::Telescopic`; nodes returning `false` are excluded.
    pub fn permits_onion_fs(&self) -> bool {
        self.onion_handshakes.contains(&OnionHandshakeKind::ForwardSecret)
    }

    /// True if every kind referenced by `spec` appears in this catalog.
    pub fn permits(&self, spec: &MirageListenerSpec) -> bool {
        if let Some(layer) = spec.ingress_layer.as_ref() {
            if let Some(cipher) = layer.byte_cipher.as_ref() {
                if !self.byte_ciphers.contains(&byte_cipher_kind(cipher)) {
                    return false;
                }
            }
            if let Some(cam) = layer.camouflage.as_ref() {
                if !self.camouflages.contains(&camouflage_kind(cam)) {
                    return false;
                }
            }
        }
        true
    }
}

/// Inner implementation called inside `catch_unwind`.
fn detect_runtime_inner() -> SupportedAxes {
    let mut axes = SupportedAxes::fully_featured();

    // Icmp camouflage requires CAP_NET_RAW on Linux; unavailable on Windows.
    if !has_cap_net_raw() {
        axes.camouflages.retain(|c| !matches!(c, CamouflageKind::Icmp));
    }

    // V9-FS is pure-Rust (no OS capability required). This binary carries the full
    // V9-FS implementation, so advertise both handshake variants.
    // `onion_handshakes` is deliberately NOT set here. Both variants come from
    // `fully_featured()` and neither is trimmable — no OS capability gates
    // either — so re-stating them would be a second place for the list to live
    // and a second place for it to drift.

    axes
}

/// Returns `true` when the process can open a raw ICMP socket.
///
/// Linux: attempt `SOCK_RAW / IPPROTO_ICMP`; success means CAP_NET_RAW
/// is effective. Non-Linux: always `false` (conservative).
#[cfg(target_os = "linux")]
fn has_cap_net_raw() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn has_cap_net_raw() -> bool {
    false
}

pub fn byte_cipher_kind(m: &ByteCipherMode) -> ByteCipherKind {
    match m {
        ByteCipherMode::Raw => ByteCipherKind::Raw,
        ByteCipherMode::ValidateFirst { .. } => ByteCipherKind::ValidateFirst,
        ByteCipherMode::StripFirst { .. } => ByteCipherKind::StripFirst,
        ByteCipherMode::ObfuscateAll { .. } => ByteCipherKind::ObfuscateAll,
    }
}

pub fn camouflage_kind(c: &TransportCamouflage) -> CamouflageKind {
    match c {
        TransportCamouflage::None => CamouflageKind::None,
        TransportCamouflage::TlsReal { .. } => CamouflageKind::TlsReal,
        TransportCamouflage::WebSocket { .. } => CamouflageKind::WebSocket,
        TransportCamouflage::Xhttp { .. } => CamouflageKind::Xhttp,
        TransportCamouflage::Reality { .. } => CamouflageKind::Reality,
        TransportCamouflage::Quic { .. } => CamouflageKind::Quic,
        TransportCamouflage::Http3 { .. } => CamouflageKind::Http3,
        TransportCamouflage::Hysteria2 { .. } => CamouflageKind::Hysteria2,
        TransportCamouflage::WireGuard { .. } => CamouflageKind::WireGuard,
        TransportCamouflage::DnsTunnel { .. } => CamouflageKind::DnsTunnel,
        TransportCamouflage::Ssh { .. } => CamouflageKind::Ssh,
        TransportCamouflage::Grpc { .. } => CamouflageKind::Grpc,
        TransportCamouflage::Icmp { .. } => CamouflageKind::Icmp,
        TransportCamouflage::WebTransport { .. } => CamouflageKind::WebTransport,
        TransportCamouflage::RawUdp { .. } => CamouflageKind::RawUdp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The panic fallback must not brick a node.
    ///
    /// `detect_runtime` falls back to `fully_featured()` when capability
    /// detection panics, and the whole point of that fallback is that a
    /// detection bug "never silently drops all axes". The topology picker
    /// excludes any node whose axes lack `ForwardSecret` from telescopic
    /// chains (`permits_onion_fs`), so once the non-FS onion path is gone,
    /// a fallback that omitted it would announce a node as capable of
    /// nothing — silently, and only under a bug, which is the worst
    /// combination to debug.
    #[test]
    fn the_panic_fallback_still_advertises_forward_secrecy() {
        assert!(
            SupportedAxes::fully_featured().permits_onion_fs(),
            "the panic fallback must claim FS, or a detection bug excludes the node from every chain"
        );
        assert!(
            SupportedAxes::detect_runtime().permits_onion_fs(),
            "and so must ordinary detection, which starts from the same base"
        );
    }

    /// A JSON blob missing `byte_ciphers` (e.g. emitted by a future writer that
    /// dropped the axis, or a stale `capabilities_json` row from before the field
    /// existed) must still deserialize into `SupportedAxes`, with `byte_ciphers`
    /// read as empty rather than failing the whole struct.
    #[test]
    fn axes_json_without_byte_ciphers_parses() {
        let axes = SupportedAxes::fully_featured();
        let mut value = serde_json::to_value(&axes).expect("serialize SupportedAxes to Value");
        let obj = value.as_object_mut().expect("SupportedAxes serializes to a JSON object");
        assert!(
            obj.remove("byte_ciphers").is_some(),
            "byte_ciphers key must be present before we remove it, or this test proves nothing"
        );

        let parsed: SupportedAxes =
            serde_json::from_value(value).expect("SupportedAxes must deserialize without byte_ciphers");
        assert!(parsed.byte_ciphers.is_empty());
    }

    /// `#[serde(default)]` on `byte_ciphers` must be deserialize-only: it has no
    /// `skip_serializing_if`, so every serialized `SupportedAxes` — populated or
    /// empty — still emits the `byte_ciphers` key. Proves the change is safe to
    /// land before any reader rolls: writers keep emitting the key unchanged.
    #[test]
    fn adding_the_default_did_not_change_what_we_emit() {
        let populated = SupportedAxes::fully_featured();
        assert!(!populated.byte_ciphers.is_empty());
        let populated_value = serde_json::to_value(&populated).expect("serialize populated axes");
        assert!(populated_value.get("byte_ciphers").is_some());

        let mut empty = SupportedAxes::fully_featured();
        empty.byte_ciphers = Vec::new();
        let empty_value = serde_json::to_value(&empty).expect("serialize empty axes");
        assert_eq!(empty_value.get("byte_ciphers"), Some(&serde_json::json!([])));
    }

    /// A populated `SupportedAxes` survives a serialize -> deserialize round trip
    /// unchanged. `SupportedAxes` is a wire type without `PartialEq`, so compare
    /// the serialized JSON values rather than adding a derive to it.
    #[test]
    fn axes_round_trip() {
        let axes = SupportedAxes::fully_featured();
        let before = serde_json::to_value(&axes).expect("serialize SupportedAxes");

        let restored: SupportedAxes =
            serde_json::from_value(before.clone()).expect("deserialize SupportedAxes");
        let after = serde_json::to_value(&restored).expect("re-serialize SupportedAxes");

        assert_eq!(before, after);
    }

    /// A build carrying this field claims it — the compile-time fact
    /// [`SupportedAxes::detect_runtime`]'s own doc promises, mirroring
    /// `the_panic_fallback_still_advertises_forward_secrecy` above for the
    /// sibling `onion_handshakes` axis.
    #[test]
    fn fully_featured_and_detect_runtime_both_claim_fs_transcript_label_capable() {
        assert!(
            SupportedAxes::fully_featured().fs_transcript_label_capable,
            "the panic fallback must claim this, or a detection bug strands the node on real node_ids"
        );
        assert!(SupportedAxes::detect_runtime().fs_transcript_label_capable);
    }

    /// A JSON blob missing `fs_transcript_label_capable` (an OLD binary's
    /// serialized `capabilities_json`, predating this field) must still
    /// deserialize, reading `false` — the safe, conservative "still uses the
    /// real node_id" interpretation — never assumed `true`. Mirrors
    /// `axes_json_without_byte_ciphers_parses` for this axis.
    #[test]
    fn axes_json_without_fs_transcript_label_capable_parses_as_false() {
        let axes = SupportedAxes::fully_featured();
        let mut value = serde_json::to_value(&axes).expect("serialize SupportedAxes to Value");
        let obj = value.as_object_mut().expect("SupportedAxes serializes to a JSON object");
        assert!(
            obj.remove("fs_transcript_label_capable").is_some(),
            "the key must be present before we remove it, or this test proves nothing"
        );

        let parsed: SupportedAxes = serde_json::from_value(value)
            .expect("SupportedAxes must deserialize without fs_transcript_label_capable");
        assert!(!parsed.fs_transcript_label_capable);
    }

    /// `#[serde(default)]` here is deserialize-only, same discipline as
    /// `byte_ciphers`'s own `adding_the_default_did_not_change_what_we_emit`:
    /// every serialized `SupportedAxes` — capable or not — still emits the
    /// key, so a reader can always tell "false" from "absent".
    #[test]
    fn fs_transcript_label_capable_is_always_emitted() {
        let capable = SupportedAxes::fully_featured();
        let capable_value = serde_json::to_value(&capable).expect("serialize capable axes");
        assert_eq!(capable_value.get("fs_transcript_label_capable"), Some(&serde_json::json!(true)));

        let mut incapable = SupportedAxes::fully_featured();
        incapable.fs_transcript_label_capable = false;
        let incapable_value = serde_json::to_value(&incapable).expect("serialize incapable axes");
        assert_eq!(
            incapable_value.get("fs_transcript_label_capable"),
            Some(&serde_json::json!(false))
        );
    }
}
