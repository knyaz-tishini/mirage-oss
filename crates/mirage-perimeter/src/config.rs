//! Perimeter configuration — resolved from the sealed capsule's
//! [`CapsuleServiceConfig`], or, on a box that runs the perimeter
//! STANDALONE, from a local face list the operator wrote down. See
//! `crate::capsule_boot`'s module doc for why the capsule is the only
//! config path a FLEET service has.
//!
//! # Strict parsing, on purpose
//!
//! [`PerimeterConfig::from_capsule`] refuses the whole capsule the moment
//! ONE face is malformed. A silently-skipped face would mean this box
//! binds fewer public ports than the operator declared while every other
//! face keeps answering and the process keeps reporting healthy — the
//! exact failure mode that is invisible until someone notices a port is
//! dark. Failing the whole boot instead is loud: the perimeter waits (see
//! `capsule_boot`) and the operator fixes the one bad entry.
//!
//! # The standalone path
//!
//! [`PerimeterConfig::from_local_faces`] is that same strict parse over
//! the same face shape, for a box that has no keeper to ask, no capsule to
//! verify and no mesh to join: the standalone perimeter a user installs
//! on their own server. Both constructors run their face list through
//! the SAME [`split_faces`] parse, so "the same checks" is a structural
//! fact here and not a promise.
//!
//! What differs between the two paths is only WHERE the list came from
//! and that nothing on it is signed. What the perimeter does with the
//! list — strip the camouflage, classify the bytes, splice a wire verdict
//! inward by the face's own [`FacePurpose`] — is the same code on both
//! paths ([`crate::face::run_face`]), and there is exactly one of it.

use std::collections::HashSet;
use std::net::{AddrParseError, SocketAddr};

use mirage_core::capsule::CapsuleServiceConfig;
use mirage_core::mirage::wire::camouflage::TransportCamouflage;
use thiserror::Error;

/// Default splice target when the capsule carries no
/// `perimeter_inner_addr` — the same bare endpoint every box's monitor has
/// always listened on directly, before the perimeter existed to stand in
/// front of it.
pub const DEFAULT_INNER_ADDR: &str = "127.0.0.1:19444";
// `DEFAULT_STATS_BIND` (`127.0.0.1:19470`) is GONE, and so is the
// `stats_bind` field it fed, for the same reasons as `ssh_addr` below.
//
// Where this daemon answers questions about itself is no longer an ADDRESS
// either. It is `LocalChannel::PerimeterQuery` — a unix socket, unconditional
// on unix, with no configured alternative — and what travels on it is a typed
// `PerimeterRequest`, not an HTTP GET. `perimeter_stats_bind` in
// `CapsuleServiceConfig` is now read by nobody; it stays in the capsule type
// rather than being removed here, because dropping a field changes what every
// monitor mints and this arc's rule is one pair per step.
//
// `DEFAULT_SSH_ADDR` (`127.0.0.1:19471`) is GONE, and so is the whole
// `ssh_addr` field it fed.
//
// Where an SSH-shaped connection goes is no longer an ADDRESS this config
// resolves. It is `mirage_core::local_endpoint::LocalChannel::MshdSshSplice`
// — a unix socket on unix, unconditional, with no configured alternative and
// no way to be absent. Three things follow, all of them the point:
//
// 1. The capsule can no longer turn the operator's path off. `from_capsule`
//    used to read `perimeter_ssh_addr` and default it to `None`, so a box
//    whose capsule omitted the field dropped every SSH-shaped connection as
//    "never given the role". The operator's way in must not be a field the
//    mesh fills in.
// 2. There is no port to reach it on, from anywhere. `19471` was a loopback
//    listener like any other: in `ss -lnt`, one filter edit from public.
// 3. The destination learns WHO connected, because a socket carries
//    `SO_PEERCRED` and a preamble instead of an ephemeral port for a third
//    daemon to correlate on. See `mirage_core::perimeter_preamble`.
//
// `perimeter_ssh_addr` in `CapsuleServiceConfig` is now read by nobody. It is
// left in the capsule type rather than removed in this step: dropping a field
// changes what every monitor mints, and this arc's rule is one pair per step.

/// How long a face may spend in `strip_tcp_server` before it is treated as
/// a camouflage failure.
pub const DEFAULT_CAMO_TIMEOUT_MS: u64 = 10_000;
/// How long a face may wait for the first [`crate::classify::V9_CLIENT_HELLO_LEN`]
/// bytes to arrive, post-camouflage.
pub const DEFAULT_PEEK_TIMEOUT_MS: u64 = 10_000;
/// How long a face may spend dialling the inner monitor once a connection
/// classifies as wire.
pub const DEFAULT_INNER_DIAL_TIMEOUT_MS: u64 = 5_000;
/// Default `ts_ms` tolerance — the same 5-minute window
/// `mirage_core::identity_boot`'s `SenderProof`-style freshness checks use
/// elsewhere in this codebase.
pub const DEFAULT_MAX_SKEW_MS: u64 = 300_000;
/// Default cap on concurrently in-flight connections — PER FACE. Each
/// face's `crate::face::run_face` task owns its own semaphore sized to
/// this value, so a flood on one face cannot starve another face's budget.
pub const DEFAULT_MAX_INFLIGHT: usize = 256;
/// Default sustained accepts per second allowed from one source address, and
/// the burst it may spend at once. Same numbers the monitor's own accept gate
/// used before this budget moved out here — see `crate::ratelimit`.
pub const DEFAULT_ACCEPT_PER_IP_PER_SEC: f64 = crate::ratelimit::DEFAULT_ACCEPT_PER_IP_PER_SEC;
pub const DEFAULT_ACCEPT_BURST: f64 = crate::ratelimit::DEFAULT_ACCEPT_BURST;

/// What a face carries inward, and therefore which box-local service the
/// perimeter splices a wire verdict to.
///
/// Defined in `mirage_core::capsule` — it rides inside the signed
/// `CapsuleControlEndpoint.purpose` field, part of `DeclaredIdentity`'s
/// signed face list, so this crate re-uses that type rather than declaring
/// its own with the same name. See that type's own doc.
pub use mirage_core::capsule::FacePurpose;

/// One public port this perimeter binds, and the outer camouflage a dialer
/// must present there.
#[derive(Debug, Clone)]
pub struct PerimeterFace {
    /// TCP port to bind — on BOTH `0.0.0.0` and `[::]`, as two independent
    /// listeners; see `crate::face`'s module doc, "A face is two sockets,
    /// not one", for why a single dual-stack socket was rejected.
    pub port: u16,
    /// Outer camouflage this face strips before classification.
    pub camouflage: TransportCamouflage,
    /// Human label for logs and stats — `"<camouflage-label>:<port>"`.
    pub label: String,
    /// Which inward service a wire verdict on this face is spliced to.
    ///
    /// Defaults to [`FacePurpose::MonitorWire`] everywhere it is not stated,
    /// including on a box with no capsule, so a build carrying this field
    /// behaves exactly as one without it until a capsule says otherwise.
    pub purpose: FacePurpose,
}

/// One UDP-camouflage port this box has been told to bind — resolved by
/// [`PerimeterConfig::from_capsule`] but, as of this step, uncalled. See
/// [`PerimeterConfig::udp_faces`]'s own doc for why an unread field here is
/// not an oversight.
#[derive(Debug, Clone)]
pub struct UdpFace {
    /// UDP port to bind. Unlike [`PerimeterFace::port`], there is no
    /// TCP-style dual v4/v6 accept loop for this yet — binding is a later
    /// step (`docs/mirage/plans/udp-front-door-u0-2026-09-05.md` §6 step 4).
    pub port: u16,
    /// Outer camouflage this face will eventually strip. Narrowed to
    /// [`TransportCamouflage::RawUdp`] by [`PerimeterConfig::from_capsule`]
    /// — see that constructor's own note on why only this one variant
    /// resolves here.
    pub camouflage: TransportCamouflage,
    /// Human label for logs and stats — `"<camouflage-label>:<port>"`, the
    /// same convention as [`PerimeterFace::label`].
    pub label: String,
    /// Which inward service a wire verdict on this face would be spliced
    /// to, once something reads it. See [`PerimeterFace::purpose`].
    pub purpose: FacePurpose,
}

/// Fully resolved perimeter configuration for one boot.
#[derive(Debug, Clone)]
pub struct PerimeterConfig {
    /// Every face to bind. Never empty — see [`ConfigError::NoFaces`].
    pub faces: Vec<PerimeterFace>,
    /// Every UDP face the capsule declared, resolved but not yet bound —
    /// nothing in this crate reads this field today; the listener,
    /// dispatcher and `Surface` wiring that would bind it are a later step
    /// (`docs/mirage/plans/udp-front-door-u0-2026-09-05.md` §6 steps 4-5).
    ///
    /// An unread field that COULD be populated would normally be exactly
    /// the "reports healthy while serving fewer doors than declared"
    /// failure this module's own doctrine refuses — a face parses, nobody
    /// binds it, and the operator believes it is live. What makes it safe
    /// here, CHECKED rather than assumed: only [`TransportCamouflage::RawUdp`]
    /// resolves into this list (see [`Self::from_capsule`]), and
    /// `mirage_core::persona` — the only place a `TransportCamouflage` is
    /// minted for a real identity — contains zero references to any UDP
    /// camouflage variant. No identity can populate this list today, so it
    /// stays empty on every box that exists, until BOTH persona mints a UDP
    /// shape AND the binder (a later step) exists to serve it. If either
    /// changes on its own — persona starts minting a UDP shape before the
    /// binder lands, or a capsule with a `RawUdp` endpoint is hand-built
    /// bypassing persona — that guarantee breaks, and this comment is the
    /// tripwire for the next reader to notice it before it ships quietly.
    pub udp_faces: Vec<UdpFace>,
    /// Where a classified-as-wire connection is spliced through to.
    pub inner_addr: SocketAddr,
    // No `stats_bind`. Questions about this daemon arrive on
    // `LocalChannel::PerimeterQuery` — see the note beside the deleted
    // `DEFAULT_STATS_BIND` above.
    /// Time bound on `strip_tcp_server` per connection.
    pub camo_timeout_ms: u64,
    /// Time bound on reading the first hello bytes, post-camouflage.
    pub peek_timeout_ms: u64,
    /// Time bound on dialling `inner_addr` once a connection classifies as
    /// wire.
    pub inner_dial_timeout_ms: u64,
    /// `ts_ms` tolerance passed to [`crate::classify::classify_v9_hello`].
    pub max_skew_ms: u64,
    // No `ssh_addr`. An SSH-shaped connection goes to
    // `LocalChannel::MshdSshSplice`, always — see the note beside the
    // deleted `DEFAULT_SSH_ADDR` above.
    /// Sustained accepts per second one source address may make across ALL
    /// faces. Unlike [`Self::max_inflight`], this budget is not per face —
    /// see `crate::ratelimit`'s module doc.
    pub accept_per_ip_per_sec: f64,
    /// Burst tokens for the same budget.
    pub accept_burst: f64,
    /// Per-face concurrent-connection cap — see [`DEFAULT_MAX_INFLIGHT`]'s
    /// doc for why this is per face, not a fleet-wide total.
    pub max_inflight: usize,
    /// What each face does with a touch that is not ours — see
    /// [`crate::jail`]. Absent from a capsule means every face jails, which
    /// is the safe default: it tells an observer less than a close does.
    pub jail: crate::jail::JailConfig,
}

/// Everything that can be wrong with a capsule's perimeter configuration.
/// Every variant is a refusal to boot with a partial/ambiguous face list —
/// see this module's doc.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(
        "control_plane_endpoints is empty — this box would bind nothing on any public port \
         while reporting healthy; refusing to boot dark"
    )]
    NoFaces,
    #[error(
        "the local face list is empty — this box would bind nothing on any public port while \
         reporting healthy; refusing to boot dark"
    )]
    NoLocalFaces,
    #[error("a face declares port 0 — an ordinary public port must be explicit")]
    ZeroPort,
    #[error(
        "face on port {port} uses {camouflage} camouflage, which rides on UDP — the perimeter \
         is a TCP-only front door and cannot bind this face"
    )]
    UdpCamouflage {
        port: u16,
        camouflage: &'static str,
    },
    #[error(
        "{camouflage} face declares port {declared_port} but its own bind_addr names port \
         {camo_port} — a face whose two statements of its own port disagree must be refused, \
         not silently resolved to either one"
    )]
    UdpPortMismatch {
        declared_port: u16,
        camo_port: u16,
        camouflage: &'static str,
    },
    #[error("two faces both declare port {0} — a port can only be bound once")]
    DuplicatePort(u16),
    #[error("perimeter_inner_addr {raw:?} does not parse as a socket address: {source}")]
    BadInnerAddr {
        raw: String,
        #[source]
        source: AddrParseError,
    },
}

impl PerimeterConfig {
    /// The surface every box binds at boot — `:22`, `:80`, `:443`, every one
    /// of them [`TransportCamouflage::None`] — with no identity, no
    /// capsule, and no waiting on either. See `crate::run`'s module doc for
    /// why the surface can never be conditional on an identity: an identity
    /// arrives THROUGH this surface, so a version that waited for one
    /// before binding anything could never receive one on its own.
    ///
    /// Baseline does not pretend to be a web server on `:80`/`:443` — every
    /// face here is `None`, so it hardens the surface and passes SSH in,
    /// SSH out (`crate::face::route_ssh`, spliced to the co-located mshd)
    /// exactly as a capsule-declared face does; everything else on these
    /// three ports is refused or held (`crate::jail`), the same disposition
    /// any other face falls back to. This is not a reduced or second
    /// mechanism — `crate::run::Surface::bind_baseline` spawns the SAME
    /// `crate::face::run_face` accept loop for these faces that a
    /// capsule-declared face uses, so there is exactly one classifier and
    /// one splice in this crate, not one per boot state.
    ///
    /// A capsule's own faces are ADDED on top once identity lands
    /// (`crate::run::Surface::apply_identity_when_ready`) — persona
    /// camouflage and mesh function are what an identity buys, never a
    /// precondition for this box answering at all.
    pub fn baseline() -> Self {
        let faces = [22u16, 80, 443]
            .into_iter()
            .map(|port| PerimeterFace {
                port,
                camouflage: TransportCamouflage::None,
                label: format!("{}:{port}", TransportCamouflage::None.label()),
                // No capsule here to read a purpose from, and the baseline is
                // what a box serves before it is admitted — mesh control only.
                purpose: FacePurpose::MonitorWire,
            })
            .collect();

        Self {
            faces,
            // There is no baseline UDP face — nothing about mesh
            // bootstrapping needs one before an identity lands. See
            // `udp_faces`'s own doc; a UDP face is only ever added by
            // `from_capsule`'s capsule-driven path.
            udp_faces: Vec::new(),
            // Unwrap: a literal this module owns — every test below that
            // calls `baseline()` exercises this parse too, so a typo in
            // `DEFAULT_INNER_ADDR` fails loudly at `cargo test` time, not as
            // a runtime condition on a live box.
            inner_addr: DEFAULT_INNER_ADDR.parse().expect("DEFAULT_INNER_ADDR parses"),
            camo_timeout_ms: DEFAULT_CAMO_TIMEOUT_MS,
            peek_timeout_ms: DEFAULT_PEEK_TIMEOUT_MS,
            inner_dial_timeout_ms: DEFAULT_INNER_DIAL_TIMEOUT_MS,
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            accept_per_ip_per_sec: DEFAULT_ACCEPT_PER_IP_PER_SEC,
            accept_burst: DEFAULT_ACCEPT_BURST,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            // The safe default — every face jails absent an operator
            // override — because there is no capsule here to read one
            // from. See `jail_from_capsule`'s own doc.
            jail: crate::jail::JailConfig::default(),
        }
    }

    /// The baseline's own port set — `:22`, `:80`, `:443` — read off
    /// [`Self::baseline`] rather than duplicated as a literal.
    ///
    /// This is the guard [`crate::run::Surface::apply_config`]'s retirement
    /// checks before ever closing a port a capsule no longer declares: see
    /// this module's doc for the rule it enforces ("getting a capsule must
    /// not be able to close the door that not having one leaves open"). A
    /// second copy of `[22, 80, 443]` here would let the two drift the
    /// moment either list changes.
    pub(crate) fn baseline_ports() -> HashSet<u16> {
        Self::baseline().faces.iter().map(|f| f.port).collect()
    }

    /// Build a [`PerimeterConfig`] from the capsule's service config.
    /// Strict: see this module's doc for why a malformed face is a hard
    /// error rather than a skip.
    pub fn from_capsule(cfg: &CapsuleServiceConfig) -> Result<Self, ConfigError> {
        if cfg.control_plane_endpoints.is_empty() {
            return Err(ConfigError::NoFaces);
        }

        let candidates: Vec<PerimeterFace> = cfg
            .control_plane_endpoints
            .iter()
            .map(|endpoint| PerimeterFace {
                port: endpoint.port,
                camouflage: endpoint.camouflage.clone(),
                label: format!("{}:{}", endpoint.camouflage.label(), endpoint.port),
                // The capsule's signed `purpose` field now drives this
                // directly. `None` — every face minted before this field
                // existed, and any face left unset since — lands on
                // `FacePurpose::MonitorWire` via `unwrap_or_default`, which
                // is the exact behaviour this constructor always had: no
                // face this box has ever published changes destination
                // until an operator signs one with `purpose: Some(NodeChain)`.
                purpose: endpoint.purpose.unwrap_or_default(),
            })
            .collect();
        let (faces, udp_faces) = split_faces(candidates, PortScope::Shared)?;

        let inner_addr = parse_addr(
            cfg.perimeter_inner_addr.as_deref().unwrap_or(DEFAULT_INNER_ADDR),
            |raw, source| ConfigError::BadInnerAddr { raw, source },
        )?;
        // `cfg.perimeter_ssh_addr` is deliberately NOT read. The SSH
        // destination is a channel, not an address — see the note beside the
        // deleted `DEFAULT_SSH_ADDR`. It used to default to `None` here, so a
        // capsule that omitted the field left an identified box dropping every
        // SSH-shaped connection while an UNIDENTIFIED one (which took the
        // baseline's `Some`) let the operator in. Getting a capsule must not
        // be able to close the door that not having one leaves open.
        // `cfg.perimeter_stats_bind` is deliberately NOT read either — see
        // the note beside the deleted `DEFAULT_STATS_BIND`.

        Ok(Self {
            faces,
            udp_faces,
            inner_addr,
            camo_timeout_ms: DEFAULT_CAMO_TIMEOUT_MS,
            peek_timeout_ms: DEFAULT_PEEK_TIMEOUT_MS,
            inner_dial_timeout_ms: DEFAULT_INNER_DIAL_TIMEOUT_MS,
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            accept_per_ip_per_sec: DEFAULT_ACCEPT_PER_IP_PER_SEC,
            accept_burst: DEFAULT_ACCEPT_BURST,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            jail: jail_from_capsule(cfg),
        })
    }

    /// Build a [`PerimeterConfig`] from a face list the operator wrote down
    /// LOCALLY — the standalone path, with no capsule, no keeper and no
    /// mesh behind it.
    ///
    /// The same strict parse [`Self::from_capsule`] performs, over the same
    /// face shape, because both run their list through the same
    /// [`split_faces`]: a port may not be zero, two faces on the SAME
    /// transport may not share one port, and a UDP camouflage is refused —
    /// with the single exception of
    /// [`TransportCamouflage::RawUdp`], which resolves into
    /// [`Self::udp_faces`] exactly as it does on the capsule path.
    ///
    /// ONE rule differs from the capsule path, and only because the socket
    /// spaces differ: a TCP face and a UDP face may carry the SAME port
    /// number here. TCP 443 and UDP 443 are two different ports to the
    /// kernel, and an ordinary server serves HTTPS and QUIC side by side on
    /// one number. The capsule path keeps the old, stricter rule — see
    /// [`PortScope`].
    ///
    /// Nothing here is signed, because nothing here needs to be. A face list
    /// is not an assertion about WHO this box is; it is a list of doors the
    /// operator asked this process to open. What the perimeter does with
    /// those doors — strip the camouflage, classify the bytes, splice a wire
    /// verdict inward by the face's own [`FacePurpose`] — is the same code
    /// on both paths ([`crate::face::run_face`]), and there is exactly one
    /// of it.
    ///
    /// The jail settings are the SAFE default
    /// ([`crate::jail::JailConfig`]'s own default): a local config carries
    /// no operator jail policy, and "jail what is not ours" is the
    /// disposition that tells an observer least.
    pub fn from_local_faces(
        faces: Vec<PerimeterFace>,
        inner_addr: SocketAddr,
    ) -> Result<Self, PerimeterConfigError> {
        if faces.is_empty() {
            return Err(ConfigError::NoLocalFaces);
        }
        let (faces, udp_faces) = split_faces(faces, PortScope::PerTransport)?;
        Ok(Self {
            faces,
            udp_faces,
            inner_addr,
            camo_timeout_ms: DEFAULT_CAMO_TIMEOUT_MS,
            peek_timeout_ms: DEFAULT_PEEK_TIMEOUT_MS,
            inner_dial_timeout_ms: DEFAULT_INNER_DIAL_TIMEOUT_MS,
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            accept_per_ip_per_sec: DEFAULT_ACCEPT_PER_IP_PER_SEC,
            accept_burst: DEFAULT_ACCEPT_BURST,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            // The safe default — every face jails absent an operator
            // override — because a local face list carries no jail policy
            // to read one from. See `jail_from_capsule`'s own doc.
            jail: crate::jail::JailConfig::default(),
        })
    }
}

/// The error both [`PerimeterConfig`] constructors return.
///
/// The same type as [`ConfigError`] under the name this module's own
/// history gave it: one error, two spellings, so neither the existing
/// `ConfigError` nor the `PerimeterConfigError` a caller reaches for
/// breaks.
pub type PerimeterConfigError = ConfigError;

/// Whether one port number may be claimed by both a TCP face and a UDP face.
///
/// TCP and UDP have SEPARATE socket spaces: to the kernel, TCP 443 and
/// UDP 443 are two different ports, and one box may listen on both at
/// once. Whether a configuration is ALLOWED to say so is a policy of that
/// configuration, not of the kernel:
///
/// * [`PortScope::Shared`] — the capsule path. One capsule naming one port
///   on both transports is refused, and that rule is left exactly as it
///   was: the fleet's capsules are signed documents, and their face list
///   does not change here.
/// * [`PortScope::PerTransport`] — the standalone path. The operator's own
///   box publishes a TCP 443 face and a UDP 443 face side by side, the way
///   an ordinary server serves HTTPS and QUIC on the same number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortScope {
    /// One port number across both transports — the capsule rule.
    Shared,
    /// One port number per transport — the standalone rule.
    PerTransport,
}

/// Claim `port` for a face on one transport, or report it as already claimed.
///
/// Under [`PortScope::Shared`] the two sets are kept in step, so a port a
/// UDP face claimed is refused for a TCP face too — the capsule rule,
/// unchanged. Under [`PortScope::PerTransport`] each transport keeps its
/// own set, which is what the kernel itself keeps: TCP 443 and UDP 443 do
/// not collide.
fn claim_port(
    scope: PortScope,
    seen_tcp: &mut HashSet<u16>,
    seen_udp: &mut HashSet<u16>,
    port: u16,
    udp: bool,
) -> bool {
    match (scope, udp) {
        (PortScope::Shared, true) => seen_udp.insert(port) && seen_tcp.insert(port),
        (PortScope::Shared, false) => seen_tcp.insert(port) && seen_udp.insert(port),
        (PortScope::PerTransport, true) => seen_udp.insert(port),
        (PortScope::PerTransport, false) => seen_tcp.insert(port),
    }
}

/// Split a face list into the TCP faces this perimeter binds and the UDP
/// faces it resolves but cannot serve yet.
///
/// The one parse both [`PerimeterConfig::from_capsule`] and
/// [`PerimeterConfig::from_local_faces`] run their list through, so the two
/// constructors cannot drift apart on what a valid face is.
///
/// Strict, for the reason this module's doc gives: one malformed face
/// refuses the whole list rather than quietly binding fewer doors than
/// were declared.
///
/// The two constructors differ in ONE thing: `scope`, which decides whether
/// the same port number may be claimed once on TCP and once on UDP. The
/// capsule path keeps the old, stricter rule; the standalone path allows
/// the pair, because TCP and UDP are separate socket spaces.
fn split_faces(
    faces: Vec<PerimeterFace>,
    scope: PortScope,
) -> Result<(Vec<PerimeterFace>, Vec<UdpFace>), ConfigError> {
    let mut seen_tcp: HashSet<u16> = HashSet::with_capacity(faces.len());
    let mut seen_udp: HashSet<u16> = HashSet::with_capacity(faces.len());
    let mut tcp_faces = Vec::with_capacity(faces.len());
    let mut udp_faces = Vec::new();
    for face in faces {
        if face.port == 0 {
            return Err(ConfigError::ZeroPort);
        }

        // `RawUdp` alone resolves into a UDP face. Its wire shape — no
        // outer wrapper, a bare V9 hello that fits one datagram — is the
        // only one of the seven UDP camouflages that already matches
        // what `core::udp_handshake`/`core::udp_tunnel` carry end to end
        // as whole datagrams. The other six are today served by taking a
        // byte stream off their camouflage layer and running the STREAM
        // handshake over it; rewriting them onto real datagrams is later
        // work (U6 — see `udp_faces`'s own doc for the plan reference).
        // Refusing them here is not forgetting them; it is refusing to
        // promise a door nothing can serve yet.
        if let TransportCamouflage::RawUdp { bind_addr } = &face.camouflage {
            if bind_addr.port() != face.port {
                return Err(ConfigError::UdpPortMismatch {
                    declared_port: face.port,
                    camo_port: bind_addr.port(),
                    camouflage: face.camouflage.label(),
                });
            }
            if !claim_port(scope, &mut seen_tcp, &mut seen_udp, face.port, true) {
                return Err(ConfigError::DuplicatePort(face.port));
            }
            udp_faces.push(UdpFace {
                port: face.port,
                camouflage: face.camouflage.clone(),
                label: face.label.clone(),
                purpose: face.purpose,
            });
            continue;
        }

        if face.camouflage.is_udp() {
            return Err(ConfigError::UdpCamouflage {
                port: face.port,
                camouflage: face.camouflage.label(),
            });
        }
        if !claim_port(scope, &mut seen_tcp, &mut seen_udp, face.port, false) {
            return Err(ConfigError::DuplicatePort(face.port));
        }
        tcp_faces.push(face);
    }
    Ok((tcp_faces, udp_faces))
}

/// Resolve the jail settings from the capsule.
///
/// Deliberately NOT strict, unlike the face list above. A face list that
/// cannot be parsed means the box would bind the wrong ports, so the whole
/// boot is refused; a jail setting that cannot be parsed means one port
/// treats a prober slightly differently from what the operator intended, and
/// refusing to boot the box's only public listener over that is a far worse
/// outcome than falling back to the safe disposition. Unrecognised spellings
/// resolve to `Jail` in `Disposition::from_tag`.
fn jail_from_capsule(cfg: &CapsuleServiceConfig) -> crate::jail::JailConfig {
    let mut jail = crate::jail::JailConfig {
        default_disposition: cfg
            .perimeter_jail_default
            .as_deref()
            .map(crate::jail::Disposition::from_tag)
            .unwrap_or_default(),
        ..Default::default()
    };
    for f in &cfg.perimeter_jail_faces {
        jail
            .per_face
            .insert(f.port, crate::jail::Disposition::from_tag(&f.disposition));
    }
    if let Some(ms) = cfg.perimeter_jail_hold_ms {
        jail.hold_ms = ms;
    }
    if let Some(n) = cfg.perimeter_jail_max_held_per_face {
        jail.max_held_per_face = n;
    }
    jail
}

fn parse_addr(
    raw: &str,
    to_err: impl FnOnce(String, AddrParseError) -> ConfigError,
) -> Result<SocketAddr, ConfigError> {
    raw.parse().map_err(|source| to_err(raw.to_string(), source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::capsule::CapsuleControlEndpoint;

    fn tls_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::TlsReal {
                sni: "edge-static.net".into(),
                alpn: vec!["h2".into()],
            },
            wire_version: Some(9),
            purpose: None,
        }
    }

    /// Same shape as [`tls_endpoint`], but with the signed `purpose` field
    /// explicitly set to `NodeChain` — used to prove `from_capsule` maps a
    /// declared chain face onto [`FacePurpose::NodeChain`] rather than the
    /// default.
    fn chain_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::TlsReal {
                sni: "edge-static.net".into(),
                alpn: vec!["h2".into()],
            },
            wire_version: Some(9),
            purpose: Some(FacePurpose::NodeChain),
        }
    }

    fn udp_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::WireGuard {
                magic_byte: 0x05,
                junk_count: 3,
                junk_min: 16,
                junk_max: 64,
                bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    /// `RawUdp` with `bind_addr`'s port equal to `port` — the one UDP
    /// camouflage `from_capsule` resolves rather than refuses.
    fn raw_udp_endpoint(port: u16, bind_port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{bind_port}").parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    fn quic_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::Quic {
                alpn: vec!["h3".into()],
                bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    fn http3_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::Http3 {
                authority: "edge-static.net".into(),
                tunnel_path: "/tunnel".into(),
                alpn: "h3".into(),
                bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    fn hysteria2_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::Hysteria2 {
                psk_hex: "deadbeef".into(),
                bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    fn web_transport_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::WebTransport {
                path: "/wt".into(),
                authority: "edge-static.net".into(),
                bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    fn dns_tunnel_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::DnsTunnel {
                domain: "tunnel.example".into(),
                dns_server: "1.1.1.1:53".parse().expect("valid dns server addr"),
                encoding: "base32".into(),
                query_type: "TXT".into(),
            },
            wire_version: None,
            purpose: None,
        }
    }

    /// The baseline is what every box answers on before any identity —
    /// `:22`, `:80`, `:443`, all `None` camouflage. Two ways to break it,
    /// both pinned here: losing a port (the surface is no longer what
    /// `crate::run`'s doc promises it is before identity) and a face
    /// carrying real camouflage (baseline never pretends to be anything —
    /// that is what a capsule's own faces add on top).
    #[test]
    fn baseline_binds_22_80_443_with_no_camouflage() {
        let baseline = PerimeterConfig::baseline();

        let ports: Vec<u16> = baseline.faces.iter().map(|f| f.port).collect();
        assert_eq!(ports, vec![22, 80, 443]);
        assert!(
            baseline.faces.iter().all(|f| f.camouflage == TransportCamouflage::None),
            "the baseline never wears a disguise — that is what a capsule adds"
        );
        assert_eq!(baseline.faces[0].label, "none:22");
        assert_eq!(baseline.faces[1].label, "none:80");
        assert_eq!(baseline.faces[2].label, "none:443");
    }

    /// The baseline still routes SSH-shaped bytes to mshd's fixed local
    /// channel exactly like a capsule-declared face — there is no
    /// `ssh_addr` left to pin (see this module's doc), so what is provable
    /// here is that the constructor still resolves to a jail-configured,
    /// non-empty face list rather than an empty or malformed one.
    #[test]
    fn baseline_carries_the_safe_default_jail() {
        let baseline = PerimeterConfig::baseline();
        assert_eq!(baseline.jail.default_disposition, crate::jail::Disposition::Jail);
        assert!(!baseline.faces.is_empty());
    }

    /// [`PerimeterConfig::baseline_ports`] must name exactly the ports
    /// [`PerimeterConfig::baseline`] itself binds — a retirement guard read
    /// from a set that has drifted from the surface it is meant to protect
    /// would be worse than no guard at all.
    #[test]
    fn baseline_ports_matches_the_baseline_face_list() {
        let expected: HashSet<u16> = PerimeterConfig::baseline().faces.iter().map(|f| f.port).collect();
        assert_eq!(PerimeterConfig::baseline_ports(), expected);
        assert_eq!(PerimeterConfig::baseline_ports(), HashSet::from([22, 80, 443]));
    }

    #[test]
    fn empty_endpoint_list_is_refused() {
        let cfg = CapsuleServiceConfig::default();
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::NoFaces), "got {err:?}");
    }

    #[test]
    fn zero_port_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(0));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ZeroPort), "got {err:?}");
    }

    /// `RawUdp` is the one exception to the six tests below it — see
    /// `raw_udp_face_parses_into_udp_faces`. This one (`WireGuard`) is one
    /// of the six that still refuse; named individually, alongside its five
    /// siblings further down, rather than a representative sample — this is
    /// exactly the kind of list where one silently falling through is the
    /// bug.
    #[test]
    fn udp_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(udp_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn quic_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(quic_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn http3_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(http3_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn hysteria2_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(hysteria2_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn web_transport_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(web_transport_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn dns_tunnel_camouflage_face_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(dns_tunnel_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
    }

    /// The one exception: `RawUdp`'s wire shape already matches what the
    /// datagram handshake and tunnel carry, so it resolves into
    /// `udp_faces` instead of being refused, and must NOT also land in the
    /// TCP `faces` list.
    #[test]
    fn raw_udp_face_parses_into_udp_faces() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(raw_udp_endpoint(9000, 9000));
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("RawUdp alone must parse");
        assert_eq!(resolved.udp_faces.len(), 1);
        assert_eq!(resolved.udp_faces[0].port, 9000);
        assert!(
            resolved.faces.iter().all(|f| f.port != 9000),
            "a RawUdp face must not land in the TCP faces list"
        );
    }

    /// `RawUdp` carries its own `bind_addr`, which can disagree with the
    /// endpoint's declared port — a face whose two statements of its own
    /// port disagree must be refused rather than silently resolved to one
    /// of them.
    #[test]
    fn raw_udp_face_with_mismatched_bind_port_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(raw_udp_endpoint(9000, 9001));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::UdpPortMismatch {
                    declared_port: 9000,
                    camo_port: 9001,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn duplicate_port_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePort(443)), "got {err:?}");
    }

    #[test]
    fn one_bad_face_refuses_the_whole_list_even_with_good_faces_present() {
        // The strict-parse invariant this module's doc is about: a good
        // face earlier in the list must not mask a bad one later in it.
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.control_plane_endpoints.push(tls_endpoint(0));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ZeroPort), "got {err:?}");
    }

    #[test]
    fn defaults_apply_when_addrs_are_absent() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("valid config");
        assert_eq!(resolved.faces.len(), 1);
        assert_eq!(resolved.inner_addr, DEFAULT_INNER_ADDR.parse::<SocketAddr>().unwrap());
        assert_eq!(resolved.camo_timeout_ms, DEFAULT_CAMO_TIMEOUT_MS);
        assert_eq!(resolved.peek_timeout_ms, DEFAULT_PEEK_TIMEOUT_MS);
        assert_eq!(resolved.inner_dial_timeout_ms, DEFAULT_INNER_DIAL_TIMEOUT_MS);
        assert_eq!(resolved.max_skew_ms, DEFAULT_MAX_SKEW_MS);
        assert_eq!(resolved.max_inflight, DEFAULT_MAX_INFLIGHT);
    }

    #[test]
    fn explicit_addrs_override_defaults() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.perimeter_inner_addr = Some("127.0.0.1:29444".to_string());
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("valid config");
        assert_eq!(resolved.inner_addr, "127.0.0.1:29444".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn malformed_inner_addr_is_refused() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.perimeter_inner_addr = Some("not-an-addr".to_string());
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::BadInnerAddr { .. }), "got {err:?}");
    }

    #[test]
    fn a_capsule_cannot_put_this_daemon_back_on_a_port() {
        // `perimeter_stats_bind` used to name a loopback listener. It is
        // read by nobody now — the channel is a socket the capsule has no
        // say over — and a capsule carrying the field (every box's does,
        // and will until the field is retired from the type) must not
        // refuse the boot, resolve to anything, or reopen `:19470`.
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.perimeter_stats_bind = Some("also-not-an-addr".to_string());
        let resolved = PerimeterConfig::from_capsule(&cfg)
            .expect("a field nobody reads cannot make a capsule invalid");
        assert_eq!(resolved.faces.len(), 1);
        assert_eq!(
            mirage_core::local_endpoint::LocalChannel::PerimeterQuery.unix_path(),
            "/run/mirage/perimeter/query.sock",
            "the query channel is a path, not an address a capsule supplies"
        );
    }

    #[test]
    fn multiple_distinct_faces_all_survive() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.control_plane_endpoints.push(tls_endpoint(80));
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("valid config");
        assert_eq!(resolved.faces.len(), 2);
        assert_eq!(resolved.faces[0].label, "tls_real:443");
        assert_eq!(resolved.faces[1].label, "tls_real:80");
    }

    /// The dormancy guarantee this whole change rests on: a face with no
    /// `purpose` on the wire — every face published before this field
    /// existed, and any face an operator has not touched since — must land
    /// on `MonitorWire`. If this ever resolved to anything else, every box
    /// already in the fleet would change destination the next time its
    /// capsule was merely re-signed.
    #[test]
    fn absent_purpose_resolves_to_monitor_wire() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("valid config");
        assert_eq!(resolved.faces[0].purpose, FacePurpose::MonitorWire);
    }

    /// The other half of the mapping: an operator who signs a face with
    /// `purpose: Some(NodeChain)` gets a `PerimeterFace` that actually
    /// carries `NodeChain`, not silently coerced back to the default.
    #[test]
    fn declared_chain_purpose_survives_into_the_face() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(chain_endpoint(443));
        let resolved = PerimeterConfig::from_capsule(&cfg).expect("valid config");
        assert_eq!(resolved.faces[0].purpose, FacePurpose::NodeChain);
    }

    // ── the STANDALONE path — `from_local_faces` ──
    //
    // The standalone constructor is the same strict parse over the same
    // face shape, so these tests are the capsule tests above with the
    // capsule replaced by a list the operator wrote down. Where the two
    // paths must agree, they agree BY CONSTRUCTION — both run
    // `split_faces` — and these are the tests that pin that.

    /// The address a standalone face list splices inward to. A loopback
    /// address, like every other address in this crate's tests: the
    /// perimeter must never point at anything off this box.
    fn local_inner() -> SocketAddr {
        "127.0.0.1:29444".parse().expect("valid addr")
    }

    /// One local face — the same struct the capsule path resolves into, so
    /// the same helper shape serves both.
    fn local_face(port: u16, purpose: FacePurpose) -> PerimeterFace {
        PerimeterFace {
            port,
            camouflage: TransportCamouflage::None,
            label: format!("none:{port}"),
            purpose,
        }
    }

    /// One local UDP face — `RawUdp`, the one UDP camouflage the perimeter
    /// serves as a whole datagram, with its `bind_addr` naming the same
    /// port the face declares (as the parse demands).
    fn local_udp_face(port: u16, purpose: FacePurpose) -> PerimeterFace {
        PerimeterFace {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{port}").parse().expect("valid bind addr"),
            },
            label: format!("raw_udp:{port}"),
            purpose,
        }
    }

    /// A local face list builds the same config the capsule path builds —
    /// the faces, the inner address and the safe default jail, with no
    /// capsule and no keeper anywhere in it.
    #[test]
    fn local_faces_build_a_config() {
        let cfg = PerimeterConfig::from_local_faces(
            vec![
                local_face(443, FacePurpose::MonitorWire),
                local_face(8443, FacePurpose::NodeChain),
            ],
            local_inner(),
        )
        .expect("a local face list must parse");

        let ports: Vec<u16> = cfg.faces.iter().map(|f| f.port).collect();
        assert_eq!(ports, vec![443, 8443]);
        assert_eq!(cfg.faces[1].purpose, FacePurpose::NodeChain);
        assert_eq!(cfg.inner_addr, local_inner());
        assert!(cfg.udp_faces.is_empty());
        assert_eq!(
            cfg.jail.default_disposition,
            crate::jail::Disposition::Jail,
            "a local face list carries no jail policy, so the SAFE default stands"
        );
    }

    /// Two faces on one port would leave the second one retrying a bind
    /// forever while the process reported healthy — the exact failure this
    /// module's doc refuses. Refused, on the standalone path too.
    #[test]
    fn two_local_faces_on_one_port_are_refused() {
        let err = PerimeterConfig::from_local_faces(
            vec![
                local_face(443, FacePurpose::MonitorWire),
                local_face(443, FacePurpose::NodeChain),
            ],
            local_inner(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePort(443)), "got {err:?}");
    }

    /// The standalone box publishes HTTPS and QUIC side by side: a TCP 443
    /// face and a UDP 443 face, one port NUMBER on two transports. TCP and
    /// UDP are separate socket spaces, so this is two doors, not one door
    /// opened twice — and the kernel binds them independently.
    #[test]
    fn a_local_tcp_face_and_a_local_udp_face_may_share_one_port_number() {
        let cfg = PerimeterConfig::from_local_faces(
            vec![
                local_face(443, FacePurpose::NodeChain),
                local_udp_face(443, FacePurpose::NodeChain),
            ],
            local_inner(),
        )
        .expect("TCP 443 and UDP 443 are two different ports to the kernel");

        let tcp: Vec<u16> = cfg.faces.iter().map(|f| f.port).collect();
        let udp: Vec<u16> = cfg.udp_faces.iter().map(|f| f.port).collect();
        assert_eq!(tcp, vec![443]);
        assert_eq!(udp, vec![443]);
    }

    /// The rule above is per TRANSPORT: two UDP faces on one number are
    /// still two faces on one port, and the second one would retry its bind
    /// forever while the process reported healthy.
    #[test]
    fn two_local_udp_faces_on_one_port_are_refused() {
        let err = PerimeterConfig::from_local_faces(
            vec![
                local_udp_face(443, FacePurpose::NodeChain),
                local_udp_face(443, FacePurpose::MonitorWire),
            ],
            local_inner(),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePort(443)), "got {err:?}");
    }

    /// The fleet's own path does NOT get the relaxation: one capsule naming
    /// one port on both transports is refused exactly as it was before the
    /// standalone path changed. A signed capsule's face list is not touched
    /// by this crate.
    #[test]
    fn the_capsule_path_still_refuses_one_port_on_both_transports() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(tls_endpoint(443));
        cfg.control_plane_endpoints.push(raw_udp_endpoint(443, 443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePort(443)), "got {err:?}");
    }

    /// And the capsule path still refuses two UDP faces on one number, for
    /// the same reason it always did.
    #[test]
    fn the_capsule_path_still_refuses_two_udp_faces_on_one_port() {
        let mut cfg = CapsuleServiceConfig::default();
        cfg.control_plane_endpoints.push(raw_udp_endpoint(443, 443));
        cfg.control_plane_endpoints.push(raw_udp_endpoint(443, 443));
        let err = PerimeterConfig::from_capsule(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePort(443)), "got {err:?}");
    }

    /// A UDP camouflage is refused on the standalone path exactly as it is
    /// on the capsule path — and the refusal says WHY, because "your face
    /// list is wrong" without a reason is not an operator-facing message.
    #[test]
    fn a_udp_camouflage_on_a_local_face_is_refused_with_a_reason() {
        let err = PerimeterConfig::from_local_faces(
            vec![PerimeterFace {
                port: 443,
                camouflage: TransportCamouflage::Quic {
                    alpn: vec!["h3".into()],
                    bind_addr: "0.0.0.0:0".parse().expect("valid bind addr"),
                },
                label: "quic:443".into(),
                purpose: FacePurpose::MonitorWire,
            }],
            local_inner(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::UdpCamouflage { port: 443, .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("UDP"),
            "the refusal has to say why: {err}"
        );
    }

    /// An empty local face list is refused for the same reason an empty
    /// capsule is: this box would bind nothing on any public port while
    /// reporting healthy.
    #[test]
    fn an_empty_local_face_list_is_refused() {
        let err = PerimeterConfig::from_local_faces(Vec::new(), local_inner()).unwrap_err();
        assert!(matches!(err, ConfigError::NoLocalFaces), "got {err:?}");
    }

    /// A zero port is refused on the standalone path too — "port 0" is not
    /// a port a perimeter can bind, it is a request for "any port".
    #[test]
    fn a_zero_port_on_a_local_face_is_refused() {
        let err =
            PerimeterConfig::from_local_faces(vec![local_face(0, FacePurpose::MonitorWire)], local_inner())
                .unwrap_err();
        assert!(matches!(err, ConfigError::ZeroPort), "got {err:?}");
    }

    /// `RawUdp` is the ONE UDP camouflage that resolves rather than being
    /// refused, on the capsule path — and on the standalone path too, into
    /// the same `udp_faces` list the capsule path fills.
    #[test]
    fn a_raw_udp_local_face_resolves_into_udp_faces() {
        let cfg = PerimeterConfig::from_local_faces(
            vec![PerimeterFace {
                port: 443,
                camouflage: TransportCamouflage::RawUdp {
                    bind_addr: "0.0.0.0:443".parse().expect("valid bind addr"),
                },
                label: "raw_udp:443".into(),
                purpose: FacePurpose::MonitorWire,
            }],
            local_inner(),
        )
        .expect("raw_udp is the one UDP shape that resolves");
        assert!(cfg.faces.is_empty(), "a UDP face is not a TCP face");
        assert_eq!(cfg.udp_faces.len(), 1);
        assert_eq!(cfg.udp_faces[0].port, 443);
        assert_eq!(cfg.udp_faces[0].purpose, FacePurpose::MonitorWire);
    }

    /// The two constructors must not drift: the SAME face list must be
    /// accepted by one exactly as by the other, and the SAME broken list
    /// refused by one exactly as by the other. This is the test that says
    /// "the same checks" out loud, with both paths in one frame.
    #[test]
    fn the_two_constructors_refuse_the_same_broken_list() {
        let broken = vec![
            local_face(443, FacePurpose::MonitorWire),
            local_face(443, FacePurpose::MonitorWire),
        ];

        let mut capsule = CapsuleServiceConfig::default();
        capsule
            .control_plane_endpoints
            .push(CapsuleControlEndpoint {
                port: 443,
                camouflage: TransportCamouflage::None,
                wire_version: None,
                purpose: None,
            });
        capsule
            .control_plane_endpoints
            .push(CapsuleControlEndpoint {
                port: 443,
                camouflage: TransportCamouflage::None,
                wire_version: None,
                purpose: None,
            });

        assert!(matches!(
            PerimeterConfig::from_capsule(&capsule).unwrap_err(),
            ConfigError::DuplicatePort(443)
        ));
        assert!(matches!(
            PerimeterConfig::from_local_faces(broken, local_inner()).unwrap_err(),
            ConfigError::DuplicatePort(443)
        ));
    }
}
