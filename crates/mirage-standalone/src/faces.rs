//! Face proposal — what this box can offer, and what it cannot.
//!
//! The set of faces a standalone box publishes is a **human** decision: the
//! person who owns the box looks at what the box could carry and picks. The
//! machine's job is narrower and stated here exactly: it **detects** which
//! ports are free on the box and it **proposes** a set — it never takes the
//! choice away.
//!
//! # What the proposal is made of
//!
//! Two kinds of thing, held by two different processes, and they must not be
//! mixed:
//!
//! * **A perimeter face** — a TCP port the perimeter binds and classifies.
//!   Its mask is the port's own protocol (443 is TLS, 80 is a WebSocket, and
//!   so on): the same rule the fleet's persona follows.
//! * **A node UDP endpoint** — a UDP port the NODE holds, wearing a real UDP
//!   mask (QUIC on 443 is the everyday case). The mask is an outer wrapper:
//!   real QUIC outside, Mirage inside.
//!
//! The perimeter's own **datagram door** (`RawUdp`) is a third thing again:
//! the perimeter binds that port itself and relays whole datagrams. It is not
//! what this module proposes, and the perimeter refuses every other UDP
//! camouflage for exactly that reason.
//!
//! # The rules the proposal obeys
//!
//! * **Port 22 is never proposed.** The box's own standard SSH answers
//!   there; a face on 22 would fight the operator's own login.
//! * **One port number may be claimed once per transport.** TCP 443 and
//!   UDP 443 are two different ports to the kernel, and an ordinary server
//!   serves HTTPS and QUIC on the same number.
//! * **A busy port is not proposed** — the same face is offered on another
//!   port instead, with the reason spelled out.
//! * **A port the detector cannot judge is still proposed**, but the reason
//!   says so. "I could not check" is not "it is busy", and pretending
//!   otherwise would hide a real service behind a false refusal.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;

use mirage_core::mirage::wire::TransportCamouflage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The transport a face speaks on.
///
/// TCP and UDP are separate socket spaces: the kernel keeps one port space
/// per transport, and a box may hold the same NUMBER on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// A stream face, held by the perimeter.
    Tcp,
    /// A datagram face, held by the node.
    Udp,
}

impl Transport {
    /// The transport's own name, as it appears in the proposal file.
    pub fn label(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// What the detector knows about one port on one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Nothing holds it — the box may take it.
    Free,
    /// Something already holds it.
    Taken,
    /// The detector could not tell.
    ///
    /// Either there is no `/proc/net` to read (Windows, a container without
    /// it mounted) or the box would not even let the detector bind the port
    /// to test it. This is NOT "busy": a face on such a port may still come
    /// up fine, and refusing it would be refusing on a guess.
    Unknown,
}

/// The detector the proposal asks about ports.
///
/// A trait, so the proposal can be tested against a fixed answer instead of
/// against whatever this build machine happens to be listening on.
pub trait PortDetector {
    /// What is known about `port` on `transport`.
    fn state(&self, port: u16, transport: Transport) -> PortState;
}

/// The detector that asks THIS box.
///
/// Two sources, and the order between them is not arbitrary:
///
/// * A **privileged** port (below 1024) cannot be bound just to test it
///   without `CAP_NET_BIND_SERVICE`, so for those the kernel's own table
///   (`/proc/net/tcp`, `/proc/net/tcp6`) is the only honest source. Both
///   files are read: a service listening on `[::]:443` shows up only in the
///   IPv6 table, and it holds the IPv4 port too.
/// * Every other port is tested by **binding it** — the most direct answer
///   there is. The socket is dropped again immediately, so the test leaves
///   nothing behind.
///
/// When `/proc` cannot be read at all, the bind test is the fallback for
/// privileged ports too, and a permission failure there is reported as
/// [`PortState::Unknown`] rather than as "busy".
#[derive(Debug, Clone, Copy, Default)]
pub struct HostPortDetector;

impl PortDetector for HostPortDetector {
    fn state(&self, port: u16, transport: Transport) -> PortState {
        match transport {
            Transport::Tcp => tcp_state(port),
            Transport::Udp => udp_state(port),
        }
    }
}

/// The TCP state of one port on this box.
fn tcp_state(port: u16) -> PortState {
    if port < 1024 {
        if let Some(ports) = proc_ports(&["/proc/net/tcp", "/proc/net/tcp6"], true) {
            return if ports.contains(&port) {
                PortState::Taken
            } else {
                PortState::Free
            };
        }
    }
    match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
        Ok(listener) => {
            drop(listener);
            PortState::Free
        }
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => PortState::Taken,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => PortState::Unknown,
        Err(_) => PortState::Unknown,
    }
}

/// The UDP state of one port on this box.
fn udp_state(port: u16) -> PortState {
    if port < 1024 {
        if let Some(ports) = proc_ports(&["/proc/net/udp", "/proc/net/udp6"], false) {
            return if ports.contains(&port) {
                PortState::Taken
            } else {
                PortState::Free
            };
        }
    }
    match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
        Ok(socket) => {
            drop(socket);
            PortState::Free
        }
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => PortState::Taken,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => PortState::Unknown,
        Err(_) => PortState::Unknown,
    }
}

/// The ports the kernel's own tables report as held.
///
/// `None` when none of the files could be read — the honest "I cannot tell"
/// answer, on a system with no `/proc` at all.
///
/// `listening_only` picks what counts as held: for TCP only a socket in
/// `LISTEN` holds the port for a server, while for UDP any socket bound to
/// the port holds it.
fn proc_ports(paths: &[&str], listening_only: bool) -> Option<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    let mut read_any = false;
    for path in paths {
        let Ok(text) = std::fs::read_to_string(Path::new(path)) else {
            continue;
        };
        read_any = true;
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _sl = fields.next();
            let Some(local) = fields.next() else {
                continue;
            };
            let _remote = fields.next();
            let Some(state) = fields.next() else {
                continue;
            };
            if listening_only && state != "0A" {
                continue;
            }
            let Some((_, port_hex)) = local.rsplit_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            ports.insert(port);
        }
    }
    if read_any {
        Some(ports)
    } else {
        None
    }
}

/// What the detector says about one port on one transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortReport {
    /// The port asked about.
    pub port: u16,
    /// The transport asked about.
    pub transport: Transport,
    /// What the detector knows.
    pub state: PortState,
}

/// Ask the detector about a set of ports, on both transports.
///
/// The report is the raw answer — one row per `(port, transport)` pair — and
/// it is what [`propose`] reads, so an operator can see WHY a port was or
/// was not offered.
pub fn detect_free_ports(detector: &dyn PortDetector, ports: &[u16]) -> Vec<PortReport> {
    let mut reports = Vec::with_capacity(ports.len() * 2);
    for &port in ports {
        for transport in [Transport::Tcp, Transport::Udp] {
            reports.push(PortReport {
                port,
                transport,
                state: detector.state(port, transport),
            });
        }
    }
    reports
}

/// One face this box could publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedFace {
    /// The port the face would sit on.
    pub port: u16,
    /// The transport the face would speak on.
    pub transport: Transport,
    /// The mask the face would wear.
    pub mask: TransportCamouflage,
    /// Why this face is being offered — in the operator's own language.
    ///
    /// This is the sentence a person reads before deciding, so it says the
    /// thing that matters: what the port looks like from outside, and — when
    /// the port was not the one first in mind — what happened to it.
    pub why: String,
}

/// The shape a face wears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Real TLS 1.3.
    Tls,
    /// HTTP/1.1 WebSocket.
    WebSocket,
    /// HTTP/1.1 `Upgrade` to a raw stream.
    Xhttp,
    /// Real QUIC (UDP + TLS 1.3), held by the node.
    Quic,
}

/// One candidate face, and what to do when its port is busy.
struct Candidate {
    transport: Transport,
    port: u16,
    shape: Shape,
    /// Where the same face goes when its own port is busy.
    alternatives: &'static [u16],
    /// The sentence for a free port.
    why_free: &'static str,
    /// The sentence for a busy port, with `{port}` for the one offered.
    why_moved: &'static str,
    /// The sentence for a port the detector could not judge.
    why_unknown: &'static str,
}

/// The faces a standalone box is offered, in the order they are offered.
///
/// The set is what an ORDINARY server on the internet looks like: HTTPS on
/// 443, HTTP on 80, and the UDP port where QUIC usually lives — 443 as
/// well, because TCP and UDP are separate socket spaces. Two more TCP doors
/// (8080 behind a gateway, 8443 as a second HTTPS) make the box look like a
/// small server rather than a one-door host.
///
/// **Port 22 is never in this list.** The box's own standard SSH answers
/// there, and a face on 22 would fight the operator's own login.
const CANDIDATES: &[Candidate] = &[
    Candidate {
        transport: Transport::Tcp,
        port: 443,
        shape: Shape::Tls,
        alternatives: &[8443, 2083, 2087, 10000],
        why_free: "443/TCP — главный HTTPS-порт: обычный сервер отвечает на нём настоящим TLS, \
                   поэтому снаружи это просто сайт.",
        why_moved: "443/TCP уже занят на этом хосте, поэтому тот же настоящий TLS предложен на \
                    {port}/TCP — обычная альтернатива HTTPS.",
        why_unknown: "443/TCP — главный HTTPS-порт (настоящий TLS). Занятость проверить не \
                      удалось: нет /proc/net или не хватает прав, поэтому порт предложен, но \
                      не подтверждён.",
    },
    Candidate {
        transport: Transport::Tcp,
        port: 80,
        shape: Shape::WebSocket,
        alternatives: &[3000, 5000],
        why_free: "80/TCP — обычный HTTP-порт: трафик выглядит как WebSocket поверх HTTP/1.1, \
                   как на живом сайте.",
        why_moved: "80/TCP уже занят на этом хосте, поэтому тот же WebSocket предложен на \
                    {port}/TCP.",
        why_unknown: "80/TCP — обычный HTTP-порт (WebSocket поверх HTTP/1.1). Занятость \
                      проверить не удалось, поэтому порт предложен, но не подтверждён.",
    },
    Candidate {
        transport: Transport::Udp,
        port: 443,
        shape: Shape::Quic,
        alternatives: &[8443, 2053, 2083, 2096],
        why_free: "443/UDP — там обычно весит QUIC: снаружи настоящий QUIC, внутри Мираж. Этот \
                   порт держит НОДА, а не периметр. Номер у TCP и UDP не конфликтует — это \
                   разные пространства сокетов, поэтому 443/TCP и 443/UDP уживаются.",
        why_moved: "443/UDP уже занят на этом хосте, поэтому тот же QUIC предложен на {port}/UDP.",
        why_unknown: "443/UDP — порт, где обычно весит QUIC (снаружи QUIC, внутри Мираж; держит \
                      нода). Занятость проверить не удалось, поэтому порт предложен, но не \
                      подтверждён.",
    },
    Candidate {
        transport: Transport::Tcp,
        port: 8080,
        shape: Shape::Xhttp,
        alternatives: &[8000],
        why_free: "8080/TCP — порт приложения за HTTP-шлюзом: маска xhttp выглядит как \
                   обычный HTTP-запрос с Upgrade.",
        why_moved: "8080/TCP уже занят на этом хосте, поэтому тот же xhttp предложен на \
                    {port}/TCP.",
        why_unknown: "8080/TCP — порт приложения за HTTP-шлюзом (маска xhttp). Занятость \
                      проверить не удалось, поэтому порт предложен, но не подтверждён.",
    },
    Candidate {
        transport: Transport::Tcp,
        port: 8443,
        shape: Shape::Tls,
        alternatives: &[2083, 2087, 10000],
        why_free: "8443/TCP — второй HTTPS-порт: настоящий TLS на нестандартном номере, как у \
                   приложения за nginx.",
        why_moved: "8443/TCP уже занят на этом хосте, поэтому тот же настоящий TLS предложен на \
                    {port}/TCP.",
        why_unknown: "8443/TCP — второй HTTPS-порт (настоящий TLS). Занятость проверить не \
                      удалось, поэтому порт предложен, но не подтверждён.",
    },
];

impl Candidate {
    /// The mask this candidate wears on `port`.
    fn mask(&self, port: u16, hostname: &str) -> TransportCamouflage {
        match self.shape {
            Shape::Tls => TransportCamouflage::TlsReal {
                sni: hostname.to_owned(),
                alpn: vec!["h2".to_owned()],
            },
            Shape::WebSocket => TransportCamouflage::WebSocket {
                path: "/".to_owned(),
                host: hostname.to_owned(),
            },
            Shape::Xhttp => TransportCamouflage::Xhttp {
                path: "/".to_owned(),
                host: hostname.to_owned(),
            },
            Shape::Quic => TransportCamouflage::Quic {
                alpn: vec!["h3".to_owned()],
                bind_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            },
        }
    }
}

/// Whether `port` was already claimed on `transport` by this proposal.
fn is_used(
    used_tcp: &BTreeSet<u16>,
    used_udp: &BTreeSet<u16>,
    transport: Transport,
    port: u16,
) -> bool {
    match transport {
        Transport::Tcp => used_tcp.contains(&port),
        Transport::Udp => used_udp.contains(&port),
    }
}

/// Claim `port` on `transport` for this proposal.
fn claim(
    used_tcp: &mut BTreeSet<u16>,
    used_udp: &mut BTreeSet<u16>,
    transport: Transport,
    port: u16,
) {
    match transport {
        Transport::Tcp => {
            used_tcp.insert(port);
        }
        Transport::Udp => {
            used_udp.insert(port);
        }
    }
}

/// The faces this box could publish, in the order they are offered.
///
/// `detector` answers what is free on the box; `hostname` is the name the
/// masks present themselves under (the box's own persona hostname, so the
/// name on the wire and the name in the artefact never disagree).
///
/// A busy port is not offered — the same face is offered on another port
/// instead, and the reason says which port was busy and what was offered
/// instead. A port the detector could not judge IS offered, with a reason
/// that says the check did not happen.
pub fn propose(detector: &dyn PortDetector, hostname: &str) -> Vec<ProposedFace> {
    let mut used_tcp = BTreeSet::new();
    let mut used_udp = BTreeSet::new();
    let mut faces = Vec::new();

    for candidate in CANDIDATES {
        if is_used(&used_tcp, &used_udp, candidate.transport, candidate.port) {
            // Already taken by an earlier face of this same proposal — one
            // role, one door.
            continue;
        }
        match detector.state(candidate.port, candidate.transport) {
            PortState::Free => {
                claim(&mut used_tcp, &mut used_udp, candidate.transport, candidate.port);
                faces.push(ProposedFace {
                    port: candidate.port,
                    transport: candidate.transport,
                    mask: candidate.mask(candidate.port, hostname),
                    why: candidate.why_free.to_owned(),
                });
            }
            PortState::Unknown => {
                claim(&mut used_tcp, &mut used_udp, candidate.transport, candidate.port);
                faces.push(ProposedFace {
                    port: candidate.port,
                    transport: candidate.transport,
                    mask: candidate.mask(candidate.port, hostname),
                    why: candidate.why_unknown.to_owned(),
                });
            }
            PortState::Taken => {
                for alternative in candidate.alternatives {
                    let port = *alternative;
                    if is_used(&used_tcp, &used_udp, candidate.transport, port) {
                        continue;
                    }
                    if detector.state(port, candidate.transport) == PortState::Taken {
                        continue;
                    }
                    claim(&mut used_tcp, &mut used_udp, candidate.transport, port);
                    faces.push(ProposedFace {
                        port,
                        transport: candidate.transport,
                        mask: candidate.mask(port, hostname),
                        why: candidate.why_moved.replace("{port}", &port.to_string()),
                    });
                    break;
                }
            }
        }
    }

    faces
}

/// One face, as it is written in the proposal file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedFaceEntry {
    /// The port the face sits on.
    pub port: u16,
    /// The transport: `tcp` or `udp`.
    pub transport: String,
    /// The mask, as the JSON [`TransportCamouflage`] serializes to.
    pub mask: String,
    /// Why the face is offered.
    pub why: String,
}

/// The whole proposal, as the installer reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaceProposal {
    /// One table per face.
    #[serde(rename = "face")]
    pub faces: Vec<ProposedFaceEntry>,
}

/// Everything that can go wrong while encoding or decoding a proposal.
#[derive(Debug, Error)]
pub enum FacesError {
    /// A face's mask could not be encoded as JSON.
    #[error("a face's mask could not be encoded as JSON ({reason})")]
    MaskEncode {
        /// Why the encoding failed.
        reason: String,
    },

    /// The proposal could not be encoded as TOML.
    #[error("the proposal could not be encoded as TOML ({reason})")]
    Encode {
        /// Why the encoding failed.
        reason: String,
    },

    /// The proposal could not be decoded from TOML.
    #[error("the proposal could not be read ({reason})")]
    Decode {
        /// Why the decoding failed.
        reason: String,
    },
}

impl FaceProposal {
    /// The proposal as it is written in the file.
    pub fn from_faces(faces: &[ProposedFace]) -> Result<Self, FacesError> {
        let mut entries = Vec::with_capacity(faces.len());
        for face in faces {
            let mask = serde_json::to_string(&face.mask).map_err(|e| FacesError::MaskEncode {
                reason: e.to_string(),
            })?;
            entries.push(ProposedFaceEntry {
                port: face.port,
                transport: face.transport.label().to_owned(),
                mask,
                why: face.why.clone(),
            });
        }
        Ok(Self { faces: entries })
    }

    /// The proposal as TOML — the file the installer reads over SSH.
    pub fn to_toml(&self) -> Result<String, FacesError> {
        toml::to_string(self).map_err(|e| FacesError::Encode {
            reason: e.to_string(),
        })
    }

    /// The proposal read back from TOML.
    pub fn from_toml(text: &str) -> Result<Self, FacesError> {
        toml::from_str(text).map_err(|e| FacesError::Decode {
            reason: e.to_string(),
        })
    }
}

/// The proposal as plain lines, for a person to read in a terminal.
///
/// One line per face: the transport, the port, the mask's own name and the
/// reason. Nothing secret is in here — a mask is a shape, not a key.
pub fn describe(faces: &[ProposedFace]) -> Vec<String> {
    faces
        .iter()
        .map(|face| {
            format!(
                "{}/{} {} — {}",
                face.transport.label(),
                face.port,
                face.mask.label(),
                face.why
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A detector with a fixed answer, so the proposal can be tested
    /// against a known box instead of against this build machine.
    #[derive(Debug, Default)]
    struct FixedDetector {
        busy: BTreeMap<(u16, Transport), PortState>,
    }

    impl FixedDetector {
        fn with(mut self, port: u16, transport: Transport, state: PortState) -> Self {
            self.busy.insert((port, transport), state);
            self
        }
    }

    impl PortDetector for FixedDetector {
        fn state(&self, port: u16, transport: Transport) -> PortState {
            self.busy
                .get(&(port, transport))
                .copied()
                .unwrap_or(PortState::Free)
        }
    }

    #[test]
    fn the_proposal_never_contains_port_22() {
        let detector = FixedDetector::default();
        for face in propose(&detector, "host.example") {
            assert_ne!(face.port, 22, "the box's own SSH answers on 22");
        }
    }

    #[test]
    fn the_proposal_is_the_ordinary_server_set() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let ports: Vec<(Transport, u16)> = faces
            .iter()
            .map(|f| (f.transport, f.port))
            .collect();
        assert_eq!(
            ports,
            vec![
                (Transport::Tcp, 443),
                (Transport::Tcp, 80),
                (Transport::Udp, 443),
                (Transport::Tcp, 8080),
                (Transport::Tcp, 8443),
            ]
        );
    }

    #[test]
    fn the_udp_face_wears_a_real_quic_mask_on_its_own_port() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let udp = faces
            .iter()
            .find(|f| f.transport == Transport::Udp)
            .expect("the UDP face");
        assert_eq!(udp.port, 443);
        match &udp.mask {
            TransportCamouflage::Quic { bind_addr, .. } => {
                assert_eq!(bind_addr.port(), 443, "the mask binds the face's own port");
            }
            other => panic!("the UDP face must wear a real QUIC mask, got {other:?}"),
        }
    }

    #[test]
    fn a_busy_port_is_moved_to_another_one_with_the_same_mask() {
        let detector = FixedDetector::default().with(443, Transport::Tcp, PortState::Taken);
        let faces = propose(&detector, "host.example");
        let tls: Vec<&ProposedFace> = faces
            .iter()
            .filter(|f| matches!(f.mask, TransportCamouflage::TlsReal { .. }))
            .collect();
        assert_eq!(tls.len(), 1, "one role, one door");
        assert_eq!(tls[0].port, 8443, "the busy 443 moved to 8443");
        assert!(
            tls[0].why.contains("занят"),
            "the reason says the port was busy: {}",
            tls[0].why
        );
        assert!(
            !faces.iter().any(|f| f.port == 443 && f.transport == Transport::Tcp),
            "the busy port is not offered"
        );
    }

    #[test]
    fn a_busy_udp_port_does_not_stop_the_tcp_faces() {
        let detector = FixedDetector::default().with(443, Transport::Udp, PortState::Taken);
        let faces = propose(&detector, "host.example");
        assert!(faces.iter().any(|f| f.transport == Transport::Tcp && f.port == 443));
        let udp = faces
            .iter()
            .find(|f| f.transport == Transport::Udp)
            .expect("the UDP face");
        assert_eq!(udp.port, 8443, "the QUIC face moved to another UDP port");
    }

    #[test]
    fn an_unjudgeable_port_is_offered_and_says_so() {
        let detector = FixedDetector::default().with(443, Transport::Tcp, PortState::Unknown);
        let faces = propose(&detector, "host.example");
        let tls = faces
            .iter()
            .find(|f| f.transport == Transport::Tcp && f.port == 443)
            .expect("the TLS face");
        assert!(
            tls.why.contains("проверить не удалось"),
            "the reason says the check did not happen: {}",
            tls.why
        );
    }

    #[test]
    fn one_port_number_is_claimed_once_per_transport() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        for face in &faces {
            match face.transport {
                Transport::Tcp => assert!(tcp.insert(face.port), "TCP {} twice", face.port),
                Transport::Udp => assert!(udp.insert(face.port), "UDP {} twice", face.port),
            }
        }
    }

    #[test]
    fn the_proposal_round_trips_through_toml() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let proposal = FaceProposal::from_faces(&faces).expect("encode");
        let text = proposal.to_toml().expect("toml");
        assert!(text.contains("[[face]]"), "the file is an array of faces: {text}");
        assert!(text.contains("transport = \"tcp\""), "the transport is named: {text}");
        let back = FaceProposal::from_toml(&text).expect("read back");
        assert_eq!(back.faces.len(), faces.len());
        assert_eq!(back.faces[0].port, faces[0].port);
        assert_eq!(back.faces[0].mask, proposal.faces[0].mask);
    }

    #[test]
    fn the_mask_in_the_file_is_the_mask_serde_reads() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let proposal = FaceProposal::from_faces(&faces).expect("encode");
        let mask: TransportCamouflage =
            serde_json::from_str(&proposal.faces[0].mask).expect("the mask reads back");
        assert_eq!(mask, faces[0].mask);
    }

    #[test]
    fn the_report_asks_about_both_transports() {
        let detector = FixedDetector::default();
        let reports = detect_free_ports(&detector, &[443, 80]);
        assert_eq!(reports.len(), 4);
        assert!(reports
            .iter()
            .any(|r| r.port == 443 && r.transport == Transport::Udp));
    }

    #[test]
    fn the_description_names_the_transport_and_the_mask() {
        let detector = FixedDetector::default();
        let faces = propose(&detector, "host.example");
        let lines = describe(&faces);
        assert_eq!(lines.len(), faces.len());
        assert!(lines[0].starts_with("tcp/443 tls_real — "), "{}", lines[0]);
    }
}
