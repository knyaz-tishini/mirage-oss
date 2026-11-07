//! Per-box perimeter persona
//!
//! # Why this lives in `mirage-core` and not in the operator
//!
//! It was operator-only until 2026-08-25, and that placement was the whole
//! reason a box which had lost its identity came up looking different from
//! one that had not. The derivation is a pure function of the machine id —
//! no key, no secret, no network, no DNS — and the box has the machine id
//! on disk in `/var/lib/mirage/attestation.key`, across reboots. So the
//! warden had every input the function needs and simply did not have the
//! function: a self-issued capsule carried no faces, the perimeter fell
//! back to its bare 22/80/443 baseline with no camouflage, and "this box
//! has lost its identity" became visible from the outside — the exact
//! fleet-wide tell this module exists to remove.
//!
//! Both sides derive it now, and they derive the same thing, because it is
//! the same code.
//!
//! ---
//!
//! Original module doc follows.
//!
//! Per-box perimeter persona — the port set and the camouflage parameters that
//! make one box look like an ordinary server rather than like eight siblings.
//!
//! ## The problem this exists to remove
//!
//! Measured 2026-08-04: every box in the fleet published a **byte-identical**
//! face list — `443 tls_real`, `80 web_socket(/)`, `8080 xhttp(/api)`,
//! `3000 web_socket(/ws)` — with the same invented SNI shape on all of them.
//! Four providers, four countries, one signature. Anyone who fingerprints one
//! box has fingerprinted the fleet, and the port-arc work that removed
//! `:19444` and `:22` bought nothing while that stayed true.
//!
//! ## Why it generates rather than asks
//!
//! A persona must exist for **every** box or it is not camouflage, it is a
//! smaller identical set plus some exceptions. So this depends on nothing
//! outside the operator's own process: no DNS lookup, no reverse record, no
//! purchased domain, no certificate authority, no panel. Given a `MachineId` it
//! produces the same persona on every run, on any machine, offline.
//!
//! Real CA-issued certificates on real owned domains are strictly better and
//! are a separate, later change: they are a purchase, and a purchase cannot be
//! a prerequisite for the fleet no longer looking like one fleet. When those
//! exist, they arrive as an override on top of what this produces — the shape
//! of the face list does not change.
//!
//! ## What the names are for
//!
//! Nothing resolves them and nothing validates them. The perimeter's TLS layer
//! runs `NoopCertVerifier`, and a client reaches a box by the `ip:port` in its
//! signed identity — the SNI and the HTTP `Host` are decoration on the wire.
//! Their entire job is to be unremarkable and to differ between boxes. No DNS
//! query is ever made for them, by us or by a peer, so a name is never a route.
//!
//! ## Determinism, and why it is not decoration
//!
//! The persona is a pure function of the machine id. That means it can be
//! reviewed before it is applied, re-derived after the fact to check that a box
//! is serving what it was given, and regenerated identically if the operator's
//! state is ever rebuilt — none of which is true of anything random.

use crate::capsule::{CapsuleControlEndpoint, FacePurpose};
use crate::ids::MachineId;
use crate::mirage::wire::camouflage::TransportCamouflage;

/// Ports the perimeter must never be handed, because something on the box
/// already owns them.
///
/// `19444` / `19445` are the monitor (loopback since the port arc), `19470` is
/// the perimeter's own stats reader, `19471` is where the perimeter hands SSH
/// over to mshd, and `9100` is `node_exporter` on every image here. `53` is a
/// resolver we spent a day closing once already.
///
/// `22` is deliberately NOT here. The foreign `sshd` was retired fleet-wide on
/// 2026-08-04, which freed the port — and a public server with no SSH at all is
/// the unusual case. It comes back as a perimeter face; see [`BASE_PORTS`].
const RESERVED_PORTS: &[u16] = &[53, 9100, 19444, 19445, 19470, 19471];

/// The ports every box publishes.
///
/// This is the part that must **not** vary, and getting that backwards is the
/// mistake the first version of this module made. An externally-visible Linux
/// server shows three to six TCP ports, and `22 / 80 / 443` is overwhelmingly
/// what they are. A box that hides those and instead offers `2087` and `9443`
/// is individually strange, and a fleet of individually strange boxes is still
/// one recognisable family — the monoculture, moved rather than removed.
///
/// So the base is uniform because uniform is what ordinary looks like, and the
/// variation lives entirely in [`ARCHETYPES`] below. Correlating these boxes by
/// port set then means correlating their tails, and the tails are disjoint.
///
/// `22` is a real face: the perimeter reads a connection's opening bytes and
/// routes `SSH-2.0-` to the co-located mshd, so the port genuinely answers SSH
/// while also carrying the wire for a client that dials it. `Shape::Raw` is not
/// a gap in the camouflage — an SSH port that spoke TLS would be the anomaly.
const BASE_PORTS: &[(u16, Shape)] = &[
    (22, Shape::Raw),
    (80, Shape::WebSocket),
    (443, Shape::Tls),
];

/// The tail: what this particular box looks like it is FOR.
///
/// A tail has to be coherent, not merely different. Ports do not appear
/// independently on real servers — `2083` shows up next to `2087` because both
/// are cPanel, `8080` next to `8443` because both are one app server's plain
/// and TLS halves. A box exposing an unrelated scatter of ports is its own
/// tell, so the persona picks ONE archetype and takes its whole tail.
///
/// The empty tail is first and is drawn as often as any other, because the
/// commonest real server on the internet publishes exactly `22 / 80 / 443` and
/// nothing else. A fleet where every box has an interesting tail is, again, a
/// family.
const ARCHETYPES: &[(&str, &[(u16, Shape)])] = &[
    // Plain web server. The single most common shape there is.
    ("plain", &[]),
    // Application server behind the web port — plain and TLS halves together.
    ("app", &[(8080, Shape::Xhttp), (8443, Shape::Tls)]),
    // Shared-hosting control panel. These two always travel together.
    ("panel", &[(2083, Shape::Tls), (2087, Shape::Tls)]),
    // Node/dev service left exposed, which is extremely common and boring.
    ("node-app", &[(3000, Shape::WebSocket)]),
    // Python/uwsgi-shaped deployment.
    ("py-app", &[(5000, Shape::WebSocket), (8000, Shape::Xhttp)]),
    // Admin console.
    ("admin", &[(10000, Shape::Tls)]),
    // Alternate HTTPS only — a second site or a staging vhost.
    ("alt-tls", &[(8443, Shape::Tls)]),
    // Cache/proxy in front of the app.
    ("proxy", &[(8080, Shape::Xhttp)]),
];

/// Which camouflage family a port wears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// No outer wrapper. The perimeter classifies by opening bytes, so this is
    /// what an SSH-shaped port has to be.
    Raw,
    Tls,
    WebSocket,
    Xhttp,
}

/// Upper bound on the published surface, base plus tail plus the one
/// datagram chain face every box now carries.
///
/// Six is where a small server stops looking like a small server. The
/// longest archetype tail (two ports) plus the three base ports plus the one
/// datagram face reaches exactly this bound and no archetype exceeds it, and
/// the assertion in `faces_are_distinct_and_ordered` exists so a future one
/// cannot.
const MAX_FACES: usize = 6;

/// Hostname vocabulary. Deliberately dull: the parts a real
/// small-server hostname is made of, in the proportions they actually occur.
const HOST_LABELS: &[&str] = &[
    "srv", "node", "web", "app", "edge", "gw", "vm", "host", "cache", "static", "cdn", "media",
    "api", "mail", "cloud", "data",
];
/// Second-level labels. Generic infrastructure words rather than anything that
/// reads as a brand — a brand would be a claim about who runs the box.
const DOMAIN_LABELS: &[&str] = &[
    "netops", "hostbay", "servline", "datapoint", "cloudmesh", "webhold", "linknode", "coreserve",
];
/// TLDs in roughly the proportion boring hosting uses them.
const TLDS: &[&str] = &["com", "net", "io", "cloud", "systems", "host"];

/// Paths for the HTTP-shaped camouflages. Each is something a real service
/// serves, so the path and the shape agree.
const WS_PATHS: &[&str] = &["/ws", "/socket", "/live", "/stream", "/events", "/"];
const XHTTP_PATHS: &[&str] = &["/api", "/v1", "/api/v2", "/rpc", "/gateway", "/data"];

/// ALPN sets, all of them things a real TLS server offers.
const ALPN_SETS: &[&[&str]] = &[
    &["h2", "http/1.1"],
    &["http/1.1"],
    &["h2"],
    &["h2", "http/1.1", "acme-tls/1"],
];

/// Ports the one UDP face draws from. Ordinary NON-VPN UDP services a public
/// VPS plausibly runs, so an unwrapped `RawUdp` face reads as one of THEM
/// rather than as a bare tunnel sitting where nothing should be listening:
/// `123` NTP, `853` DNS-over-QUIC, `3478` STUN (WebRTC signaling/media),
/// `5060` SIP, `5349` STUN/TURN over DTLS, `8443` QUIC/HTTP3 on the common
/// HTTPS-alt port. No port here is one a real VPN protocol registers on,
/// because that is the one label that announces "a tunnel lives here" —
/// exactly the tell a face exists to remove.
///
/// The honest limit: `RawUdp` has no outer wrapper (see its own doc), so the
/// port number is the only thing making it blend in — the bytes on the wire
/// are ours, not the named service's. That defeats a PASSIVE port scan only.
/// An active probe that actually speaks NTP/DoQ/STUN/SIP/TURN/QUIC and reads
/// the reply gets silence or garbage, not the service's real answer; closing
/// that gap needs a full datagram camouflage that answers the real protocol
/// (U6), not a bare port-number choice.
///
/// **The pool may only name services a stock box does NOT already run.** A
/// face has to BIND its port, so a port the box's own daemon holds yields a
/// face that can never come up. `123` was in this pool and had to leave:
/// nl-hosthatch drew it, and that box — like any stock Linux — runs its own
/// NTP client on 123, so the face was refused by the perimeter, reported as
/// `udp_face_not_listening`, and could not have been made to work by any
/// amount of delivery. Every other entry names a service a plain VPS does not
/// run unasked: DNS-over-QUIC needs a resolver, STUN/TURN and SIP need their
/// own daemons, and 8443 is an application port nothing claims by default.
///
/// This is a rule about the pool, not a patch for one box. Adding an entry
/// means checking that a stock image leaves it free — the alternative is
/// discovering it one collision at a time, in production, on the box that
/// happens to draw it.
///
/// Removing an entry re-draws EVERY box's datagram port: the draw indexes
/// into the filtered candidate list, so the list's length is part of the
/// derivation. That is a one-time reissue, and it is the correct cost —
/// the alternative is a fleet where one box's face is permanently unbindable.
const UDP_PORT_POOL: &[u16] = &[853, 3478, 5060, 5349, 8443];

/// One box's published surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Persona {
    /// The machine this was derived for.
    pub machine: String,
    /// The name every HTTP-shaped face reports as `Host` and every TLS face
    /// presents as SNI — and therefore, since 2026-08-04, the name in the
    /// certificate the box generates for itself.
    pub hostname: String,
    /// What this box looks like it is FOR — the tail's name. Carried so a
    /// reviewer can see the intent behind a port set rather than reverse it
    /// from the numbers.
    pub archetype: String,
    /// The faces, ascending by port so two derivations are trivially diffable.
    pub faces: Vec<CapsuleControlEndpoint>,
}

/// A deterministic stream of numbers derived from a machine id.
///
/// BLAKE3 of the id seeds a xorshift, so the whole persona is reproducible from
/// the id alone and adjacent machine ids do not produce adjacent personas — the
/// fleet's ids differ by a single octet, and a generator that turned that into
/// neighbouring port sets would have rebuilt the monoculture in a new shape.
struct Stream(u64);

impl Stream {
    fn new(seed_material: &str) -> Self {
        let digest = blake3::hash(seed_material.as_bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&digest.as_bytes()[..8]);
        // Never zero: a xorshift seeded with zero produces only zero.
        Self(u64::from_le_bytes(b) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Uniform-enough index into a slice of length `n`.
    fn index(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }
}

/// Derive the persona for `machine`.
///
/// Pure: same id in, same persona out, with no I/O of any kind.
pub fn persona_for(machine: &MachineId) -> Persona {
    let mut rng = Stream::new(machine.as_str());

    let hostname = format!(
        "{}{}.{}.{}",
        rng.pick(HOST_LABELS),
        // A two-to-four digit tag. Real hosting names carry one far more often
        // than not, and it is what keeps two boxes that drew the same labels
        // from colliding.
        rng.next() % 9000 + 100,
        rng.pick(DOMAIN_LABELS),
        rng.pick(TLDS),
    );

    // Uniform base, varying tail — see `BASE_PORTS` for why round that way.
    let (archetype, tail) = *rng.pick(ARCHETYPES);
    let mut chosen: Vec<(u16, Shape)> = BASE_PORTS.to_vec();
    for (port, shape) in tail {
        // An archetype must never reach for something the box already runs, and
        // must never restate a base port under a different shape.
        if !RESERVED_PORTS.contains(port) && !chosen.iter().any(|(p, _)| p == port) {
            chosen.push((*port, *shape));
        }
    }

    chosen.sort_by_key(|(p, _)| *p);

    let mut faces: Vec<CapsuleControlEndpoint> = chosen
        .into_iter()
        .map(|(port, shape)| CapsuleControlEndpoint {
            port,
            camouflage: match shape {
                // The perimeter routes by opening bytes, so a raw face carries
                // both an SSH client and a wire client. Wrapping `:22` in TLS
                // would make the one port everybody expects to speak SSH the
                // one port on the box that does not.
                Shape::Raw => TransportCamouflage::None,
                Shape::Tls => TransportCamouflage::TlsReal {
                    sni: hostname.clone(),
                    alpn: rng.pick(ALPN_SETS).iter().map(|s| (*s).to_string()).collect(),
                },
                Shape::WebSocket => TransportCamouflage::WebSocket {
                    path: (*rng.pick(WS_PATHS)).to_string(),
                    host: hostname.clone(),
                },
                Shape::Xhttp => TransportCamouflage::Xhttp {
                    path: (*rng.pick(XHTTP_PATHS)).to_string(),
                    host: hostname.clone(),
                },
            },
            wire_version: None,
            // Every face starts unmarked. `None` here means the pre-existing
            // meaning — monitor control traffic — and, crucially, encodes to
            // nothing at all (`skip_serializing_if` on `purpose`): a face this
            // loop leaves alone signs byte-identically to a persona minted
            // before `FacePurpose` existed. Writing `Some(MonitorWire)` instead
            // would add a key to every face's JSON for a fact that is already
            // the default, moving the signing preimage of every box in the
            // fleet for no gain.
            purpose: None,
        })
        .collect();

    // Designate exactly one already-published face as the chain data-plane
    // face (`FacePurpose::NodeChain`), so a hop that is about to be addressed
    // by face has somewhere on this box's EXISTING port set for the perimeter
    // to splice to the co-located node instead of the monitor. This draws
    // from the same seeded `Stream` that picked the hostname and archetype
    // above, and only after every earlier draw: appending here cannot change
    // which hostname, archetype or ports an id already produces, because a
    // xorshift only depends on draws that came before it, never after.
    //
    // Never `:22` — that face already carries the operator's own way in (the
    // perimeter splices `SSH-2.0-` there to mshd), and folding the chain data
    // plane onto the same face would put the operator's door and a data plane
    // on one wire. `:80` and `:443` are on every box regardless of archetype,
    // so keeping `:22` clear costs nothing.
    let chain_candidates: Vec<usize> =
        faces.iter().enumerate().filter(|(_, f)| f.port != 22).map(|(i, _)| i).collect();
    // Never empty: `BASE_PORTS` always contributes `80` and `443`. Asserted
    // rather than assumed, in the same spirit as `MAX_FACES` below: an empty
    // list would reach `rng.index(0)` and die on a modulo by zero, which names
    // nothing. A future `BASE_PORTS` that left only `:22` would be a real bug,
    // and it should say which invariant it broke.
    assert!(
        !chain_candidates.is_empty(),
        "persona: a box must publish at least one face that is not :22 to carry the chain plane"
    );
    let chain_idx = chain_candidates[rng.index(chain_candidates.len())];
    faces[chain_idx].purpose = Some(FacePurpose::NodeChain);

    // A DATAGRAM chain face, so the already-built and already-tested UDP
    // data plane has somewhere on this box's signed identity to be born —
    // until this addition `persona_for` never emitted `RawUdp`, so no box in
    // the fleet could ever have a UDP face at all. Two more draws from the
    // SAME seeded `Stream`, both strictly after `chain_idx` above and after
    // every draw before it, for the same reason given there: a xorshift only
    // depends on draws that came before it, so appending here cannot move
    // the hostname, archetype, TCP port set or which stream face carries the
    // chain purpose.
    //
    // The candidate pool is excluded against every port this box already
    // publishes (reserved, base, tail) and against `:22` explicitly, because
    // `PerimeterConfig::from_capsule` keeps ONE `seen_ports` set shared
    // across TCP and UDP faces and refuses a repeat with `DuplicatePort`.
    let udp_candidates: Vec<u16> = UDP_PORT_POOL
        .iter()
        .copied()
        .filter(|p| *p != 22 && !RESERVED_PORTS.contains(p) && !faces.iter().any(|f| f.port == *p))
        .collect();
    // Never empty in practice: the pool has more entries than any archetype
    // has faces. Asserted rather than assumed, in the same spirit as
    // `chain_candidates` above — a future archetype or a future pool that
    // let this run dry would be a real bug and should say so, not divide by
    // zero silently.
    assert!(
        !udp_candidates.is_empty(),
        "persona: no UDP port left for the datagram chain face"
    );
    let udp_port = udp_candidates[rng.index(udp_candidates.len())];

    faces.push(CapsuleControlEndpoint {
        port: udp_port,
        // `RawUdp`'s wire shape — enforced by `PerimeterConfig::from_capsule`
        // — requires `bind_addr.port() == endpoint.port`; matches the shape
        // that crate's own test helper `raw_udp_endpoint` builds.
        camouflage: TransportCamouflage::RawUdp {
            bind_addr: format!("0.0.0.0:{udp_port}")
                .parse()
                .expect("a port number formatted into an IPv4 socket address always parses"),
        },
        wire_version: None,
        // Same purpose as the stream chain face above, deliberately: the
        // perimeter keys the inward destination off `purpose` on BOTH paths
        // — `inward_target(purpose)` for stream faces, `dgram_relay_for
        // (purpose)` for datagram faces — so a datagram face marked
        // `NodeChain` splices to the co-located node over the datagram
        // relay, exactly as intended. A separate purpose variant is not
        // wanted.
        purpose: Some(FacePurpose::NodeChain),
    });
    // Re-sort: `faces` is documented as ascending by port so two derivations
    // are trivially diffable, and the datagram face was appended, not
    // inserted in place.
    faces.sort_by_key(|f| f.port);

    Persona {
        machine: machine.as_str().to_string(),
        hostname,
        archetype: archetype.to_string(),
        faces,
    }
}

#[cfg(test)]
mod tests {

    /// Ports a stock Linux server occupies without being asked. A face has to
    /// BIND its port, so anything here is a face that can never come up — and
    /// it fails in the one place nobody looks, on whichever box happens to
    /// draw it. `123` was in the UDP pool and cost nl-hosthatch a face that
    /// the perimeter refused and `/fleet/ports` reported as
    /// `udp_face_not_listening`, correctly and uselessly.
    const STOCK_OCCUPIED_UDP: &[u16] = &[
        // systemd-timesyncd / chrony / ntpd — running on essentially every
        // distribution image out of the box.
        123,
        // systemd-resolved's stub listener. Not in the pool today; named so
        // that adding "DNS" as a disguise is checked rather than assumed.
        53,
        // DHCP client, and the reason secd's UDP readback excludes them: the
        // renderer always writes these two exceptions.
        68, 546,
    ];

    /// The pool disguises a face as a service the box does NOT run. A port
    /// that is both is not a disguise, it is a collision.
    #[test]
    fn the_udp_pool_names_no_service_a_stock_box_already_runs() {
        for port in UDP_PORT_POOL {
            assert!(
                !STOCK_OCCUPIED_UDP.contains(port),
                "UDP_PORT_POOL contains {port}, which a stock box already                  listens on — a face drawn on it can never bind"
            );
        }
    }
    use super::*;

    /// The nine live machine ids, so the properties below are asserted against
    /// the fleet that actually exists rather than against invented input.
    const FLEET: &[&str] = &[
        "ch-example-203.0.113.41",
        "nl-example-203.0.113.31",
        "nl-example-203.0.113.30",
        "ru-hostkey-203.0.113.10",
        "ru-example-203.0.113.50",
        "tr-hostkey-203.0.113.20",
        "us-example-203.0.113.25",
        "us-example-203.0.113.25",
        "us-example-203.0.113.25",
    ];

    fn fleet_personas() -> Vec<Persona> {
        FLEET
            .iter()
            .map(|m| persona_for(&MachineId::new(m).expect("machine id")))
            .collect()
    }

    /// The property that actually matters, and it is NOT "every box is
    /// unique".
    ///
    /// Two ordinary servers sharing `22 / 80 / 443` is what ordinary looks
    /// like — uniqueness would be the anomaly. What must not happen is the
    /// fleet sharing ONE distinctive set, which is what it did until today. So:
    /// several distinct sets, and no single set covering most of the fleet.
    #[test]
    fn the_fleet_does_not_share_one_port_set() {
        let personas = fleet_personas();
        let mut counts: std::collections::BTreeMap<Vec<u16>, usize> = Default::default();
        for p in &personas {
            *counts
                .entry(p.faces.iter().map(|f| f.port).collect())
                .or_default() += 1;
        }
        assert!(
            counts.len() >= 4,
            "only {} distinct port sets across {} boxes: {:?}",
            counts.len(),
            personas.len(),
            counts
        );
        let worst = counts.values().copied().max().unwrap_or(0);
        assert!(
            worst * 2 <= personas.len(),
            "one port set covers {worst} of {} boxes — that set IS the fleet",
            personas.len()
        );
    }

    /// The base is the camouflage; the tail is the unlinkability. Every box
    /// must publish the base, or it stops looking like an ordinary server.
    #[test]
    fn every_box_publishes_the_ordinary_base() {
        for p in fleet_personas() {
            for (port, _) in BASE_PORTS {
                assert!(
                    p.faces.iter().any(|f| f.port == *port),
                    "{} does not publish {port}",
                    p.machine
                );
            }
        }
    }

    /// `:22` has to be raw. The perimeter decides by opening bytes, so a raw
    /// face carries an SSH client and a wire client both; wrapping it would
    /// make the one port everyone expects to speak SSH the one that does not.
    #[test]
    fn the_ssh_port_is_unwrapped() {
        for p in fleet_personas() {
            let ssh = p
                .faces
                .iter()
                .find(|f| f.port == 22)
                .unwrap_or_else(|| panic!("{} publishes no :22", p.machine));
            assert!(
                matches!(ssh.camouflage, TransportCamouflage::None),
                "{} wraps :22 in {:?}",
                p.machine,
                ssh.camouflage
            );
        }
    }

    /// …and the same is true of the name, which is the other half of what a
    /// scanner records.
    #[test]
    fn no_two_boxes_share_a_hostname() {
        let personas = fleet_personas();
        for (i, a) in personas.iter().enumerate() {
            for b in personas.iter().skip(i + 1) {
                assert_ne!(a.hostname, b.hostname, "{} and {}", a.machine, b.machine);
            }
        }
    }

    /// Reproducible from the id alone: a persona that could not be re-derived
    /// could not be reviewed before it was applied, nor checked afterwards
    /// against what the box is really serving.
    #[test]
    fn a_persona_is_a_pure_function_of_the_machine_id() {
        for m in FLEET {
            let id = MachineId::new(m).expect("machine id");
            let a = persona_for(&id);
            let b = persona_for(&id);
            assert_eq!(a.hostname, b.hostname);
            assert_eq!(
                a.faces.iter().map(|f| f.port).collect::<Vec<_>>(),
                b.faces.iter().map(|f| f.port).collect::<Vec<_>>()
            );
            assert_eq!(
                serde_json::to_string(&a.faces).unwrap(),
                serde_json::to_string(&b.faces).unwrap()
            );
        }
    }

    /// Machine ids in this fleet differ by one octet. A generator that mapped
    /// that to neighbouring personas would have rebuilt the monoculture, so the
    /// two closest possible ids must not land on the same persona.
    ///
    /// Asserted on the whole persona, not on the port set alone: with a small
    /// set of archetypes two boxes sharing a tail is expected and fine — see
    /// `the_fleet_does_not_share_one_port_set` — so a port-set assertion here
    /// would pass or fail on the luck of the draw rather than on the property.
    #[test]
    fn adjacent_machine_ids_do_not_produce_adjacent_personas() {
        let a = persona_for(&MachineId::new("us-example-203.0.113.25").expect("id"));
        let b = persona_for(&MachineId::new("us-example-203.0.113.25").expect("id"));
        assert_ne!(a.hostname, b.hostname);
        assert_ne!(
            serde_json::to_string(&a).expect("a"),
            serde_json::to_string(&b).expect("b")
        );
    }

    /// A face on a port the box already uses would go dark at bind, and a dark
    /// face is a published address that fails — worse than not publishing it.
    #[test]
    fn no_persona_claims_a_port_the_box_already_owns() {
        for p in fleet_personas() {
            for f in &p.faces {
                assert!(
                    !RESERVED_PORTS.contains(&f.port),
                    "{} claims reserved port {}",
                    p.machine,
                    f.port
                );
            }
        }
    }

    /// Ports must be distinct within a box, and the list ordered, or two
    /// derivations of the same persona would not diff cleanly.
    #[test]
    fn faces_are_distinct_and_ordered() {
        for p in fleet_personas() {
            let ports: Vec<u16> = p.faces.iter().map(|f| f.port).collect();
            let mut sorted = ports.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(ports, sorted, "{} has duplicate or unordered faces", p.machine);
            assert!(
                (BASE_PORTS.len()..=MAX_FACES).contains(&p.faces.len()),
                "{} publishes {} faces",
                p.machine,
                p.faces.len()
            );
        }
    }

    /// The camouflage must match the port it sits on, and every box must keep
    /// one TLS face — see the guarantee in `persona_for`.
    #[test]
    fn every_box_keeps_a_tls_face_and_the_shapes_match_their_ports() {
        for p in fleet_personas() {
            let mut tls = 0;
            for f in &p.faces {
                // The datagram chain face is not drawn from `BASE_PORTS` or
                // any archetype tail — it has its own dedicated port pool
                // and its own dedicated invariants, checked elsewhere.
                if f.camouflage.is_udp() {
                    continue;
                }
                let expected = BASE_PORTS
                    .iter()
                    .chain(ARCHETYPES.iter().flat_map(|(_, tail)| tail.iter()))
                    .find(|(port, _)| *port == f.port)
                    .map(|(_, s)| *s)
                    .expect("every face comes from the base or an archetype tail");
                match (&f.camouflage, expected) {
                    (TransportCamouflage::None, Shape::Raw) => {}
                    (TransportCamouflage::TlsReal { sni, alpn }, Shape::Tls) => {
                        tls += 1;
                        assert_eq!(sni, &p.hostname, "the SNI is the persona's name");
                        assert!(!alpn.is_empty(), "a TLS face with no ALPN is unusual");
                    }
                    (TransportCamouflage::WebSocket { host, path }, Shape::WebSocket)
                    | (TransportCamouflage::Xhttp { host, path }, Shape::Xhttp) => {
                        assert_eq!(host, &p.hostname);
                        assert!(path.starts_with('/'));
                    }
                    (other, want) => {
                        panic!("{} port {} wears {other:?}, want {want:?}", p.machine, f.port)
                    }
                }
            }
            assert!(tls >= 1, "{} publishes no TLS face", p.machine);
        }
    }

    /// The name has to survive being put in a certificate and in an SNI
    /// extension: a label that is not a legal DNS name is refused by rcgen at
    /// the box and by `ServerName::try_from` at the dialer, and the face would
    /// be dark on both sides.
    #[test]
    fn hostnames_are_legal_dns_names() {
        for p in fleet_personas() {
            assert!(p.hostname.len() <= 253, "{}", p.hostname);
            let labels: Vec<&str> = p.hostname.split('.').collect();
            assert!(labels.len() >= 3, "{}", p.hostname);
            for l in labels {
                assert!(!l.is_empty() && l.len() <= 63, "bad label in {}", p.hostname);
                assert!(
                    l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                    "non-hostname characters in {}",
                    p.hostname
                );
            }
            assert!(
                p.hostname.parse::<std::net::IpAddr>().is_err(),
                "an IP literal suppresses the SNI extension entirely: {}",
                p.hostname
            );
        }
    }

    /// Nothing in a persona may name Mirage. The fleet already shipped one
    /// literal — `mirage.local` in every certificate — and it was the single
    /// most identifying string on the public surface. `zengeld` and
    /// `m1r4g3` are the product's former and current public domains
    /// (owner ruling 2026-09-23 detached the product from zengeld.com in
    /// favor of m1r4g3.bid) — both stay banned indefinitely: a box that
    /// still carries an old cert/config referencing the retired domain
    /// during a transition must be caught by this check too.
    #[test]
    fn nothing_in_a_persona_names_the_project() {
        for p in fleet_personas() {
            let json = serde_json::to_string(&p).expect("serialise");
            for banned in ["mirage", "Mirage", "zengeld", "m1r4g3", "operator"] {
                assert!(
                    !json.contains(banned),
                    "{} leaks {banned:?} onto the public surface",
                    p.machine
                );
            }
        }
    }

    /// Every box must have exactly one STREAM face and exactly one DATAGRAM
    /// face the perimeter will splice to the co-located node instead of the
    /// monitor: the stream face for the mux-carried chain traffic that
    /// already existed, and the datagram face so the already-built UDP data
    /// plane has somewhere to be born. Both share `FacePurpose::NodeChain` —
    /// see the datagram face's own doc in `persona_for` for why a second
    /// purpose variant is not wanted — so this discriminates by the
    /// camouflage's own transport (`TransportCamouflage::is_udp`) rather
    /// than by purpose alone.
    #[test]
    fn exactly_one_face_is_the_node_chain_face() {
        for p in fleet_personas() {
            let stream_chain: Vec<&CapsuleControlEndpoint> = p
                .faces
                .iter()
                .filter(|f| f.purpose == Some(FacePurpose::NodeChain) && !f.camouflage.is_udp())
                .collect();
            assert_eq!(
                stream_chain.len(),
                1,
                "{} has {} stream node-chain faces, want exactly 1",
                p.machine,
                stream_chain.len()
            );
            let dgram_chain: Vec<&CapsuleControlEndpoint> = p
                .faces
                .iter()
                .filter(|f| f.purpose == Some(FacePurpose::NodeChain) && f.camouflage.is_udp())
                .collect();
            assert_eq!(
                dgram_chain.len(),
                1,
                "{} has {} datagram node-chain faces, want exactly 1",
                p.machine,
                dgram_chain.len()
            );
        }
    }

    /// `:22` also carries the operator's own way in — the perimeter splices
    /// `SSH-2.0-` there to mshd — so neither chain data-plane face, stream or
    /// datagram, may land on it. `:80` and `:443` are on every box regardless
    /// of archetype, so keeping `:22` clear costs nothing.
    #[test]
    fn the_node_chain_face_is_never_port_22() {
        for p in fleet_personas() {
            let stream_chain = p
                .faces
                .iter()
                .find(|f| f.purpose == Some(FacePurpose::NodeChain) && !f.camouflage.is_udp())
                .expect("exactly one stream node-chain face");
            assert_ne!(stream_chain.port, 22, "{} put the stream chain face on :22", p.machine);
            let dgram_chain = p
                .faces
                .iter()
                .find(|f| f.purpose == Some(FacePurpose::NodeChain) && f.camouflage.is_udp())
                .expect("exactly one datagram node-chain face");
            assert_ne!(dgram_chain.port, 22, "{} put the datagram chain face on :22", p.machine);
        }
    }

    /// Every face other than the two designated above (one stream, one
    /// datagram — see `exactly_one_face_is_the_node_chain_face`) must stay
    /// `None` — not an explicit `Some(MonitorWire)` — so it keeps encoding to
    /// nothing in the signed face list. See `purpose`'s own doc for why
    /// `None` is the pre-existing meaning and not merely a missing value.
    #[test]
    fn every_other_face_stays_unmarked() {
        for p in fleet_personas() {
            for f in &p.faces {
                if f.purpose == Some(FacePurpose::NodeChain) {
                    continue;
                }
                assert_eq!(
                    f.purpose, None,
                    "{} face :{} carries {:?}, want None",
                    p.machine, f.port, f.purpose
                );
            }
        }
    }

    /// Determinism must cover the new draws too: the same machine id must
    /// yield the same hostname, the same archetype, the same port set AND
    /// the same chosen chain faces — stream AND datagram — not merely
    /// four-out-of-five.
    #[test]
    fn the_chain_face_choice_is_also_a_pure_function_of_the_machine_id() {
        for m in FLEET {
            let id = MachineId::new(m).expect("machine id");
            let a = persona_for(&id);
            let b = persona_for(&id);
            let chain_port = |p: &Persona, udp: bool| {
                p.faces
                    .iter()
                    .find(|f| f.purpose == Some(FacePurpose::NodeChain) && f.camouflage.is_udp() == udp)
                    .map(|f| f.port)
            };
            assert_eq!(
                chain_port(&a, false),
                chain_port(&b, false),
                "{m} stream chain face is not deterministic"
            );
            assert_eq!(
                chain_port(&a, true),
                chain_port(&b, true),
                "{m} datagram chain face is not deterministic"
            );
            assert_eq!(
                serde_json::to_string(&a.faces).unwrap(),
                serde_json::to_string(&b.faces).unwrap()
            );
        }
    }

    /// No perturbation: hostname, archetype, TCP (stream) port set and the
    /// port carrying the stream `NodeChain` face, for these four ids, were
    /// recorded by running the code as it stood BEFORE the datagram chain
    /// face existed — `git show HEAD:crates/mirage-core/src/persona.rs` at
    /// the commit this diff is built on top of, in a detached worktree, with
    /// a throwaway test printing exactly these fields. Adding the datagram
    /// draw (and, before that, marking a face's `purpose` at all) must not
    /// move any of them, because both happen strictly after the draws that
    /// pick these, in the same `Stream`.
    ///
    /// The comparison is against the STREAM faces only (`!is_udp()`): the
    /// datagram face is a new, additional member of `p.faces` by design —
    /// see `persona_for` — so it is asserted separately below, not folded
    /// into a port-set literal that predates it.
    #[test]
    fn marking_the_chain_face_does_not_perturb_the_pre_existing_persona() {
        let golden: &[(&str, &str, &str, &[u16], u16)] = &[
            (
                "ch-example-203.0.113.41",
                "srv316.hostbay.systems",
                "panel",
                &[22, 80, 443, 2083, 2087],
                2087,
            ),
            (
                "nl-example-203.0.113.31",
                "srv6436.netops.systems",
                "alt-tls",
                &[22, 80, 443, 8443],
                443,
            ),
            (
                "ru-example-203.0.113.50",
                "srv6195.datapoint.host",
                "proxy",
                &[22, 80, 443, 8080],
                443,
            ),
            (
                "us-example-203.0.113.25",
                "static7309.webhold.net",
                "py-app",
                &[22, 80, 443, 5000, 8000],
                80,
            ),
        ];
        for (machine, hostname, archetype, ports, chain_port) in golden {
            let p = persona_for(&MachineId::new(machine).expect("id"));
            assert_eq!(&p.hostname, hostname, "{machine} hostname moved");
            assert_eq!(&p.archetype, archetype, "{machine} archetype moved");
            let stream_ports: Vec<u16> =
                p.faces.iter().filter(|f| !f.camouflage.is_udp()).map(|f| f.port).collect();
            assert_eq!(&stream_ports, ports, "{machine} stream port set moved");
            let stream_chain_port = p
                .faces
                .iter()
                .find(|f| f.purpose == Some(FacePurpose::NodeChain) && !f.camouflage.is_udp())
                .map(|f| f.port);
            assert_eq!(
                stream_chain_port,
                Some(*chain_port),
                "{machine} stream chain face moved"
            );
        }
    }

    /// The face marked as the stream chain face must not change the
    /// archetype's published TCP surface itself — same count, same ports,
    /// same order — only the `purpose` of one entry. The datagram chain face
    /// is a deliberate, separate addition on top of that surface — see
    /// `persona_for` — so it is checked here only for "exactly one exists",
    /// not folded into the archetype-derived port list.
    #[test]
    fn the_published_port_set_is_unchanged_by_the_marking() {
        for p in fleet_personas() {
            let (_, tail) = ARCHETYPES
                .iter()
                .find(|(name, _)| *name == p.archetype)
                .expect("persona archetype is one of ARCHETYPES");
            let mut expected: Vec<u16> = BASE_PORTS.iter().map(|(port, _)| *port).collect();
            for (port, _) in *tail {
                if !RESERVED_PORTS.contains(port) && !expected.contains(port) {
                    expected.push(*port);
                }
            }
            expected.sort_unstable();
            let actual_stream: Vec<u16> =
                p.faces.iter().filter(|f| !f.camouflage.is_udp()).map(|f| f.port).collect();
            assert_eq!(
                actual_stream, expected,
                "{} stream port set does not match its archetype",
                p.machine
            );

            let dgram_count = p.faces.iter().filter(|f| f.camouflage.is_udp()).count();
            assert_eq!(
                dgram_count, 1,
                "{} publishes {} datagram faces, want exactly 1",
                p.machine, dgram_count
            );
        }
    }
}
