//! The peer wire: what a Mirage peer says, in one place.
//!
//! Three implementations speak the edge-session wire today:
//!
//! - the commercial box (`mirage-vpn`): the mux wire of versions 1 to 3 and
//!   the packet plane of version 4;
//! - the fleet box (`mirage-node`'s entrance): the mux wire of versions 1 to 3;
//! - the client (`mirage-subscriber-client`): it offers version 4 first and
//!   falls back to 3, 2 and 1.
//!
//! Before this module each of them kept its own version numbers and its own
//! copy of the hello/welcome rules, and the copies disagreed: the commercial
//! box answered a version-3 hello with "this exit carries no datagrams" while
//! the fleet box answered the same hello with "it does", and the commercial
//! box answered a refused hello with the version the client had offered
//! (which it could not even encode when the session had arrived on no face).
//! The version numbers and the rules live here now, so the two wires can be
//! merged without a third copy of the negotiation appearing.

use crate::edge_session::{
    ClientAssignment, CountryCode, EdgeHello, EdgeOutcome, EdgeRefusal, EdgeSessionError,
    EdgeWelcome, ExitPreference,
};

// -- The wire versions ----------------------------------------------------

/// The packet plane: the wire of the future.
///
/// The whole IP packets ride the datagrams of one QUIC connection, and the
/// box's TUN device is the exit. This is the only version a new peer speaks.
pub const PLANE_VERSION: u8 = 4;

/// The legacy mux wire, version 1: no trailer at all. Every flow of the
/// session is a stream of the same connection.
pub const MUX_VERSION_V1: u8 = 1;

/// The legacy mux wire, version 2: the hello carries the client's faces, and
/// the welcome names the face the box assigned to the session.
pub const MUX_VERSION_V2: u8 = 2;

/// The legacy mux wire, version 3: version 2 plus one flag byte in the
/// welcome, which says whether the exit carries datagrams.
pub const MUX_VERSION_V3: u8 = 3;

/// Every version of the legacy mux wire, newest first.
pub const MUX_VERSIONS: [u8; 3] = [MUX_VERSION_V3, MUX_VERSION_V2, MUX_VERSION_V1];

/// Every wire version a client may offer, newest first: the fallback chain
/// of a client that has to reach boxes of different ages.
pub const ALL_VERSIONS: [u8; 4] = [PLANE_VERSION, MUX_VERSION_V3, MUX_VERSION_V2, MUX_VERSION_V1];

// -- What a server speaks -------------------------------------------------

/// What a server speaks of the peer wire.
///
/// The versions are listed newest first: that is the order the client offers
/// them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerProfile {
    /// The wire versions this server understands, newest first.
    versions: &'static [u8],
    /// Does this server's mux wire carry datagram flows?
    ///
    /// This is exactly what the flag byte of a version-3 welcome says. The
    /// fleet box carries UDP flows over its mux; the commercial box does
    /// not -- its mux path serves TCP flows only. The packet plane carries
    /// whole IP packets, so the flag is always set there.
    mux_carries_datagrams: bool,
}

impl PeerProfile {
    /// The mux wire only, and the mux carries datagram flows: the fleet
    /// box. It cannot serve the plane yet.
    pub const MUX_WITH_DATAGRAMS: PeerProfile = PeerProfile {
        versions: &MUX_VERSIONS,
        mux_carries_datagrams: true,
    };

    /// The mux wire only, and the mux carries no datagram flows: the mux
    /// path of the commercial box. Its flows are TCP only.
    pub const MUX_WITHOUT_DATAGRAMS: PeerProfile = PeerProfile {
        versions: &MUX_VERSIONS,
        mux_carries_datagrams: false,
    };

    /// The packet plane only: the plane path of the commercial box.
    pub const PLANE_ONLY: PeerProfile = PeerProfile {
        versions: &[PLANE_VERSION],
        mux_carries_datagrams: false,
    };

    /// Does this server speak this wire version?
    pub fn supports(&self, version: u8) -> bool {
        self.versions.contains(&version)
    }

    /// The newest wire version this server speaks.
    pub fn newest(&self) -> u8 {
        self.versions.first().copied().unwrap_or(0)
    }

    /// Every wire version this server speaks, newest first.
    pub fn versions(&self) -> &'static [u8] {
        self.versions
    }

    /// The outcome for a hello: one implementation for every server.
    ///
    /// A version this server does not speak is refused by name, so the
    /// client can fall back to the next version down. A country this exit
    /// does not serve is refused by name too.
    pub fn decide_outcome(&self, hello: &EdgeHello, catalog: &ExitCatalog<'_>) -> EdgeOutcome {
        if !self.supports(hello.version) {
            return EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                requested: hello.version,
                supported: self.newest(),
            });
        }
        match hello.exit {
            ExitPreference::Auto => EdgeOutcome::Accepted {
                exit: ExitPreference::Auto,
            },
            ExitPreference::Country(code) => {
                if catalog.serves(code) {
                    EdgeOutcome::Accepted {
                        exit: ExitPreference::Country(code),
                    }
                } else {
                    EdgeOutcome::Refused(EdgeRefusal::CountryUnavailable { requested: code })
                }
            }
        }
    }

    /// The welcome this server answers a hello with: one implementation for
    /// every server.
    ///
    /// `face_port` is the face the box names to the client -- the face the
    /// session arrived on, or the face the box redirected the session to.
    /// `assignment` is the address the plane assigns to this client.
    ///
    /// A refusal is answered in the oldest wire shape: it carries no
    /// session, so the trailer of the accepted versions has nothing to say,
    /// and the oldest shape has no trailer at all -- it always encodes.
    pub fn welcome_for(
        &self,
        hello: &EdgeHello,
        outcome: &EdgeOutcome,
        catalog: &ExitCatalog<'_>,
        face_port: Option<u16>,
        assignment: Option<ClientAssignment>,
    ) -> Result<EdgeWelcome, EdgeSessionError> {
        if let EdgeOutcome::Refused(_) = outcome {
            return Ok(EdgeWelcome {
                version: MUX_VERSION_V1,
                countries: catalog.countries(outcome),
                outcome: *outcome,
                assigned_face_port: None,
                carries_datagrams: None,
                assigned_client: None,
            });
        }

        let version = hello.version;
        // Versions 2 and up name the face the session runs on. The wire
        // requires the trailer from version 2 on, so a session that arrived
        // on no face cannot be answered in that shape.
        let assigned_face_port = if version >= MUX_VERSION_V2 {
            Some(face_port.ok_or(EdgeSessionError::MissingAssignedFacePort)?)
        } else {
            None
        };
        // The flag says what this session carries: whole IP packets on the
        // plane, datagram flows on a version-3 mux, nothing at all before
        // that.
        let carries_datagrams = if version >= PLANE_VERSION {
            Some(self.supports(PLANE_VERSION))
        } else if version >= MUX_VERSION_V3 {
            Some(self.mux_carries_datagrams)
        } else {
            None
        };
        // Only the plane hands out an address: one per client, or two
        // clients behind one box would collide.
        let assigned_client = if version >= PLANE_VERSION { assignment } else { None };

        Ok(EdgeWelcome {
            version,
            countries: catalog.countries(outcome),
            outcome: *outcome,
            assigned_face_port,
            carries_datagrams,
            assigned_client,
        })
    }
}

// -- The exit catalogue ---------------------------------------------------

/// The countries an exit serves.
#[derive(Debug, Clone, Copy)]
pub enum ExitCatalog<'a> {
    /// The exit serves whatever country is asked for.
    ///
    /// The commercial box has one exit and no country table of its own: the
    /// country the client asks for is the one it gets.
    AnyRequested,
    /// The exit serves exactly these countries.
    Countries(&'a [CountryCode]),
}

impl ExitCatalog<'_> {
    /// Does this exit serve the country the client asked for?
    fn serves(&self, code: CountryCode) -> bool {
        match self {
            ExitCatalog::AnyRequested => true,
            ExitCatalog::Countries(countries) => countries.contains(&code),
        }
    }

    /// The countries the welcome names: the exit's own table, or the one
    /// country the client asked for.
    pub fn countries(&self, outcome: &EdgeOutcome) -> Vec<CountryCode> {
        match self {
            ExitCatalog::AnyRequested => match outcome {
                EdgeOutcome::Accepted {
                    exit: ExitPreference::Country(code),
                } => vec![*code],
                _ => Vec::new(),
            },
            ExitCatalog::Countries(countries) => countries.to_vec(),
        }
    }
}

// -- The assignment flag --------------------------------------------------

/// Does this client want the box to assign it an address?
///
/// The flag in the hello says the client can put the assigned address on
/// its tunnel adapter. A client without the flag is an older one: it cannot,
/// and the box must not hand it an address it will not use.
pub fn wants_assignment(hello: &EdgeHello) -> bool {
    hello.flags & EdgeHello::FLAG_ACCEPTS_ASSIGNMENT != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn hello(version: u8, exit: ExitPreference) -> EdgeHello {
        EdgeHello {
            version,
            exit,
            flags: 0,
            offered_ports: Vec::new(),
        }
    }

    fn country(code: &str) -> CountryCode {
        CountryCode::new(code).expect("a country code")
    }

    #[test]
    fn the_versions_are_in_one_place() {
        assert_eq!(PLANE_VERSION, 4);
        assert_eq!(MUX_VERSIONS, [3, 2, 1]);
        assert_eq!(ALL_VERSIONS, [4, 3, 2, 1]);
    }

    #[test]
    fn the_fleet_box_cannot_serve_the_plane_yet() {
        assert!(!PeerProfile::MUX_WITH_DATAGRAMS.supports(PLANE_VERSION));
        assert!(PeerProfile::MUX_WITH_DATAGRAMS.supports(MUX_VERSION_V3));
        assert_eq!(PeerProfile::MUX_WITH_DATAGRAMS.newest(), MUX_VERSION_V3);
    }

    #[test]
    fn the_plane_path_speaks_the_plane_only() {
        assert!(PeerProfile::PLANE_ONLY.supports(PLANE_VERSION));
        assert_eq!(PeerProfile::PLANE_ONLY.newest(), PLANE_VERSION);
    }

    #[test]
    fn the_mux_path_does_not_speak_the_plane() {
        // The mux path cannot carry whole IP packets: a peer that asks for
        // the plane there is refused by name, so it falls back to version 3
        // instead of getting a welcome that promises packets.
        assert!(!PeerProfile::MUX_WITHOUT_DATAGRAMS.supports(PLANE_VERSION));
        let outcome = PeerProfile::MUX_WITHOUT_DATAGRAMS.decide_outcome(
            &hello(PLANE_VERSION, ExitPreference::Auto),
            &ExitCatalog::AnyRequested,
        );
        assert_eq!(
            outcome,
            EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                requested: PLANE_VERSION,
                supported: MUX_VERSION_V3,
            })
        );
    }

    #[test]
    fn a_version_the_server_does_not_speak_is_refused_by_name() {
        let outcome = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(
            &hello(PLANE_VERSION, ExitPreference::Auto),
            &ExitCatalog::AnyRequested,
        );
        assert_eq!(
            outcome,
            EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                requested: PLANE_VERSION,
                supported: MUX_VERSION_V3,
            })
        );
    }

    #[test]
    fn the_commercial_box_serves_the_country_it_is_asked_for() {
        let outcome = PeerProfile::MUX_WITHOUT_DATAGRAMS.decide_outcome(
            &hello(MUX_VERSION_V3, ExitPreference::Country(country("NL"))),
            &ExitCatalog::AnyRequested,
        );
        assert_eq!(
            outcome,
            EdgeOutcome::Accepted {
                exit: ExitPreference::Country(country("NL"))
            }
        );
    }

    #[test]
    fn the_fleet_box_refuses_a_country_it_does_not_serve() {
        let outcome = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(
            &hello(MUX_VERSION_V3, ExitPreference::Country(country("NL"))),
            &ExitCatalog::Countries(&[country("DE")]),
        );
        assert_eq!(
            outcome,
            EdgeOutcome::Refused(EdgeRefusal::CountryUnavailable {
                requested: country("NL")
            })
        );
    }

    #[test]
    fn a_refusal_is_answered_in_the_oldest_shape() {
        let refused = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(
            &hello(PLANE_VERSION, ExitPreference::Auto),
            &ExitCatalog::AnyRequested,
        );
        let welcome = PeerProfile::MUX_WITH_DATAGRAMS
            .welcome_for(
                &hello(PLANE_VERSION, ExitPreference::Auto),
                &refused,
                &ExitCatalog::AnyRequested,
                None,
                None,
            )
            .expect("a refusal welcome");
        assert_eq!(welcome.version, MUX_VERSION_V1);
        assert_eq!(welcome.assigned_face_port, None);
        assert_eq!(welcome.carries_datagrams, None);
        // The oldest shape has no trailer, so it always encodes.
        welcome.encode().expect("the refusal welcome encodes");
    }

    #[test]
    fn an_accepted_welcome_needs_a_face_port() {
        let hello = hello(MUX_VERSION_V2, ExitPreference::Auto);
        let outcome = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let result = PeerProfile::MUX_WITH_DATAGRAMS.welcome_for(
            &hello,
            &outcome,
            &ExitCatalog::AnyRequested,
            None,
            None,
        );
        assert_eq!(result, Err(EdgeSessionError::MissingAssignedFacePort));
    }

    #[test]
    fn the_fleet_box_says_it_carries_datagrams() {
        let hello = hello(MUX_VERSION_V3, ExitPreference::Auto);
        let outcome = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let welcome = PeerProfile::MUX_WITH_DATAGRAMS
            .welcome_for(
                &hello,
                &outcome,
                &ExitCatalog::AnyRequested,
                Some(41444),
                None,
            )
            .expect("a version-3 welcome");
        assert_eq!(welcome.carries_datagrams, Some(true));
        assert_eq!(welcome.assigned_face_port, Some(41444));
    }

    #[test]
    fn the_commercial_box_says_its_mux_carries_no_datagrams() {
        let hello = hello(MUX_VERSION_V3, ExitPreference::Auto);
        let outcome = PeerProfile::MUX_WITHOUT_DATAGRAMS.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let welcome = PeerProfile::MUX_WITHOUT_DATAGRAMS
            .welcome_for(
                &hello,
                &outcome,
                &ExitCatalog::AnyRequested,
                Some(41444),
                None,
            )
            .expect("a version-3 welcome");
        assert_eq!(welcome.carries_datagrams, Some(false));
    }

    #[test]
    fn the_plane_welcome_carries_the_assigned_address() {
        let hello = hello(PLANE_VERSION, ExitPreference::Auto);
        let outcome = PeerProfile::PLANE_ONLY.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let assignment = ClientAssignment {
            addr: Ipv4Addr::new(10, 77, 0, 2),
            prefix: 24,
        };
        let welcome = PeerProfile::PLANE_ONLY
            .welcome_for(
                &hello,
                &outcome,
                &ExitCatalog::AnyRequested,
                Some(41444),
                Some(assignment),
            )
            .expect("a plane welcome");
        assert_eq!(welcome.carries_datagrams, Some(true));
        assert_eq!(welcome.assigned_client, Some(assignment));
        welcome.encode().expect("the plane welcome encodes");
    }

    #[test]
    fn a_mux_welcome_carries_no_address() {
        let hello = hello(MUX_VERSION_V3, ExitPreference::Auto);
        let outcome = PeerProfile::MUX_WITH_DATAGRAMS.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let welcome = PeerProfile::MUX_WITH_DATAGRAMS
            .welcome_for(
                &hello,
                &outcome,
                &ExitCatalog::AnyRequested,
                Some(41444),
                Some(ClientAssignment {
                    addr: Ipv4Addr::new(10, 77, 0, 2),
                    prefix: 24,
                }),
            )
            .expect("a version-3 welcome");
        assert_eq!(welcome.assigned_client, None);
    }

    #[test]
    fn only_a_client_that_asked_for_an_address_is_assigned_one() {
        assert!(!wants_assignment(&hello(PLANE_VERSION, ExitPreference::Auto)));
        assert!(wants_assignment(&EdgeHello {
            flags: EdgeHello::FLAG_ACCEPTS_ASSIGNMENT,
            ..hello(PLANE_VERSION, ExitPreference::Auto)
        }));
    }
}
