//! The chain this box belongs to.
//!
//! A standalone box can sit in two places: alone, as the exit of its own
//! one-hop chain, or at the front of a chain that ends somewhere else. Both
//! shapes are described by a [`ChainSpec`], and the spec can be written two
//! ways that must agree:
//!
//! * as a TOML file —
//!
//!   ```toml
//!   chain_id = "mychain"
//!
//!   [[hop]]
//!   addr = "10.0.0.5:443"
//!   public_key = "<64 hex>"
//!   role = "Exit"
//!   mask = { type = "tls_real", sni = "example.com" }
//!   ```
//!
//! * from the `server.env` chain fields — `MIRAGE_CHAIN_ID`,
//!   `MIRAGE_CHAIN_ROLE`, `MIRAGE_NEXT_HOP_ADDR`, `MIRAGE_NEXT_HOP_PUBKEY`,
//!   `MIRAGE_NEXT_HOP_MASK`.
//!
//! # The rules
//!
//! The rules below are the ones
//! [`mirage_core::config::ChainConfig::validate`] enforces, restated for a
//! box that has no monitor to gossip a peer table from:
//!
//! * a chain has at least one hop;
//! * a one-hop chain is the exit — its single hop's role is `Exit`;
//! * a multi-hop chain starts `Entry`, ends `Exit`, and everything between is
//!   `Middle`;
//! * every hop is resolvable — it names a `public_key` or a `node_id`;
//! * every hop's address carries a port.
//!
//! One rule is deliberately looser than core's: core insists on a `node_id`
//! on every hop, because in the fleet a hop is resolved through the
//! monitor's peer table. A standalone box has no peer table — its next hop
//! is named by its own public key, which is enough to dial it — so a hop
//! with a `public_key` and no `node_id` is accepted here.

use mirage_core::config::HopRole;
use mirage_core::mirage::wire::TransportCamouflage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::env::{ChainEnv, ChainRole};

/// Everything that can go wrong while reading or validating a chain.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// The chain file is not valid TOML, or not the shape this build reads.
    #[error("chain: cannot read the chain file ({reason})")]
    Malformed {
        /// Why the file was refused.
        reason: String,
    },

    /// The chain has no hops at all.
    #[error("chain: the chain has no hops")]
    EmptyChain,

    /// A one-hop chain whose hop is not the exit.
    #[error("chain: a one-hop chain must be an Exit chain")]
    SingleHopMustExit,

    /// A multi-hop chain whose roles do not run Entry, Middle…, Exit.
    #[error("chain: hop {index} has role {role:?}, which does not fit this chain")]
    BadChainRole {
        /// The offending hop's index.
        index: usize,
        /// The offending role.
        role: HopRole,
    },

    /// A hop that names neither a public key nor a node id.
    #[error("chain: hop {index} names neither a public_key nor a node_id")]
    UnresolvableHop {
        /// The offending hop's index.
        index: usize,
    },

    /// A hop whose address carries no port.
    #[error("chain: hop {index} has no port in its address")]
    HopWithoutPort {
        /// The offending hop's index.
        index: usize,
    },

    /// A hop whose public key is not 64 hex characters.
    #[error("chain: hop {index} has a malformed public_key")]
    BadPublicKey {
        /// The offending hop's index.
        index: usize,
    },

    /// A hop with no role.
    #[error("chain: hop {index} has no role")]
    MissingRole {
        /// The offending hop's index.
        index: usize,
    },

    /// A role that is not one of the three this build knows.
    #[error("chain: hop {index} has an unknown role ({role})")]
    UnknownRole {
        /// The offending hop's index.
        index: usize,
        /// The role as it was written.
        role: String,
    },

    /// The configuration names a next hop but not this box's own hop.
    #[error("chain: an entry box needs its own hop to build the chain")]
    MissingLocalHop,

    /// The configuration names a next hop the chain cannot use.
    #[error("chain: an entry box needs a next hop, and none is configured")]
    MissingNextHop,

    /// The chain fields do not say where this box stands in the chain.
    #[error("chain: the chain does not say where this box stands in it")]
    MissingChainPosition,

    /// The chain says one number of hops and names another.
    #[error("chain: the chain says {expected} hop(s), but {found} were named")]
    HopCountMismatch {
        /// How many hops the chain says it has.
        expected: usize,
        /// How many were actually named.
        found: usize,
    },

    /// The chain's position is outside the chain.
    #[error("chain: position {index} is outside a chain of {length} hop(s)")]
    PositionOutsideChain {
        /// The offending position.
        index: usize,
        /// How many hops the chain has.
        length: usize,
    },

    /// The short description cannot build a middle hop.
    #[error("chain: the short chain description cannot build a middle hop — the whole chain has to be named")]
    MiddleNeedsFullChain,

    /// The short description cannot build an edge.
    #[error("chain: the short chain description cannot build an edge — the whole chain has to be named")]
    EdgeNeedsFullChain,
}

/// What the hop at `index` does in a chain of `length` hops.
///
/// The first hop receives the client, the last one sends it out to the
/// internet, and everything between relays onward. A chain of one hop is
/// the exit: it receives the client and exits by itself.
fn role_for_position(index: usize, length: usize) -> HopRole {
    if length <= 1 {
        HopRole::Exit
    } else if index == 0 {
        HopRole::Entry
    } else if index + 1 == length {
        HopRole::Exit
    } else {
        HopRole::Middle
    }
}

/// One hop of a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHop {
    /// `host:port` of the hop.
    pub addr: String,
    /// The hop's X25519 public key, hex.
    pub public_key: Option<String>,
    /// The hop's node id, when it is known by one.
    pub node_id: Option<String>,
    /// What the hop does.
    pub role: HopRole,
    /// The mask the hop wears, when one is configured.
    pub camouflage: Option<TransportCamouflage>,
    /// `host:port` of the hop's DATAGRAM door — where the chain's datagrams
    /// are answered.
    ///
    /// A hop that has one answers the chain's datagram-native leg on it, with
    /// the V9 datagram handshake and a real UDP socket behind it — datagrams
    /// stay datagrams the whole way, and never ride a stream. `None` means the
    /// hop carries no datagrams, and the chain is a TCP chain.
    pub udp_addr: Option<String>,
}

/// A whole chain, in the order the client traverses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSpec {
    /// The chain's id.
    pub chain_id: String,
    /// The hops, first to last. The last one is the exit.
    pub hops: Vec<ChainHop>,
}

impl ChainSpec {
    /// The DATAGRAM chain's id — the chain of its own that carries datagrams.
    ///
    /// The datagram leg is not the stream leg with another mask on it: it is a
    /// chain of its own, with its own hops, its own handshake and its own exit.
    /// Giving it its own id is what keeps the two planes apart in the node's
    /// registry, and it is not a naming convenience — a listener is addressed
    /// by `{chain_id}-h{position}`, so a shared id would mean the stream hop
    /// and the datagram hop wanted the same address, and only one of them
    /// could hold it.
    pub fn datagram_chain_id(&self) -> String {
        format!("{}-dgram", self.chain_id)
    }

    /// Whether this chain carries DATAGRAMS at all.
    ///
    /// True when every hop has a datagram door. A datagram leg cannot skip a
    /// hop: a chain that carried datagrams only halfway would deliver them
    /// out of the wrong box, which is worse than not carrying them at all.
    pub fn carries_datagrams(&self) -> bool {
        !self.hops.is_empty() && self.hops.iter().all(|hop| hop.udp_addr.is_some())
    }
}

/// The chain file's own shape.
#[derive(Debug, Deserialize)]
struct ChainFile {
    /// The chain's id.
    chain_id: String,
    /// The hops.
    #[serde(default)]
    hop: Vec<ChainHopFile>,
}

/// One hop as the chain file writes it.
#[derive(Debug, Deserialize)]
struct ChainHopFile {
    /// `host:port`.
    addr: String,
    /// The hop's public key, hex.
    #[serde(default)]
    public_key: Option<String>,
    /// The hop's node id.
    #[serde(default)]
    node_id: Option<String>,
    /// The hop's role — `entry`, `middle` or `exit`, in any case.
    #[serde(default)]
    role: Option<String>,
    /// The mask the hop wears.
    #[serde(default)]
    mask: Option<TransportCamouflage>,
    /// The hop's DATAGRAM door — `host:port` — when it has one.
    ///
    /// A hop with one answers the chain's datagram-native leg on it; a hop
    /// without one carries TCP only.
    #[serde(default)]
    udp_addr: Option<String>,
}

impl ChainSpec {
    /// Read a chain from its TOML form.
    ///
    /// The file is validated before it is returned: a chain that does not
    /// satisfy the rules is refused here, not at the first dial.
    pub fn from_toml_str(text: &str) -> Result<Self, ChainError> {
        let file: ChainFile =
            toml::from_str(text).map_err(|e| ChainError::Malformed { reason: e.to_string() })?;

        let mut hops = Vec::with_capacity(file.hop.len());
        for (index, hop) in file.hop.iter().enumerate() {
            let role = match hop.role.as_deref().map(str::trim) {
                None | Some("") => return Err(ChainError::MissingRole { index }),
                Some(raw) => parse_role(raw).ok_or_else(|| ChainError::UnknownRole {
                    index,
                    role: raw.to_owned(),
                })?,
            };
            if let Some(key) = hop.public_key.as_deref() {
                if key.len() != 64 || hex::decode(key).is_err() {
                    return Err(ChainError::BadPublicKey { index });
                }
            }
            hops.push(ChainHop {
                addr: hop.addr.clone(),
                public_key: hop.public_key.clone(),
                node_id: hop.node_id.clone(),
                role,
                camouflage: hop.mask.clone(),
                udp_addr: hop.udp_addr.clone(),
            });
        }

        let spec = Self {
            chain_id: file.chain_id,
            hops,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Build the chain from the `server.env` chain fields.
    ///
    /// `local` is this box's own hop — its published address and its own wire
    /// public key.
    ///
    /// * An **exit** box is the end of its own chain: the chain is one hop,
    ///   this box, with the `Exit` role.
    /// * An **entry** box relays onward: the chain is this box as `Entry`,
    ///   then the configured next hop as `Exit`.
    ///
    /// The result is the same chain the equivalent TOML file describes — the
    /// two are two spellings of one thing, and the tests hold them to it.
    pub fn from_env(env: &ChainEnv, local: ChainHop) -> Result<Self, ChainError> {
        let hops = match env.role {
            ChainRole::Exit => vec![ChainHop {
                role: HopRole::Exit,
                ..local
            }],
            ChainRole::Middle => return Err(ChainError::MiddleNeedsFullChain),
            // The edge owns the chain and is not a hop of it — the short
            // description cannot say what the chain is. The whole chain has to
            // be named.
            ChainRole::Edge => return Err(ChainError::EdgeNeedsFullChain),
            ChainRole::Entry => {
                let next = env.next_hop.as_ref().ok_or(ChainError::MissingNextHop)?;
                vec![
                    ChainHop {
                        role: HopRole::Entry,
                        ..local
                    },
                    ChainHop {
                        addr: next.addr.clone(),
                        public_key: Some(next.public_key.clone()),
                        node_id: None,
                        role: HopRole::Exit,
                        camouflage: next.camouflage.clone(),
                        udp_addr: None,
                    },
                ]
            }
        };
        let spec = Self {
            chain_id: env.chain_id.clone(),
            hops,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Build the chain from the WHOLE chain the env file describes.
    ///
    /// The whole chain is written to every box in it, and each box knows its
    /// own place in it by position. That is what lets the exit box recognise
    /// the entry box: an exit box told only about "the hop after me" has
    /// never heard of the one in front of it, and has no way to accept its
    /// leg.
    ///
    /// The chain's hops are the boxes that RELAY. The box the customer knocks
    /// on is the chain's **edge**: it is not a hop of its own chain, it owns
    /// the chain and dials it. That is the fleet's rule, and this build keeps
    /// it — an edge that was also hop 0 would have to serve its own chain's
    /// listener and accept legs it never asked for.
    ///
    /// `local` is this box's own hop — its own address, its own key, its own
    /// face. The box's own row is taken from the box and never from the
    /// file: a file that lies about the box itself would put a wrong key in
    /// the box's own peer table, and the box would then fail to recognise
    /// itself. For the edge the row is not used at all — the edge is not in
    /// the hop list.
    pub fn from_env_full(env: &ChainEnv, local: ChainHop) -> Result<Self, ChainError> {
        let Some(length) = env.length else {
            return Err(ChainError::MissingChainPosition);
        };
        if length == 0 {
            return Err(ChainError::EmptyChain);
        }
        if let Some(position) = env.position {
            if position >= length {
                return Err(ChainError::PositionOutsideChain {
                    index: position,
                    length,
                });
            }
        }
        if env.hops.len() != length {
            return Err(ChainError::HopCountMismatch {
                expected: length,
                found: env.hops.len(),
            });
        }

        let mut hops: Vec<ChainHop> = env
            .hops
            .iter()
            .enumerate()
            .map(|(index, hop)| ChainHop {
                addr: hop.addr.clone(),
                public_key: Some(hop.public_key.clone()),
                node_id: None,
                role: role_for_position(index, length),
                camouflage: hop.camouflage.clone(),
                udp_addr: hop.udp_addr.clone(),
            })
            .collect();
        // The box's own hop is the box's own truth — and only a hop of the
        // chain has one.
        if let Some(position) = env.position {
            hops[position] = ChainHop {
                role: hops[position].role,
                ..local
            };
        }

        let spec = Self {
            chain_id: env.chain_id.clone(),
            hops,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Check the chain against the rules.
    ///
    /// See the module doc for what each rule is and why the resolvable-hop
    /// rule is looser here than in core.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.hops.is_empty() {
            return Err(ChainError::EmptyChain);
        }
        if self.hops.len() == 1 {
            if self.hops[0].role != HopRole::Exit {
                return Err(ChainError::SingleHopMustExit);
            }
        } else {
            if self.hops[0].role != HopRole::Entry {
                return Err(ChainError::BadChainRole {
                    index: 0,
                    role: self.hops[0].role,
                });
            }
            let last = self.hops.len() - 1;
            if self.hops[last].role != HopRole::Exit {
                return Err(ChainError::BadChainRole {
                    index: last,
                    role: self.hops[last].role,
                });
            }
            for (index, hop) in self.hops.iter().enumerate().skip(1).take(last - 1) {
                if hop.role != HopRole::Middle {
                    return Err(ChainError::BadChainRole {
                        index,
                        role: hop.role,
                    });
                }
            }
        }
        for (index, hop) in self.hops.iter().enumerate() {
            if hop.public_key.is_none() && hop.node_id.is_none() {
                return Err(ChainError::UnresolvableHop { index });
            }
            if !addr_has_port(&hop.addr) {
                return Err(ChainError::HopWithoutPort { index });
            }
        }
        Ok(())
    }
}

/// Parse a role as written in a chain file.
///
/// Case does not matter: `Exit`, `exit` and `EXIT` are the same role.
fn parse_role(raw: &str) -> Option<HopRole> {
    match raw.to_ascii_lowercase().as_str() {
        "entry" => Some(HopRole::Entry),
        "middle" => Some(HopRole::Middle),
        "exit" => Some(HopRole::Exit),
        _ => None,
    }
}

/// `true` for an address that carries a port.
fn addr_has_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{ChainHopEnv, NextHop};

    fn pubkey(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn local_hop() -> ChainHop {
        ChainHop {
            addr: "203.0.113.7:443".to_owned(),
            public_key: Some(pubkey(1)),
            node_id: None,
            role: HopRole::Exit,
            camouflage: None,
            udp_addr: None,
        }
    }

    #[test]
    fn the_whole_chain_puts_the_box_where_it_was_told() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "stand-2hop".to_owned(),
            role: ChainRole::Exit,
            next_hop: None,
            position: Some(1),
            length: Some(2),
            hops: vec![
                ChainHopEnv {
                    addr: "203.0.113.1:443".to_owned(),
                    public_key: pubkey(1),
                    camouflage: None,
                    udp_addr: None,
                },
                ChainHopEnv {
                    addr: "203.0.113.2:443".to_owned(),
                    public_key: pubkey(2),
                    camouflage: None,
                    udp_addr: None,
                },
            ],
        };
        let mut local = local_hop();
        local.role = HopRole::Exit;
        let spec = ChainSpec::from_env_full(&env, local).expect("the whole chain");
        assert_eq!(spec.chain_id, "stand-2hop");
        assert_eq!(spec.hops.len(), 2);
        assert_eq!(spec.hops[0].role, HopRole::Entry);
        assert_eq!(spec.hops[1].role, HopRole::Exit);
        // The box's own row is the box's own truth — the file may say
        // anything about it, and the file is not the box.
        assert_eq!(spec.hops[1].addr, "203.0.113.7:443");
        assert_eq!(spec.hops[1].public_key, Some(pubkey(1)));
        // The hop before it is known — that is the whole point of writing the
        // whole chain into every box.
        assert_eq!(spec.hops[0].addr, "203.0.113.1:443");
        assert_eq!(spec.hops[0].public_key, Some(pubkey(1)));
    }

    #[test]
    fn a_three_hop_chain_has_a_middle() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "stand-3hop".to_owned(),
            role: ChainRole::Middle,
            next_hop: None,
            position: Some(1),
            length: Some(3),
            hops: vec![
                ChainHopEnv {
                    addr: "203.0.113.1:443".to_owned(),
                    public_key: pubkey(1),
                    camouflage: None,
                    udp_addr: None,
                },
                ChainHopEnv {
                    addr: "203.0.113.2:443".to_owned(),
                    public_key: pubkey(2),
                    camouflage: None,
                    udp_addr: None,
                },
                ChainHopEnv {
                    addr: "203.0.113.3:443".to_owned(),
                    public_key: pubkey(3),
                    camouflage: None,
                    udp_addr: None,
                },
            ],
        };
        let mut local = local_hop();
        local.role = HopRole::Middle;
        let spec = ChainSpec::from_env_full(&env, local).expect("the whole chain");
        assert_eq!(spec.hops[0].role, HopRole::Entry);
        assert_eq!(spec.hops[1].role, HopRole::Middle);
        assert_eq!(spec.hops[2].role, HopRole::Exit);
    }

    #[test]
    fn a_chain_that_does_not_name_its_position_is_refused() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "c".to_owned(),
            role: ChainRole::Exit,
            next_hop: None,
            position: None,
            length: None,
            hops: Vec::new(),
        };
        assert_eq!(
            ChainSpec::from_env_full(&env, local_hop()).expect_err("no position"),
            ChainError::MissingChainPosition
        );
    }

    #[test]
    fn a_malformed_public_key_is_refused() {
        let spec = ChainSpec::from_toml_str(
            "chain_id = \"mychain\"\n\
             [[hop]]\n\
             addr = \"10.0.0.5:443\"\n\
             public_key = \"aa\"\n\
             role = \"Exit\"\n",
        );
        // A malformed public key is caught before the role rule — both are
        // refusals, and the key one comes first.
        assert_eq!(spec.err(), Some(ChainError::BadPublicKey { index: 0 }));
    }

    #[test]
    fn a_one_hop_chain_with_a_good_key_is_accepted() {
        let spec = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\n\
             addr = \"10.0.0.5:443\"\n\
             public_key = \"{}\"\n\
             role = \"Exit\"\n",
            pubkey(2)
        ))
        .expect("a one-hop exit chain is valid");
        assert_eq!(spec.chain_id, "mychain");
        assert_eq!(spec.hops.len(), 1);
        assert_eq!(spec.hops[0].role, HopRole::Exit);
    }

    #[test]
    fn a_one_hop_chain_that_is_not_the_exit_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\n\
             addr = \"10.0.0.5:443\"\n\
             public_key = \"{}\"\n\
             role = \"Entry\"\n",
            pubkey(3)
        ))
        .expect_err("must refuse");
        assert_eq!(err, ChainError::SingleHopMustExit);
    }

    #[test]
    fn a_three_hop_chain_entry_middle_exit_is_accepted() {
        let spec = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.1:443\"\npublic_key = \"{}\"\nrole = \"Entry\"\n\
             [[hop]]\naddr = \"10.0.0.2:443\"\npublic_key = \"{}\"\nrole = \"Middle\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Exit\"\n",
            pubkey(4),
            pubkey(5),
            pubkey(6)
        ))
        .expect("a well-formed chain is valid");
        assert_eq!(spec.hops.len(), 3);
        assert_eq!(spec.hops[1].role, HopRole::Middle);
    }

    #[test]
    fn a_multi_hop_chain_that_does_not_start_at_the_entry_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.2:443\"\npublic_key = \"{}\"\nrole = \"Middle\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Exit\"\n",
            pubkey(7),
            pubkey(8)
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            ChainError::BadChainRole {
                index: 0,
                role: HopRole::Middle
            }
        );
    }

    #[test]
    fn a_multi_hop_chain_that_does_not_end_at_the_exit_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.1:443\"\npublic_key = \"{}\"\nrole = \"Entry\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Middle\"\n",
            pubkey(9),
            pubkey(10)
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            ChainError::BadChainRole {
                index: 1,
                role: HopRole::Middle
            }
        );
    }

    #[test]
    fn a_middle_hop_that_is_not_middle_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.1:443\"\npublic_key = \"{}\"\nrole = \"Entry\"\n\
             [[hop]]\naddr = \"10.0.0.2:443\"\npublic_key = \"{}\"\nrole = \"Entry\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Exit\"\n",
            pubkey(11),
            pubkey(12),
            pubkey(13)
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            ChainError::BadChainRole {
                index: 1,
                role: HopRole::Entry
            }
        );
    }

    #[test]
    fn an_empty_chain_is_refused() {
        let err = ChainSpec::from_toml_str("chain_id = \"mychain\"\n").expect_err("must refuse");
        assert_eq!(err, ChainError::EmptyChain);
    }

    #[test]
    fn a_hop_with_neither_key_nor_node_id_is_refused() {
        let err = ChainSpec::from_toml_str(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\nrole = \"Exit\"\n",
        )
        .expect_err("must refuse");
        assert_eq!(err, ChainError::UnresolvableHop { index: 0 });
    }

    #[test]
    fn a_hop_with_only_a_node_id_is_accepted() {
        let spec = ChainSpec::from_toml_str(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\nnode_id = \"node-abc\"\nrole = \"Exit\"\n",
        )
        .expect("a node id resolves a hop");
        assert_eq!(spec.hops[0].node_id.as_deref(), Some("node-abc"));
    }

    #[test]
    fn a_hop_without_a_port_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5\"\npublic_key = \"{}\"\nrole = \"Exit\"\n",
            pubkey(14)
        ))
        .expect_err("must refuse");
        assert_eq!(err, ChainError::HopWithoutPort { index: 0 });
    }

    #[test]
    fn a_hop_without_a_role_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\n",
            pubkey(15)
        ))
        .expect_err("must refuse");
        assert_eq!(err, ChainError::MissingRole { index: 0 });
    }

    #[test]
    fn an_unknown_role_is_refused() {
        let err = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Sideways\"\n",
            pubkey(16)
        ))
        .expect_err("must refuse");
        assert_eq!(
            err,
            ChainError::UnknownRole {
                index: 0,
                role: "Sideways".to_owned()
            }
        );
    }

    #[test]
    fn a_broken_chain_file_is_refused() {
        let err = ChainSpec::from_toml_str("this is not toml").expect_err("must refuse");
        assert!(matches!(err, ChainError::Malformed { .. }));
    }

    #[test]
    fn the_mask_is_read_from_the_chain_file() {
        let spec = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Exit\"\n\
             mask = {{ type = \"tls_real\", sni = \"example.com\" }}\n",
            pubkey(17)
        ))
        .expect("a chain with a mask is valid");
        assert!(matches!(
            spec.hops[0].camouflage,
            Some(TransportCamouflage::TlsReal { .. })
        ));
    }

    #[test]
    fn the_env_and_the_toml_describe_the_same_chain() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "mychain".to_owned(),
            role: ChainRole::Entry,
            next_hop: Some(NextHop {
                addr: "10.0.0.5:443".to_owned(),
                public_key: pubkey(18),
                camouflage: Some(TransportCamouflage::TlsReal {
                    sni: "example.com".to_owned(),
                    alpn: vec![],
                }),
            }),
            position: None,
            length: None,
            hops: Vec::new(),
        };
        let from_env = ChainSpec::from_env(&env, local_hop()).expect("from env");

        let from_toml = ChainSpec::from_toml_str(&format!(
            "chain_id = \"mychain\"\n\
             [[hop]]\naddr = \"203.0.113.7:443\"\npublic_key = \"{}\"\nrole = \"Entry\"\n\
             [[hop]]\naddr = \"10.0.0.5:443\"\npublic_key = \"{}\"\nrole = \"Exit\"\n\
             mask = {{ type = \"tls_real\", sni = \"example.com\" }}\n",
            pubkey(1),
            pubkey(18)
        ))
        .expect("from toml");

        assert_eq!(from_env, from_toml);
    }

    #[test]
    fn an_exit_box_is_the_end_of_its_own_chain() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "solo".to_owned(),
            role: ChainRole::Exit,
            next_hop: None,
            position: None,
            length: None,
            hops: Vec::new(),
        };
        let spec = ChainSpec::from_env(&env, local_hop()).expect("from env");
        assert_eq!(spec.hops.len(), 1);
        assert_eq!(spec.hops[0].role, HopRole::Exit);
        assert_eq!(spec.hops[0].addr, "203.0.113.7:443");
    }

    #[test]
    fn an_entry_box_without_a_next_hop_is_refused() {
        let env = ChainEnv {
            operator_pubkey_hex: None,
            operator_secret_hex: None,
            mesh_id: None,
            udp_port: None,
            chain_id: "mychain".to_owned(),
            role: ChainRole::Entry,
            next_hop: None,
            position: None,
            length: None,
            hops: Vec::new(),
        };
        let err = ChainSpec::from_env(&env, local_hop()).expect_err("must refuse");
        assert_eq!(err, ChainError::MissingNextHop);
    }
}
