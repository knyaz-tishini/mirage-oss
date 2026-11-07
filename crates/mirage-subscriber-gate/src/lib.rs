//! The subscriber gate: everything an edge needs to authenticate a paying
//! customer's V9 dial and dispatch his tunnel, extracted out of
//! `mirage-node` (`docs/mirage/plans/2026-09-24-edge-as-entry.md`, "The
//! subscriber gate moves out of `mirage-node`"). `mirage-node` keeps no
//! subscriber-entrance code path at all — every accepted dial on an
//! ordinary node is a mesh-credential chain-hop dial. This crate is
//! `mirage-edge`'s own entrance gate instead.
//!
//! - [`subscriber_keys`] — the installed set of subscriber static X25519
//!   public keys (`SubscriberKeyStore`), loaded from a local file and
//!   hot-reloaded.
//! - [`entrance_auth`] — classifying what a V9 ClientHello presented
//!   (`PresentedCredential`) and composing the edge's mesh gate with the
//!   subscriber store into one `client_auth` predicate
//!   (`make_entrance_auth`), plus resolving which `mesh_id` a subscriber's
//!   own handshake verifies against (`resolve_entrance_mesh_id`).
//! - [`bandwidth_cap`] — the per-subscriber byte-rate cap
//!   (`SubscriberBandwidthRegistry`/`ConnectionBandwidthLimiter`).
//! - [`entrance_dispatch`] — resolving a connection's bandwidth cap
//!   (`resolve_subscriber_cap`) and the `Tunnel`-to-`Tunnel` pump
//!   (`copy_tunnel_to_tunnel_capped`) `mirage-edge` drives between a
//!   subscriber's accepted tunnel and the mesh chain it dialled for him.
//!
//! The V9 driver primitives these modules call
//! (`mirage_protocol::driver::handshake_server_stream_with_auth`, the
//! generic auth-predicate closure shape) are unchanged and stay in
//! `mirage-protocol` — only the subscriber-specific predicate, state, and
//! post-auth dispatch live here.

pub mod bandwidth_cap;
pub mod entrance_auth;
pub mod entrance_dispatch;
pub mod subscriber_keys;
