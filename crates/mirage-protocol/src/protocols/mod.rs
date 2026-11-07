//! Protocol catalog, one shelf per layer.
//!
//! Session engines live in `l3` / `l4` / `l5` / `l7`. Packet codecs live in
//! `mirage_tcpip_stack::catalog` on the same shelves. The index of both is
//! [`catalog`]. A caller enables the features of the rows it uses.

pub mod catalog;
pub mod l3;
pub mod l4;
pub mod l5;
pub mod l7;
