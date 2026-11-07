//! Shared control-plane types — monitor↔node WS frames + AnyListenerSpec wrapper.
//!
//! The monitor pushes listeners through [`AnyListenerSpec`]; the node
//! parses and dispatches by `family` discriminator.

pub mod any_listener_spec;
pub mod node_frame;

pub use any_listener_spec::AnyListenerSpec;
pub use node_frame::NodeFrame;
