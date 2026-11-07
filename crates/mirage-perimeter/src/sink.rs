//! The perimeter's reporting contract.
//!
//! This crate DEFINES [`ObservationSink`] but does not implement it — the
//! whole point of the arc3 core/periphery split (see `src/lib.rs`'s module
//! doc) is that a perimeter component only ever REPORTS what it saw; it
//! never decides what happens next. Deciding is the arbiter's (`mirage-secd`)
//! job, and the arbiter is not a dependency of this crate (that would put
//! the edge right back, just pointing the other way). Whoever builds the
//! not-yet-built perimeter service wires a concrete sink at construction
//! time — today that means tests in this crate supply a trivial in-memory
//! recorder; eventually it means an IPC/wire client that forwards each
//! observation to the arbiter running in its own process.

use mirage_core::perimeter_observation::PerimeterObservation;

/// Receives [`PerimeterObservation`] rows as a perimeter component emits
/// them.
///
/// Implementations MUST NOT block the caller for long — `decoy.rs` calls
/// [`ObservationSink::report`] inline on the per-connection handler task, so
/// a slow implementation (e.g. a synchronous network call) would throttle
/// the accept loop's ability to keep servicing other decoy touches.
/// Implementations that need to do slow work should hand off internally
/// (e.g. push onto an unbounded channel and drain it from a separate task).
pub trait ObservationSink: Send + Sync + 'static {
    /// Report one observation.
    fn report(&self, observation: PerimeterObservation);
}
