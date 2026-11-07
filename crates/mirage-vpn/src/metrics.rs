//! The box's counters and the `/metrics` endpoint.
//!
//! # What this is
//!
//! A tiny registry: named counters and gauges, and a Prometheus text
//! renderer over them. No dependency, no framework — the box speaks plain
//! HTTP on one socket and answers `GET /metrics` with the text.
//!
//! # Why the counters matter
//!
//! A packet that is dropped where nobody looks is a packet the operator
//! cannot account for. Every silent overflow point gets a counter here, and
//! the counters are readable over HTTP: a drop is then a number, not a
//! silence.
//!
//! ```
//! # use mirage_vpn::metrics::{Kind, Metrics};
//! let metrics = Metrics::new();
//! metrics.register("mirage_test_total", Kind::Counter, "a test counter");
//! metrics.add("mirage_test_total", 3);
//! let text = metrics.render();
//! assert!(text.contains("mirage_test_total 3"));
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Where the numbers that live outside the registry come from.
///
/// The packet plane keeps its own counters, so the endpoint asks a closure
/// for them at scrape time: the closure answers `(name, kind, help, value)`
/// for every number the registry does not own.
pub type ExtraSource = Arc<dyn Fn() -> Vec<(String, Kind, String, u64)> + Send + Sync>;

/// Wrap a closure into the source the endpoint asks for the extra numbers.
pub fn extra_source<F>(f: F) -> ExtraSource
where
    F: Fn() -> Vec<(String, Kind, String, u64)> + Send + Sync + 'static,
{
    Arc::new(f)
}

/// The source that has nothing to add: the registry alone.
pub fn no_extra() -> ExtraSource {
    Arc::new(|| Vec::new())
}

/// What kind of number a metric holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Only goes up.
    Counter,
    /// Goes up and down.
    Gauge,
}

impl Kind {
    /// The Prometheus type name.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        }
    }
}

/// One metric: a number and what it means.
#[derive(Debug)]
struct Metric {
    kind: Kind,
    help: String,
    value: AtomicU64,
}

/// The box's registry of metrics.
///
/// The registry is cheap to clone into a task — it is one mutex and a map.
#[derive(Debug, Default)]
pub struct Metrics {
    metrics: Mutex<HashMap<String, Metric>>,
}

impl Metrics {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(HashMap::new()),
        }
    }

    /// Declare a metric and what it means.
    ///
    /// Declaring the same name twice keeps the first declaration — the help
    /// text of a metric must not change under the operator's feet.
    pub fn register(&self, name: &str, kind: Kind, help: &str) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.entry(name.to_owned()).or_insert_with(|| Metric {
            kind,
            help: help.to_owned(),
            value: AtomicU64::new(0),
        });
    }

    /// Add to a counter. A metric that was never declared is declared on the
    /// spot — a counter that only shows up when it moves is still a counter.
    pub fn add(&self, name: &str, amount: u64) {
        self.register(name, Kind::Counter, name);
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(metric) = metrics.get_mut(name) {
            metric.value.fetch_add(amount, Ordering::Relaxed);
        }
    }

    /// Add one to a counter.
    pub fn inc(&self, name: &str) {
        self.add(name, 1);
    }

    /// Set a gauge.
    pub fn set(&self, name: &str, value: u64) {
        self.register(name, Kind::Gauge, name);
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(metric) = metrics.get_mut(name) {
            metric.value.store(value, Ordering::Relaxed);
        }
    }

    /// Read one metric.
    pub fn get(&self, name: &str) -> u64 {
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics
            .get(name)
            .map(|metric| metric.value.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// The whole registry as Prometheus text.
    pub fn render(&self) -> String {
        self.render_with(&[])
    }

    /// The registry as Prometheus text, plus numbers that live elsewhere.
    ///
    /// `extra` is `(name, kind, help, value)`. It is how a component that
    /// keeps its own counters — the packet plane does — joins the endpoint
    /// without the registry having to own its state.
    pub fn render_with(&self, extra: &[(String, Kind, String, u64)]) -> String {
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<&String> = metrics.keys().collect();
        names.sort();

        let mut out = String::new();
        for name in names {
            let Some(metric) = metrics.get(name) else {
                continue;
            };
            let _ = writeln!(out, "# HELP {} {}", name, metric.help);
            let _ = writeln!(out, "# TYPE {} {}", name, metric.kind.as_str());
            let _ = writeln!(out, "{} {}", name, metric.value.load(Ordering::Relaxed));
        }
        for (name, kind, help, value) in extra {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {}", kind.as_str());
            let _ = writeln!(out, "{name} {value}");
        }
        out
    }
}

/// The counters of the box's TUN device.
///
/// The device runs on OS threads that outlive any one task, so the numbers
/// they keep live here, in one place the endpoint can read them from.
#[derive(Debug)]
pub struct DeviceCounters {
    dropped_channel_full: AtomicU64,
    write_channel_full: AtomicU64,
}

/// The device counters as plain numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceStats {
    /// The packets the device's reader dropped because the channel to the
    /// plane was full.
    pub dropped_channel_full: u64,
    /// The times the channel from the plane was full when the device's
    /// writer looked at it.
    pub write_channel_full: u64,
}

impl DeviceCounters {
    /// A fresh set of counters.
    pub const fn new() -> Self {
        Self {
            dropped_channel_full: AtomicU64::new(0),
            write_channel_full: AtomicU64::new(0),
        }
    }

    /// The counters as plain numbers.
    pub fn stats(&self) -> DeviceStats {
        DeviceStats {
            dropped_channel_full: self.dropped_channel_full.load(Ordering::Relaxed),
            write_channel_full: self.write_channel_full.load(Ordering::Relaxed),
        }
    }

    /// Count a packet the reader dropped because the channel was full.
    ///
    /// Returns the new count, so the caller can log once in a while.
    pub fn note_dropped_channel_full(&self) -> u64 {
        self.dropped_channel_full.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Count a time the channel from the plane was full.
    ///
    /// Returns the new count, so the caller can log once in a while.
    pub fn note_write_channel_full(&self) -> u64 {
        self.write_channel_full.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// The counters of this process's TUN device.
pub static DEVICE_COUNTERS: DeviceCounters = DeviceCounters::new();

// -----------------------------------------------------------------------------
// The names of the plane's metrics
// -----------------------------------------------------------------------------

/// The packets that came out of the box's TUN device.
pub const PLANE_PACKETS_FROM_TUN: &str = "mirage_ip_plane_packets_from_tun";
/// The packets that went into the box's TUN device.
pub const PLANE_PACKETS_TO_TUN: &str = "mirage_ip_plane_packets_to_tun";
/// The packets dropped because nobody owns their destination.
pub const PLANE_DROPPED_UNKNOWN_DESTINATION: &str = "mirage_ip_plane_dropped_unknown_destination";
/// The packets dropped because they were too large.
pub const PLANE_DROPPED_TOO_LARGE: &str = "mirage_ip_plane_dropped_too_large";
/// The packets dropped because they were not an IP packet at all.
pub const PLANE_DROPPED_NOT_IP: &str = "mirage_ip_plane_dropped_not_ip";
/// The packets dropped because their source is not the assigned address.
pub const PLANE_DROPPED_PEER_ADDRESS_MISMATCH: &str =
    "mirage_ip_plane_dropped_peer_address_mismatch";
/// The writes that failed.
pub const PLANE_WRITE_ERRORS: &str = "mirage_ip_plane_write_errors";
/// The peers the plane knows.
pub const PLANE_PEERS: &str = "mirage_ip_plane_peers";
/// The packets the device's reader dropped because the channel was full.
pub const DEVICE_DROPPED_CHANNEL_FULL: &str = "mirage_ip_plane_device_dropped_channel_full";
/// The times the channel from the plane was full when the writer looked.
pub const DEVICE_WRITE_CHANNEL_FULL: &str = "mirage_ip_plane_device_write_channel_full";

/// The numbers of the packet plane, in the shape the endpoint shows them.
///
/// The plane keeps its own counters, so the endpoint asks for them at scrape
/// time: this is what it turns them into -- `(name, kind, help, value)` for
/// every one of them.
pub fn plane_metrics(
    stats: &crate::ip_plane::IpPlaneStats,
    peers: usize,
) -> Vec<(String, Kind, String, u64)> {
    vec![
        (
            PLANE_PACKETS_FROM_TUN.to_owned(),
            Kind::Counter,
            "The packets that came out of the box's tun device.".to_owned(),
            stats.from_tun,
        ),
        (
            PLANE_PACKETS_TO_TUN.to_owned(),
            Kind::Counter,
            "The packets that went into the box's tun device.".to_owned(),
            stats.to_tun,
        ),
        (
            PLANE_DROPPED_UNKNOWN_DESTINATION.to_owned(),
            Kind::Counter,
            "The packets dropped because no peer owns their destination.".to_owned(),
            stats.dropped_unknown,
        ),
        (
            PLANE_DROPPED_TOO_LARGE.to_owned(),
            Kind::Counter,
            "The packets dropped because they were too large to carry.".to_owned(),
            stats.dropped_too_large,
        ),
        (
            PLANE_DROPPED_NOT_IP.to_owned(),
            Kind::Counter,
            "The packets dropped because they were not an IP packet.".to_owned(),
            stats.dropped_not_ip,
        ),
        (
            PLANE_DROPPED_PEER_ADDRESS_MISMATCH.to_owned(),
            Kind::Counter,
            "The packets dropped because their source is not the assigned address.".to_owned(),
            stats.peer_address_mismatch,
        ),
        (
            PLANE_WRITE_ERRORS.to_owned(),
            Kind::Counter,
            "The writes of the plane that failed.".to_owned(),
            stats.write_errors,
        ),
        (
            PLANE_PEERS.to_owned(),
            Kind::Gauge,
            "The peers the plane knows.".to_owned(),
            peers as u64,
        ),
    ]
}

/// The numbers of the box's TUN device, in the shape the endpoint shows them.
pub fn device_metrics() -> Vec<(String, Kind, String, u64)> {
    let stats = DEVICE_COUNTERS.stats();
    vec![
        (
            DEVICE_DROPPED_CHANNEL_FULL.to_owned(),
            Kind::Counter,
            "The packets the tun reader dropped because its channel was full.".to_owned(),
            stats.dropped_channel_full,
        ),
        (
            DEVICE_WRITE_CHANNEL_FULL.to_owned(),
            Kind::Counter,
            "The times the tun writer found its channel full.".to_owned(),
            stats.write_channel_full,
        ),
    ]
}

/// Every way the metrics endpoint can fail.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// The socket could not be bound.
    #[error("the metrics endpoint could not be bound: {0}")]
    Bind(String),
    /// The endpoint stopped.
    #[error("the metrics endpoint stopped: {0}")]
    Io(String),
}

/// Serve the registry over HTTP until the task is dropped.
///
/// `GET /metrics` answers the Prometheus text; anything else answers 404.
/// The endpoint speaks just enough HTTP for a scraper and nothing more.
///
/// `extra` is asked for the numbers the registry does not own -- the packet
/// plane's counters, for one -- and what it answers is merged into the text.
/// A source that answers nothing leaves the text as the registry alone.
pub async fn serve(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    extra: ExtraSource,
) -> Result<(), MetricsError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| MetricsError::Bind(format!("{addr}: {err}")))?;
    let bound = listener
        .local_addr()
        .map_err(|err| MetricsError::Bind(format!("{addr}: {err}")))?;
    tracing::info!(%bound, "the metrics endpoint is up");

    loop {
        let (mut socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(%err, "the metrics endpoint could not accept a connection");
                continue;
            }
        };
        let metrics = Arc::clone(&metrics);
        let extra = Arc::clone(&extra);

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let count = match socket.read(&mut buf).await {
                Ok(count) => count,
                Err(err) => {
                    tracing::debug!(%peer, %err, "the metrics request could not be read");
                    return;
                }
            };
            let request = String::from_utf8_lossy(&buf[..count]);
            let path = request
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .split('?')
                .next()
                .unwrap_or("/");

            let body = if path == "/metrics" {
                metrics.render_with(&extra())
            } else {
                String::from("not found\n")
            };
            let status = if path == "/metrics" {
                "200 OK"
            } else {
                "404 Not Found"
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(err) = socket.write_all(response.as_bytes()).await {
                tracing::debug!(%peer, %err, "the metrics answer could not be written");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_counts() {
        let metrics = Metrics::new();
        metrics.add("mirage_test_total", 2);
        metrics.inc("mirage_test_total");
        assert_eq!(metrics.get("mirage_test_total"), 3);
    }

    #[test]
    fn a_gauge_is_set() {
        let metrics = Metrics::new();
        metrics.set("mirage_test_peers", 4);
        assert_eq!(metrics.get("mirage_test_peers"), 4);
    }

    #[test]
    fn the_text_carries_the_help_and_the_type() {
        let metrics = Metrics::new();
        metrics.register("mirage_test_total", Kind::Counter, "how many");
        metrics.add("mirage_test_total", 7);
        let text = metrics.render();
        assert!(text.contains("# HELP mirage_test_total how many"), "{text}");
        assert!(text.contains("# TYPE mirage_test_total counter"), "{text}");
        assert!(text.contains("mirage_test_total 7"), "{text}");
    }

    #[test]
    fn an_undeclared_counter_still_counts() {
        let metrics = Metrics::new();
        metrics.inc("mirage_moved_only");
        assert_eq!(metrics.get("mirage_moved_only"), 1);
    }

    #[test]
    fn the_extra_numbers_join_the_text() {
        let metrics = Metrics::new();
        metrics.register("mirage_test_total", Kind::Counter, "how many");
        metrics.add("mirage_test_total", 7);
        let extra = vec![(
            "mirage_test_plane_packets".to_owned(),
            Kind::Counter,
            "packets the plane carried".to_owned(),
            3,
        )];
        let text = metrics.render_with(&extra);
        assert!(text.contains("# HELP mirage_test_total how many"), "{text}");
        assert!(text.contains("mirage_test_total 7"), "{text}");
        assert!(
            text.contains("# HELP mirage_test_plane_packets packets the plane carried"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE mirage_test_plane_packets counter"),
            "{text}"
        );
        assert!(text.contains("mirage_test_plane_packets 3"), "{text}");
    }

    #[test]
    fn an_empty_source_leaves_the_text_as_it_was() {
        let metrics = Metrics::new();
        metrics.register("mirage_test_total", Kind::Counter, "how many");
        metrics.add("mirage_test_total", 7);
        assert_eq!(metrics.render_with(&[]), metrics.render());
    }

    #[test]
    fn the_device_counters_count() {
        let counters = DeviceCounters::new();
        assert_eq!(counters.stats().dropped_channel_full, 0);
        assert_eq!(counters.note_dropped_channel_full(), 1);
        assert_eq!(counters.note_dropped_channel_full(), 2);
        assert_eq!(counters.stats().dropped_channel_full, 2);

        assert_eq!(counters.note_write_channel_full(), 1);
        assert_eq!(counters.stats().write_channel_full, 1);
    }

    #[test]
    fn the_plane_metrics_carry_the_names_and_the_numbers() {
        let stats = crate::ip_plane::IpPlaneStats {
            from_tun: 10,
            to_tun: 20,
            dropped_unknown: 1,
            dropped_too_large: 2,
            dropped_not_ip: 3,
            write_errors: 4,
            peer_address_mismatch: 5,
        };
        let numbers = plane_metrics(&stats, 6);
        let text = Metrics::new().render_with(&numbers);

        for name in [
            PLANE_PACKETS_FROM_TUN,
            PLANE_PACKETS_TO_TUN,
            PLANE_DROPPED_UNKNOWN_DESTINATION,
            PLANE_DROPPED_TOO_LARGE,
            PLANE_DROPPED_NOT_IP,
            PLANE_DROPPED_PEER_ADDRESS_MISMATCH,
            PLANE_WRITE_ERRORS,
            PLANE_PEERS,
        ] {
            assert!(text.contains(name), "{name} is missing from:\n{text}");
        }

        assert!(text.contains(&format!("{PLANE_PACKETS_FROM_TUN} 10")), "{text}");
        assert!(text.contains(&format!("{PLANE_PACKETS_TO_TUN} 20")), "{text}");
        assert!(
            text.contains(&format!("{PLANE_DROPPED_UNKNOWN_DESTINATION} 1")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{PLANE_DROPPED_TOO_LARGE} 2")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{PLANE_DROPPED_NOT_IP} 3")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{PLANE_DROPPED_PEER_ADDRESS_MISMATCH} 5")),
            "{text}"
        );
        assert!(text.contains(&format!("{PLANE_WRITE_ERRORS} 4")), "{text}");
        assert!(text.contains(&format!("{PLANE_PEERS} 6")), "{text}");
        assert!(
            text.contains(&format!("# TYPE {PLANE_PEERS} gauge")),
            "{text}"
        );
    }

    #[test]
    fn the_device_metrics_carry_the_names() {
        let numbers = device_metrics();
        let text = Metrics::new().render_with(&numbers);
        assert!(
            text.contains(DEVICE_DROPPED_CHANNEL_FULL),
            "{DEVICE_DROPPED_CHANNEL_FULL} is missing from:\n{text}"
        );
        assert!(
            text.contains(DEVICE_WRITE_CHANNEL_FULL),
            "{DEVICE_WRITE_CHANNEL_FULL} is missing from:\n{text}"
        );
    }
}
