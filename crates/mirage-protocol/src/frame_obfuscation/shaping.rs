use rand::Rng;
use std::ops::Range;
use std::time::{Duration, Instant};

/// Traffic pattern presets controlling how data is padded and timed.
#[derive(Debug, Clone)]
pub enum TrafficPattern {
    /// Mimics web browsing: burst of data, then idle, then burst.
    WebBrowsing {
        /// Bytes per burst (e.g. 10 KB – 500 KB).
        burst_size: Range<usize>,
        /// Milliseconds between bursts (e.g. 200 – 3000 ms).
        idle_ms: Range<u64>,
    },
    /// Mimics cloud API calls: small request, larger response, pause.
    CloudApi {
        /// Request payload size range (e.g. 200 B – 4 KB).
        request_size: Range<usize>,
        /// Response payload size range (e.g. 1 KB – 64 KB).
        response_size: Range<usize>,
        /// Milliseconds between API calls (e.g. 50 – 500 ms).
        interval_ms: Range<u64>,
    },
    /// Mimics video streaming: continuous chunks at variable bitrate.
    Streaming {
        /// Bytes per chunk (e.g. 16 KB – 128 KB).
        chunk_size: Range<usize>,
        /// Milliseconds between chunks (e.g. 10 – 100 ms).
        interval_ms: Range<u64>,
    },
    /// No shaping — for inner L1→L2 tunnel segments.
    Direct,
}

/// Shapes outgoing data to match a [`TrafficPattern`].
///
/// Padding format:
/// ```text
/// [actual_data][random_bytes][4B little-endian: original data length]
/// ```
/// The final 4 bytes always hold the original data length so [`TrafficShaper::unpad`]
/// can recover it without side-channel guessing.
///
/// Jitter is applied only at **burst boundaries** — i.e., when the time since
/// the previous send exceeds the idle/interval threshold.  Rapid back-to-back
/// sends within a burst are not delayed.
pub struct TrafficShaper {
    pattern: TrafficPattern,
    /// Timestamp of the most recent `jitter_delay` call that produced a
    /// non-zero delay (i.e., a burst-boundary event).  Used to detect whether
    /// the current send is within a burst or starting a new one.
    last_burst_start: Option<Instant>,
}

impl TrafficShaper {
    /// Create a new shaper with the given pattern.
    pub fn new(pattern: TrafficPattern) -> Self {
        Self {
            pattern,
            last_burst_start: None,
        }
    }

    /// Pad `data` to a size that matches the pattern.
    ///
    /// Returns `(padded_data, padding_byte_count)`.
    ///
    /// Padding layout:
    /// ```text
    /// [data][random padding bytes][4B LE: original length]
    /// ```
    pub fn pad(&mut self, data: &[u8]) -> (Vec<u8>, usize) {
        let original_len = data.len();
        let mut rng = rand::thread_rng();

        let target = match &self.pattern {
            TrafficPattern::Direct => {
                // No padding — still append the 4-byte length trailer.
                let mut out = Vec::with_capacity(data.len() + 4);
                out.extend_from_slice(data);
                out.extend_from_slice(&(original_len as u32).to_le_bytes());
                return (out, 0);
            }
            TrafficPattern::WebBrowsing { burst_size, .. } => {
                let lo = burst_size.start.max(original_len);
                let hi = burst_size.end.max(lo + 1);
                rng.gen_range(lo..hi)
            }
            TrafficPattern::CloudApi { response_size, .. } => {
                // Pad to the nearest 4 KB boundary >= (data.len() + 4-byte trailer).
                let boundary = 4096usize;
                let needed = original_len + 4;
                let chunks = needed.div_ceil(boundary);
                let padded_total = chunks * boundary;
                // Clamp to response_size range so the final size looks realistic.
                let lo = response_size.start.max(padded_total);
                let hi = response_size.end.max(lo + 1);
                padded_total.clamp(lo, hi)
            }
            TrafficPattern::Streaming { chunk_size, .. } => {
                // Pad to the nearest 16 KB boundary >= (data.len() + 4-byte trailer).
                let boundary = 16384usize;
                let needed = original_len + 4;
                let chunks = needed.div_ceil(boundary);
                let padded_total = chunks * boundary;
                let lo = chunk_size.start.max(padded_total);
                let hi = chunk_size.end.max(lo + 1);
                padded_total.clamp(lo, hi)
            }
        };

        // target is the desired total (data + random padding + 4-byte trailer).
        let trailer_size = 4usize;
        let padding_len = target.saturating_sub(original_len + trailer_size);

        let total = original_len + padding_len + trailer_size;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(data);

        // Fill padding with random bytes.
        let pad_start = out.len();
        out.resize(pad_start + padding_len, 0u8);
        rng.fill(&mut out[pad_start..]);

        out.extend_from_slice(&(original_len as u32).to_le_bytes());

        (out, padding_len)
    }

    /// Calculate jitter delay before the next send, based on the active pattern.
    ///
    /// Returns a non-zero delay only at **burst boundaries** — when the elapsed
    /// time since the last burst-start exceeds the pattern's idle/interval
    /// threshold minimum.  Sends that arrive rapidly (within a burst) return
    /// [`Duration::ZERO`] so they are not artificially serialised.
    pub fn jitter_delay(&mut self) -> Duration {
        let idle_min_ms: u64 = match &self.pattern {
            TrafficPattern::Direct => return Duration::ZERO,
            TrafficPattern::WebBrowsing { idle_ms, .. } => idle_ms.start,
            TrafficPattern::CloudApi { interval_ms, .. } => interval_ms.start,
            TrafficPattern::Streaming { interval_ms, .. } => interval_ms.start,
        };

        let idle_threshold = Duration::from_millis(idle_min_ms);

        // Determine whether we are starting a new burst.
        let is_burst_boundary = match self.last_burst_start {
            // First send ever — counts as a burst boundary.
            None => true,
            // Burst boundary if more than idle_min_ms has passed since the
            // last recorded burst start.
            Some(t) => t.elapsed() >= idle_threshold,
        };

        if !is_burst_boundary {
            return Duration::ZERO;
        }

        // Record this burst-start timestamp and compute the delay.
        self.last_burst_start = Some(Instant::now());

        let mut rng = rand::thread_rng();
        let ms = match &self.pattern {
            TrafficPattern::Direct => unreachable!(),
            TrafficPattern::WebBrowsing { idle_ms, .. } => rng.gen_range(idle_ms.clone()),
            TrafficPattern::CloudApi { interval_ms, .. } => rng.gen_range(interval_ms.clone()),
            TrafficPattern::Streaming { interval_ms, .. } => rng.gen_range(interval_ms.clone()),
        };
        Duration::from_millis(ms)
    }

    /// Strip padding from received data.
    ///
    /// Reads the 4-byte little-endian original length from the end of `data`
    /// and returns a slice of that length from the beginning.
    pub fn unpad(data: &[u8]) -> &[u8] {
        if data.len() < 4 {
            return data;
        }
        let trailer_start = data.len() - 4;
        let len_bytes: [u8; 4] = [
            data[trailer_start],
            data[trailer_start + 1],
            data[trailer_start + 2],
            data[trailer_start + 3],
        ];
        let original_len = u32::from_le_bytes(len_bytes) as usize;
        &data[..original_len.min(trailer_start)]
    }
}
