use crate::frame_obfuscation::shaping::TrafficPattern;

/// Traffic pattern that mimics Yandex Cloud API calls.
pub fn yandex_cloud_api() -> TrafficPattern {
    TrafficPattern::CloudApi {
        request_size: 256..4096,
        response_size: 1024..48000,
        interval_ms: 50..300,
    }
}

/// Traffic pattern that mimics web browsing behaviour.
pub fn web_browsing() -> TrafficPattern {
    TrafficPattern::WebBrowsing {
        burst_size: 10240..48000,
        idle_ms: 200..3000,
    }
}

/// Traffic pattern that mimics video streaming (YouTube-like).
pub fn video_streaming() -> TrafficPattern {
    TrafficPattern::Streaming {
        chunk_size: 16384..48000,
        interval_ms: 10..100,
    }
}

/// Direct mode — no obfuscation, intended for inner tunnel segments.
pub fn direct() -> TrafficPattern {
    TrafficPattern::Direct
}
