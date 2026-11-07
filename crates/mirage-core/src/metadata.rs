use serde::{Deserialize, Serialize};

/// Operator directive telling the client what flow metadata to collect and return.
///
/// Transmitted DOWN the encrypted control channel (monitor → client).
/// All fields are serde-default so an absent or partial directive is safe.
/// `collect: false` (the `Default`) means the client reports nothing.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MetadataPolicy {
    /// Master opt-in. When `false` the client skips all collection.
    #[serde(default)]
    pub collect: bool,
    /// Include process / app identity in each `FlowObservation`.
    #[serde(default)]
    pub include_app: bool,
    /// Aggregation window in seconds. `0` means the client uses its own default.
    #[serde(default)]
    pub sample_window_secs: u32,
    /// Maximum `FlowObservation` entries per report. `0` means the client uses its own default.
    #[serde(default)]
    pub max_entries_per_report: u32,
    /// Domains the client must never include in any report.
    #[serde(default)]
    pub domain_blocklist: Vec<String>,
}

/// One aggregated flow observation the client returns.
///
/// Metadata only — destination address + optional domain/app + the routing
/// decision actually applied + an occurrence count. No payloads, no timing.
/// Transmitted UP the encrypted control channel (client → monitor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowObservation {
    /// Destination IP address string (IPv4 or IPv6).
    pub dest_ip: String,
    /// Destination port, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<u16>,
    /// Resolved domain name, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Process / app identity string (e.g. executable basename), if collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// The routing decision that was actually applied (`mirage` or `bypass`).
    pub decision: crate::split_policy::SplitPolicyAction,
    /// Number of flows with this (dest_ip, dest_port, domain, app, decision) tuple
    /// observed during the report window.
    pub count: u32,
}

/// Batch of flow observations the client sends to the monitor.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientMetadataReport {
    /// Duration of the aggregation window covered by this report, in seconds.
    #[serde(default)]
    pub window_secs: u32,
    /// The individual flow observations.
    #[serde(default)]
    pub flows: Vec<FlowObservation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_policy::SplitPolicyAction;

    #[test]
    fn metadata_policy_default_round_trip() {
        let policy = MetadataPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize MetadataPolicy");
        let decoded: MetadataPolicy =
            serde_json::from_str(&json).expect("deserialize MetadataPolicy");
        assert_eq!(policy, decoded);
        assert!(!decoded.collect);
    }

    #[test]
    fn client_metadata_report_round_trip() {
        let report = ClientMetadataReport {
            window_secs: 60,
            flows: vec![FlowObservation {
                dest_ip: "1.2.3.4".to_string(),
                dest_port: Some(443),
                domain: Some("example.com".to_string()),
                app: None,
                decision: SplitPolicyAction::Mirage,
                count: 7,
            }],
        };

        let json = serde_json::to_string(&report).expect("serialize ClientMetadataReport");
        let decoded: ClientMetadataReport =
            serde_json::from_str(&json).expect("deserialize ClientMetadataReport");

        assert_eq!(decoded.window_secs, 60);
        assert_eq!(decoded.flows.len(), 1);
        assert_eq!(decoded.flows[0].dest_ip, "1.2.3.4");
        assert_eq!(decoded.flows[0].dest_port, Some(443));
        assert_eq!(decoded.flows[0].count, 7);
        assert!(matches!(decoded.flows[0].decision, SplitPolicyAction::Mirage));
        // app: None → must not appear in JSON
        assert!(!json.contains("\"app\""), "None app must be skipped: {json}");
    }
}
