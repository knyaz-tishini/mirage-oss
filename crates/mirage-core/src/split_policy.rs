use serde::{Deserialize, Serialize};

/// Routing action for a split-tunnel rule.
///
/// Serializes to the same strings as `mirage_tun_core::policy::PolicyDecision`
/// for "bypass" and "mirage" — so a `SplitPolicyConfig` serialized to JSON
/// can be deserialized directly by the TUN's `PolicyConfigRequest` deserializer
/// without any translation layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SplitPolicyAction {
    /// Route through the Mirage tunnel (default data-plane).
    Mirage,
    /// Bypass: egress directly via the real NIC.
    Bypass,
}

/// A single traffic-matching rule in a split-tunnel policy.
///
/// JSON wire shape (tag field `"type"`, snake_case variant names):
/// ```json
/// {"type":"dest_cidr","cidr":"5.8.0.0/16","action":"bypass"}
/// {"type":"dest_domain","domain":"example.ru","action":"mirage"}
/// ```
///
/// This shape is structurally compatible with `mirage_tun_core::policy::PolicyRule`
/// — the TUN deserializer accepts it because `failure_policy` and `wire_class`
/// are `#[serde(default)]` on the TUN side and will fill in defaults when absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SplitPolicyRule {
    DestCidr {
        cidr: String,
        action: SplitPolicyAction,
    },
    DestDomain {
        domain: String,
        action: SplitPolicyAction,
    },
    /// Route by exact executable path (e.g. `C:/Program Files/Telegram/tg.exe`).
    /// Tag: `"dest_app_path"` — matches `mirage_tun_core::policy::PolicyRule::DestAppPath`.
    DestAppPath {
        path: String,
        action: SplitPolicyAction,
    },
    /// Route all executables under a directory subtree.
    /// Tag: `"dest_app_dir"` — matches `mirage_tun_core::policy::PolicyRule::DestAppDir`.
    DestAppDir {
        dir: String,
        action: SplitPolicyAction,
    },
}

/// Full split-tunnel policy config pushed from monitor to client.
///
/// Serializes directly to the JSON shape expected by the TUN's
/// `POST /policy/set` endpoint (`PolicyConfigRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitPolicyConfig {
    pub rules: Vec<SplitPolicyRule>,
    pub default_action: SplitPolicyAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_app_path_round_trip() {
        let config = SplitPolicyConfig {
            rules: vec![SplitPolicyRule::DestAppPath {
                path: "C:/x/tg.exe".to_string(),
                action: SplitPolicyAction::Bypass,
            }],
            default_action: SplitPolicyAction::Mirage,
        };

        let json = serde_json::to_string(&config).expect("serialization failed");

        // Verify the serde tag is exactly "dest_app_path"
        assert!(
            json.contains(r#""type":"dest_app_path""#),
            "expected dest_app_path tag, got: {json}"
        );
        assert!(
            json.contains(r#""path":"C:/x/tg.exe""#),
            "expected path field, got: {json}"
        );
        assert!(
            json.contains(r#""action":"bypass""#),
            "expected bypass action, got: {json}"
        );

        // Deserialize back and check structural equality
        let decoded: SplitPolicyConfig =
            serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(decoded.rules.len(), 1);
        assert!(matches!(
            &decoded.rules[0],
            SplitPolicyRule::DestAppPath { path, action: SplitPolicyAction::Bypass }
            if path == "C:/x/tg.exe"
        ));
        assert!(matches!(decoded.default_action, SplitPolicyAction::Mirage));
    }
}
