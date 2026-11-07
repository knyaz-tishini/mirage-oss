use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::IdParseError;
use crate::machine::{validate_idlike, MachineId};

/// Logical monitor identifier — opaque validated string.
///
/// **Canonical form** for inventory-backed monitors:
/// - `<machine>` for `seq=1` (primary monitor).
/// - `<machine>-<seq>` when a machine hosts a second+ monitor (`seq >= 2`).
///
/// Examples: `ru-hostkey-203.0.113.10`, `ru-hostkey-203.0.113.10-2`.
///
/// The type also accepts arbitrary id strings (e.g. `mon-a`) so the
/// generic substrate layer can construct monitors without a structured
/// machine-id backing.
///
/// Structured decomposition is available via [`MonitorId::machine`] and
/// [`MonitorId::seq`] — both return `Option` and return `None` when the
/// id doesn't follow the structured shape.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MonitorId(Box<str>);

impl MonitorId {
    /// Construct with charset/length validation.
    pub fn new(s: impl AsRef<str>) -> Result<Self, IdParseError> {
        let s = s.as_ref();
        validate_idlike(s)?;
        Ok(Self(s.into()))
    }

    /// Construct without validation.
    pub fn from_trusted(s: impl Into<Box<str>>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0.into()
    }

    /// Try to parse the backing machine id from this monitor id.
    ///
    /// For `<machine>` format (seq=1): returns the whole string as a `MachineId`.
    /// For `<machine>-<seq>` format (seq >= 2, trailing segment is all-digits):
    ///   strips the trailing `-<N>` and returns the head as a `MachineId`.
    /// Returns `None` if no `-` is present in the `<machine>-<seq>` split.
    pub fn machine(&self) -> Option<MachineId> {
        let (head, seq) = self.split_seq();
        if seq >= 2 {
            MachineId::new(head).ok()
        } else {
            // seq == 1: the whole string is the machine id.
            MachineId::new(self.as_str()).ok()
        }
    }

    /// Return the monitor sequence number.
    ///
    /// Returns `2+` when the id ends with `-<N>` (all-digit trailing segment,
    /// value >= 2). Returns `1` otherwise (primary monitor).
    pub fn seq(&self) -> Option<u8> {
        let (_, seq) = self.split_seq();
        Some(seq)
    }

    /// Split the id into `(head, seq)`:
    /// - If the trailing `-`-separated segment is all-ASCII-digits and parses
    ///   as a u8 >= 2, returns `(&str_before_last_dash, seq)`.
    /// - Otherwise returns `(self.as_str(), 1)`.
    fn split_seq(&self) -> (&str, u8) {
        let s = self.as_str();
        if let Some((head, tail)) = s.rsplit_once('-') {
            if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = tail.parse::<u8>() {
                    if n >= 2 {
                        return (head, n);
                    }
                }
            }
        }
        (s, 1)
    }

    /// Returns `true` when `seq()` is `Some(1)`.
    pub fn is_primary(&self) -> bool {
        self.seq() == Some(1)
    }
}

impl fmt::Debug for MonitorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MonitorId({:?})", self.0)
    }
}

impl fmt::Display for MonitorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MonitorId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provider, Region};

    #[test]
    fn accepts_primary_monitor() {
        let m: MonitorId = "ru-hostkey-203.0.113.10".parse().unwrap();
        assert_eq!(m.as_str(), "ru-hostkey-203.0.113.10");
        assert_eq!(m.seq(), Some(1));
        assert!(m.is_primary());
        let machine = m.machine().unwrap();
        assert_eq!(machine.region(), Some(Region::Ru));
        assert_eq!(machine.provider(), Some(Provider::HostKey));
    }

    #[test]
    fn accepts_second_monitor() {
        let m: MonitorId = "ru-hostkey-203.0.113.10-2".parse().unwrap();
        assert_eq!(m.seq(), Some(2));
        assert!(!m.is_primary());
        let machine = m.machine().unwrap();
        assert_eq!(machine.to_string(), "ru-hostkey-203.0.113.10");
    }

    #[test]
    fn accepts_opaque_id() {
        // Substrate pattern: arbitrary id.
        let m = MonitorId::new("mon-a").unwrap();
        assert_eq!(m.as_str(), "mon-a");
        // seq = 1 (primary by default for opaque ids)
        assert_eq!(m.seq(), Some(1));
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(MonitorId::new(""), Err(IdParseError::Empty)));
    }

    #[test]
    fn serde_roundtrip() {
        for s in ["ru-hostkey-203.0.113.10", "kz-example-113.66-2", "mon-a"] {
            let m: MonitorId = s.parse().unwrap();
            let j = serde_json::to_string(&m).unwrap();
            let back: MonitorId = serde_json::from_str(&j).unwrap();
            assert_eq!(m, back);
            assert_eq!(m.to_string(), s);
        }
    }

    #[test]
    fn from_trusted() {
        let m = MonitorId::from_trusted("ru-hostkey-203.0.113.10");
        assert_eq!(m.as_str(), "ru-hostkey-203.0.113.10");
    }
}
