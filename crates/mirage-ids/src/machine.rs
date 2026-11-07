use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::IdParseError;

// ── Charset/length validator shared by MachineId / MonitorId / NodeId ─────────

/// Validate that `s` is a well-formed idlike string:
/// non-empty, max 96 chars, charset `[a-z0-9._-]`.
pub(crate) fn validate_idlike(s: &str) -> Result<(), IdParseError> {
    if s.is_empty() {
        return Err(IdParseError::Empty);
    }
    if s.len() > 96 {
        return Err(IdParseError::TooLong(s.len()));
    }
    for ch in s.chars() {
        if !ch.is_ascii_lowercase()
            && !ch.is_ascii_digit()
            && !matches!(ch, '.' | '_' | '-')
        {
            return Err(IdParseError::InvalidChar(ch));
        }
    }
    Ok(())
}

// ── Region enum (kept for structured views) ────────────────────────────────────

/// Geographic region. Two-letter code mirrors the staging-v2 inventory.
///
/// Used by [`MachineId::region`] / [`MachineParts`] as an optional view.
/// Unknown region strings are accepted at construction time — `region()`
/// returns `None` if the string doesn't match a known variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    Ru,
    Nl,
    Tr,
    Kz,
    Ch,
    Us,
    De,
    Sg,
    Fr,
    Uk,
}

impl Region {
    pub fn as_str(&self) -> &'static str {
        match self {
            Region::Ru => "ru",
            Region::Nl => "nl",
            Region::Tr => "tr",
            Region::Kz => "kz",
            Region::Ch => "ch",
            Region::Us => "us",
            Region::De => "de",
            Region::Sg => "sg",
            Region::Fr => "fr",
            Region::Uk => "uk",
        }
    }

    /// Parse — returns `None` on unknown strings instead of erroring.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Some(match s {
            "ru" => Region::Ru,
            "nl" => Region::Nl,
            "tr" => Region::Tr,
            "kz" => Region::Kz,
            "ch" => Region::Ch,
            "us" => Region::Us,
            "de" => Region::De,
            "sg" => Region::Sg,
            "fr" => Region::Fr,
            "uk" => Region::Uk,
            _ => return None,
        })
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Region {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Region::from_str_opt(s).ok_or_else(|| IdParseError::InvalidChar('?'))
    }
}

// ── Provider enum (kept for structured views) ──────────────────────────────────

/// VPS provider. Used as the human-readable second segment of `MachineId`.
///
/// Unknown provider strings are accepted at construction time — `provider()`
/// returns `None` if the string doesn't match a known variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    HostKey,
    HostHatch,
    Cloudzy,
    WorkTitans,
    Transtelecom,
    RuVds,
    Hetzner,
    Vultr,
    DigitalOcean,
    Linode,
    Other,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::HostKey => "hostkey",
            Provider::HostHatch => "hosthatch",
            Provider::Cloudzy => "cloudzy",
            Provider::WorkTitans => "worktitans",
            Provider::Transtelecom => "transtelecom",
            Provider::RuVds => "ruvds",
            Provider::Hetzner => "hetzner",
            Provider::Vultr => "vultr",
            Provider::DigitalOcean => "do",
            Provider::Linode => "linode",
            Provider::Other => "other",
        }
    }

    /// Parse — returns `None` on unknown strings instead of erroring.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Some(match s {
            "hostkey" => Provider::HostKey,
            "hosthatch" => Provider::HostHatch,
            "cloudzy" => Provider::Cloudzy,
            "worktitans" => Provider::WorkTitans,
            "transtelecom" => Provider::Transtelecom,
            "ruvds" => Provider::RuVds,
            "hetzner" => Provider::Hetzner,
            "vultr" => Provider::Vultr,
            "do" => Provider::DigitalOcean,
            "linode" => Provider::Linode,
            "other" => Provider::Other,
            _ => return None,
        })
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Provider {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Provider::from_str_opt(s).ok_or_else(|| IdParseError::InvalidChar('?'))
    }
}

// ── MachineParts view ──────────────────────────────────────────────────────────

/// Structured decomposition of a `MachineId`, returned by [`MachineId::parts`].
///
/// All fields are borrowed from the id string — zero-copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineParts<'a> {
    pub region_str: &'a str,
    pub provider_str: &'a str,
    /// The address tail of the id, verbatim — either a full dotted quad
    /// (`203.0.113.11`, the canonical form) or the legacy two-octet
    /// abbreviation (`113.10`).
    pub addr_str: &'a str,
}

impl<'a> MachineParts<'a> {
    /// Attempt to parse the region segment to a known [`Region`] enum.
    /// Returns `None` if the string doesn't match any known variant.
    pub fn region(&self) -> Option<Region> {
        Region::from_str_opt(self.region_str)
    }

    /// Attempt to parse the provider segment to a known [`Provider`] enum.
    /// Returns `None` if the string doesn't match any known variant.
    pub fn provider(&self) -> Option<Provider> {
        Provider::from_str_opt(self.provider_str)
    }

    /// The machine's full IPv4 address when the id carries one.
    ///
    /// `None` for a legacy two-octet id — an abbreviation cannot be widened
    /// back into an address, which is the whole reason the canonical form
    /// changed.
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.addr_str.parse().ok()
    }

    /// The last two octets, for reading a legacy id or comparing a new id
    /// against one. Works for both forms.
    pub fn short_octets(&self) -> Option<(u8, u8)> {
        let mut it = self.addr_str.rsplit('.');
        let last: u8 = it.next()?.parse().ok()?;
        let prev: u8 = it.next()?.parse().ok()?;
        Some((prev, last))
    }
}

/// Accept an id's address tail: either a full dotted quad or the legacy
/// two-octet abbreviation. Every segment must be a decimal `u8`; leading
/// zeros are allowed (`094`), because the legacy form zero-pads the third
/// octet and those ids are still in flight.
fn valid_addr_tail(tail: &str) -> bool {
    let segs: Vec<&str> = tail.split('.').collect();
    if segs.len() != 4 && segs.len() != 2 {
        return false;
    }
    segs.iter().all(|seg| !seg.is_empty() && seg.parse::<u8>().is_ok())
}

// ── MachineId opaque newtype ───────────────────────────────────────────────────

/// Physical VPS / dedicated box identifier — opaque validated string.
///
/// **Canonical form** for known inventory boxes is
/// `<region>-<provider>-<ipv4>`, e.g. `ru-hostkey-203.0.113.15`.
///
/// The form used to abbreviate the address to its last two octets
/// (`ru-hostkey-203.0.113.10`). That saved eleven characters and cost the reader
/// the address: `ru-hostkey-203.0.113.10` and `tr-hostkey-203.0.113.20` read as
/// neighbours while the machines are `203.0.113.15` and `203.0.113.14` —
/// different providers, different countries, nothing in common. The
/// per-box ssh keys in `env/example-inventory/` were already named with the
/// full address (`example-203.0.113.25-us`); the id was the one place
/// still truncating it. Legacy two-octet ids still parse — see
/// [`MachineParts::addr_str`] — so a box that has not been re-adopted yet
/// keeps working.
/// The type accepts *any* charset-valid id (`[a-z0-9._-]`, ≤ 96 chars)
/// so the generic/substrate layer can create ad-hoc ids without being
/// rejected.
///
/// Structured decomposition is available as an **optional view**:
/// [`MachineId::parts`], [`MachineId::region`], [`MachineId::provider`].
/// These return `None` when the id doesn't follow the
/// `<region>-<provider>-<addr>` shape or uses unknown segments.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MachineId(Box<str>);

impl MachineId {
    /// Construct with charset/length validation.
    ///
    /// Accepts any `[a-z0-9._-]` string up to 96 chars — the ZT floor.
    /// Does **not** require `region-provider-oct3.oct4` shape.
    pub fn new(s: impl AsRef<str>) -> Result<Self, IdParseError> {
        let s = s.as_ref();
        validate_idlike(s)?;
        Ok(Self(s.into()))
    }

    /// Construct without validation — only for ids known to be well-formed
    /// (e.g. constructed internally from validated sub-parts).
    pub fn from_trusted(s: impl Into<Box<str>>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0.into()
    }

    /// Try to decompose the id as `<region>-<provider>-<addr>`, where
    /// `<addr>` is a full dotted quad or the legacy two-octet tail.
    ///
    /// Returns `None` if the shape doesn't match (not enough segments,
    /// missing dot, or non-numeric octets). Region/provider enums are
    /// *not* validated here — use [`MachineParts::region`] /
    /// [`MachineParts::provider`] for that.
    pub fn parts(&self) -> Option<MachineParts<'_>> {
        let s = self.as_str();
        // Expected: `<seg>-<seg>-<seg3>.<seg4>` — exactly three `-`-separated parts,
        // with the last part containing a `.`.
        let mut iter = s.splitn(4, '-');
        let region_str = iter.next()?;
        let provider_str = iter.next()?;
        let ip_tail = iter.next()?;
        // There must be no fourth segment (no trailing `-`).
        if iter.next().is_some() {
            // More than three parts — provider might be multi-segment (e.g. hosthatch)
            // Actually, providers are single-segment, but we want to be flexible.
            // Re-try with rsplit approach: region = first, provider = middle parts,
            // ip_tail = last.
            return self.parts_rsplit();
        }
        if !valid_addr_tail(ip_tail) {
            return None;
        }
        Some(MachineParts {
            region_str,
            provider_str,
            addr_str: ip_tail,
        })
    }

    /// Fallback: split into `(region, everything-in-middle, ip_tail)` via
    /// first `-` and last `-`. Handles multi-word providers if they ever appear.
    fn parts_rsplit(&self) -> Option<MachineParts<'_>> {
        let s = self.as_str();
        // ip_tail is the last `-`-separated segment that contains a dot
        let dot_pos = s.rfind('.')?;
        // Find the `-` before the dot that precedes the oct3
        let dash_before_ip = s[..dot_pos].rfind('-')?;
        let ip_tail = &s[dash_before_ip + 1..];
        let head = &s[..dash_before_ip];
        // head = `<region>-<provider>`
        let first_dash = head.find('-')?;
        let region_str = &head[..first_dash];
        let provider_str = &head[first_dash + 1..];
        if !valid_addr_tail(ip_tail) {
            return None;
        }
        Some(MachineParts {
            region_str,
            provider_str,
            addr_str: ip_tail,
        })
    }

    /// Returns the known [`Region`] variant if this id follows the structured
    /// shape AND the region segment is a known value. `None` otherwise.
    pub fn region(&self) -> Option<Region> {
        self.parts()?.region()
    }

    /// Returns the known [`Provider`] variant if this id follows the structured
    /// shape AND the provider segment is a known value. `None` otherwise.
    pub fn provider(&self) -> Option<Provider> {
        self.parts()?.provider()
    }
}

impl fmt::Debug for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MachineId({:?})", self.0)
    }
}

impl fmt::Display for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MachineId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// ── Client-facing label ─────────────────────────────────────────────────────

/// Derive a node's opaque, client-facing label from its `self_id`.
///
/// Pure and deterministic — the same `self_id` always derives the same
/// label, so re-signing the identity that carries a given `self_id` for
/// any reason (TTL refresh, role addition, key rotation) reproduces this
/// label unchanged, and a `self_id` rotation (a cryptographically distinct
/// peer) derives a fresh one by construction — no cache, no lookup, no
/// drift possible.
///
/// Carries no provider/region/machine-id content on purpose: `region`
/// travels as its own typed field ([`MachineParts::region_str`]), so two
/// customers comparing labels across meshes learn nothing about placement
/// from the string alone.
///
/// 10 hex chars ~ 40 bits — negligible collision risk at per-mesh node
/// counts (tens, not millions today). Safe to widen later: the label lives
/// inside a signed field, not a wire constant, so widening only affects
/// freshly-minted labels.
pub fn derive_client_label(self_id: Uuid) -> String {
    format!("node-{}", &self_id.simple().to_string()[..10])
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_full_address_form() {
        let m: MachineId = "ru-hostkey-203.0.113.15".parse().unwrap();
        assert_eq!(m.as_str(), "ru-hostkey-203.0.113.15");
        let p = m.parts().unwrap();
        assert_eq!(p.region(), Some(Region::Ru));
        assert_eq!(p.provider(), Some(Provider::HostKey));
        assert_eq!(p.addr_str, "203.0.113.15");
        assert_eq!(p.ipv4(), Some(std::net::Ipv4Addr::new(203, 0, 113, 15)));
        assert_eq!(p.short_octets(), Some((113, 15)));
        assert_eq!(m.region(), Some(Region::Ru));
        assert_eq!(m.provider(), Some(Provider::HostKey));
    }

    /// The two ids this change exists for: same two-octet tail, unrelated
    /// machines. In the legacy form both could share a two-octet tail and read as siblings.
    #[test]
    fn full_form_separates_machines_the_short_form_conflated() {
        let ru: MachineId = "ru-hostkey-203.0.113.15".parse().unwrap();
        let tr: MachineId = "tr-hostkey-203.0.113.14".parse().unwrap();
        assert_eq!(ru.parts().unwrap().short_octets(), Some((113, 15)));
        assert_eq!(tr.parts().unwrap().short_octets(), Some((113, 14)));
        assert_ne!(ru.parts().unwrap().ipv4(), tr.parts().unwrap().ipv4());
    }

    #[test]
    fn still_accepts_the_legacy_two_octet_form() {
        // A box that has not been re-adopted onto a full-address id yet must
        // keep parsing, or renaming the fleet would have to be atomic.
        let m: MachineId = "ru-hostkey-113.10".parse().unwrap();
        let p = m.parts().unwrap();
        assert_eq!(p.addr_str, "113.10");
        assert_eq!(p.short_octets(), Some((113, 10)));
        assert_eq!(p.ipv4(), None, "two octets are not an address");
    }

    #[test]
    fn accepts_padded_third_octet() {
        let m: MachineId = "kz-example-113.66".parse().unwrap();
        let p = m.parts().unwrap();
        assert_eq!(p.short_octets(), Some((113, 66)));
        assert_eq!(m.to_string(), "kz-example-113.66");
    }

    #[test]
    fn rejects_a_three_octet_tail() {
        // Neither a full address nor the legacy abbreviation.
        let m: MachineId = "ru-hostkey-11.22.33".parse().unwrap();
        assert!(m.parts().is_none());
    }

    #[test]
    fn accepts_unknown_provider() {
        // ZT floor: unknown provider no longer rejected at construction.
        let m: MachineId = "ru-newprovider-113.10".parse().unwrap();
        let p = m.parts().unwrap();
        assert_eq!(p.region(), Some(Region::Ru));
        assert_eq!(p.provider(), None); // unknown, not an error
    }

    #[test]
    fn accepts_unknown_region() {
        let m: MachineId = "xx-hostkey-113.10".parse().unwrap();
        let p = m.parts().unwrap();
        assert_eq!(p.region(), None); // unknown, not an error
        assert_eq!(p.provider(), Some(Provider::HostKey));
    }

    #[test]
    fn accepts_opaque_id() {
        // Generic substrate can construct any valid-charset id.
        let m = MachineId::new("mon-a").unwrap();
        assert_eq!(m.as_str(), "mon-a");
        // No structured parts — that's fine.
        assert!(m.parts().is_none());
    }

    #[test]
    fn parts_none_for_no_dot_in_tail() {
        let m: MachineId = "ru-hostkey-9474".parse().unwrap();
        assert!(m.parts().is_none());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(MachineId::new(""), Err(IdParseError::Empty)));
    }

    #[test]
    fn rejects_invalid_char() {
        assert!(matches!(
            MachineId::new("RU-hostkey-113.10"),
            Err(IdParseError::InvalidChar('R'))
        ));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(97);
        assert!(matches!(MachineId::new(long), Err(IdParseError::TooLong(97))));
    }

    #[test]
    fn serde_roundtrip() {
        let m: MachineId = "ru-hostkey-203.0.113.10".parse().unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "\"ru-hostkey-203.0.113.10\"");
        let back: MachineId = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn from_trusted() {
        let m = MachineId::from_trusted("ru-hostkey-203.0.113.10");
        assert_eq!(m.as_str(), "ru-hostkey-203.0.113.10");
    }

    #[test]
    fn derive_client_label_is_deterministic_for_the_same_self_id() {
        let id = Uuid::new_v4();
        assert_eq!(derive_client_label(id), derive_client_label(id));
    }

    #[test]
    fn derive_client_label_differs_across_self_ids() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(derive_client_label(a), derive_client_label(b));
    }

    #[test]
    fn derive_client_label_has_the_documented_shape() {
        let id = Uuid::nil();
        let label = derive_client_label(id);
        assert_eq!(label, "node-0000000000");
        assert!(
            label.strip_prefix("node-").is_some_and(|hex| hex.len() == 10
                && hex.chars().all(|c| c.is_ascii_hexdigit())),
            "got {label:?}"
        );
    }

    #[test]
    fn derive_client_label_carries_no_region_or_provider_content() {
        // A label must not be re-derivable back into any MachineId segment —
        // it is a pure function of self_id alone, never of placement.
        let id = Uuid::new_v4();
        let label = derive_client_label(id);
        assert!(!label.contains('.'), "must carry no address-shaped content: {label:?}");
    }
}
