//! Base64-in-JSON serde helpers for byte payloads.
//!
//! A raw `Vec<u8>` serialises as a JSON number array (~4× size bloat);
//! base64 (~1.33×) keeps wire/storage bodies compact. Shared by
//! [`crate::mshd_blob`] (ciphertext chunks) and
//! `mirage_protocol::core::mshd_rpc` (exec stdin / file chunk payloads) —
//! one canonical shim instead of a private copy per module.

/// `#[serde(with = "b64_vec")]` for a plain `Vec<u8>` field.
pub mod b64_vec {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// `#[serde(with = "b64_opt")]` for an `Option<Vec<u8>>` field — `None`
/// serialises as JSON `null`, `Some(bytes)` as a base64 string.
pub mod b64_opt {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => {
                s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct VecWrap {
        #[serde(with = "b64_vec")]
        data: Vec<u8>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct OptWrap {
        #[serde(with = "b64_opt")]
        data: Option<Vec<u8>>,
    }

    #[test]
    fn b64_vec_round_trip() {
        let v = VecWrap { data: vec![1, 2, 3, 255, 0] };
        let json = serde_json::to_string(&v).unwrap();
        // Base64 string, not a JSON number array — the whole point of this shim.
        assert_eq!(json, r#"{"data":"AQID/wA="}"#);
        let back: VecWrap = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn b64_vec_empty_round_trip() {
        let v = VecWrap { data: Vec::new() };
        let json = serde_json::to_string(&v).unwrap();
        let back: VecWrap = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn b64_opt_round_trip_some_and_none() {
        let some = OptWrap { data: Some(vec![9, 9, 200]) };
        let json = serde_json::to_string(&some).unwrap();
        let back: OptWrap = serde_json::from_str(&json).unwrap();
        assert_eq!(some, back);

        let none = OptWrap { data: None };
        let json = serde_json::to_string(&none).unwrap();
        assert_eq!(json, r#"{"data":null}"#);
        let back: OptWrap = serde_json::from_str(&json).unwrap();
        assert_eq!(none, back);
    }

    #[test]
    fn b64_vec_bad_base64_rejected() {
        let bad = r#"{"data":"not-valid-base64!!"}"#;
        let result: Result<VecWrap, _> = serde_json::from_str(bad);
        assert!(result.is_err());
    }
}
