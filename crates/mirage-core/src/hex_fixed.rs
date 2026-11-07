//! serde helpers for fixed-size byte arrays serialised as hex strings.

macro_rules! hex_arr {
    ($modname:ident, $n:expr) => {
        pub mod $modname {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(bytes: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(bytes))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let s = String::deserialize(d)?;
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if v.len() != $n {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        $n,
                        v.len()
                    )));
                }
                let mut out = [0u8; $n];
                out.copy_from_slice(&v);
                Ok(out)
            }
        }
    };
}

hex_arr!(hex12, 12);
hex_arr!(hex16, 16);
hex_arr!(hex32, 32);
