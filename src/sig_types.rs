use crate::BlsError;

/// The BLS signature algorithm schemes
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum SignatureSchemes {
    /// The basic signature algorithm scheme
    Basic = 0,
    /// The message augmentation signature algorithm scheme
    MessageAugmentation = 1,
    /// The proof of possession signature algorithm scheme
    #[default]
    ProofOfPossession = 2,
}

impl TryFrom<u8> for SignatureSchemes {
    type Error = BlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Basic),
            1 => Ok(Self::MessageAugmentation),
            2 => Ok(Self::ProofOfPossession),
            _ => Err(BlsError::InvalidInputs(format!(
                "unknown signature scheme value: {value}"
            ))),
        }
    }
}

impl TryFrom<&str> for SignatureSchemes {
    type Error = BlsError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Basic" => Ok(Self::Basic),
            "MessageAugmentation" => Ok(Self::MessageAugmentation),
            "ProofOfPossession" => Ok(Self::ProofOfPossession),
            _ => Err(BlsError::InvalidInputs(format!(
                "unknown signature scheme: {value}"
            ))),
        }
    }
}

impl core::fmt::Display for SignatureSchemes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Basic => write!(f, "Basic"),
            Self::MessageAugmentation => write!(f, "MessageAugmentation"),
            Self::ProofOfPossession => write!(f, "ProofOfPossession"),
        }
    }
}

impl core::str::FromStr for SignatureSchemes {
    type Err = BlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl serde::Serialize for SignatureSchemes {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if s.is_human_readable() {
            self.to_string().serialize(s)
        } else {
            (*self as u8).serialize(s)
        }
    }
}

impl<'de> serde::Deserialize<'de> for SignatureSchemes {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Self::try_from(s.as_str()).map_err(serde::de::Error::custom)
        } else {
            let u = u8::deserialize(d)?;
            Self::try_from(u).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_scheme_values() {
        assert!(SignatureSchemes::try_from(3).is_err());
        assert!("unknown".parse::<SignatureSchemes>().is_err());
        assert!(serde_json::from_str::<SignatureSchemes>("\"unknown\"").is_err());
        assert!(serde_bare::from_slice::<SignatureSchemes>(&[3]).is_err());
    }
}
