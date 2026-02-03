use crate::BlsError;

/// The BLS signature algorithm schemes
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
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

impl From<u8> for SignatureSchemes {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Basic,
            1 => Self::MessageAugmentation,
            _ => Self::ProofOfPossession,
        }
    }
}

impl From<&str> for SignatureSchemes {
    fn from(value: &str) -> Self {
        match value {
            "Basic" => Self::Basic,
            "MessageAugmentation" => Self::MessageAugmentation,
            _ => Self::ProofOfPossession,
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
        match s {
            "Basic" => Ok(Self::Basic),
            "MessageAugmentation" => Ok(Self::MessageAugmentation),
            _ => Ok(Self::ProofOfPossession),
        }
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
            Ok(Self::from(s.as_str()))
        } else {
            let u = u8::deserialize(d)?;
            Ok(Self::from(u))
        }
    }
}
