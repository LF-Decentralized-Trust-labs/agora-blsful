use crate::*;

/// Represents a share of a signature
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureShare<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(<C as Pairing>::SignatureShare),
    /// The message augmentation signature scheme
    MessageAugmentation(<C as Pairing>::SignatureShare),
    /// The proof of possession signature scheme
    ProofOfPossession(<C as Pairing>::SignatureShare),
}

impl<C: BlsSignatureImpl> Default for SignatureShare<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::SignatureShare::default())
    }
}

impl_signature_enum_traits!(
    SignatureShare,
    <C as Pairing>::SignatureShare,
    "SignatureShare::conditional_select: mismatched variants"
);

impl_from_derivatives_generic!(SignatureShare);

impl<C: BlsSignatureImpl> TryFrom<&SignatureShare<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(s: &SignatureShare<C>) -> BlsResult<Self> {
        match s {
            SignatureShare::Basic(s) => serde_bare::to_vec(&(SignatureSchemes::Basic, s)),
            SignatureShare::MessageAugmentation(s) => {
                serde_bare::to_vec(&(SignatureSchemes::MessageAugmentation, s))
            }
            SignatureShare::ProofOfPossession(s) => {
                serde_bare::to_vec(&(SignatureSchemes::ProofOfPossession, s))
            }
        }
        .map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignatureShare<C> {
    type Error = BlsError;

    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        let (scheme, s): (SignatureSchemes, <C as Pairing>::SignatureShare) =
            serde_bare::from_slice(bytes).map_err(BlsError::from)?;
        match scheme {
            SignatureSchemes::Basic => Ok(Self::Basic(s)),
            SignatureSchemes::MessageAugmentation => Ok(Self::MessageAugmentation(s)),
            SignatureSchemes::ProofOfPossession => Ok(Self::ProofOfPossession(s)),
        }
    }
}

impl<C: BlsSignatureImpl> SignatureShare<C> {
    /// Return the signature scheme used to create this share.
    pub const fn scheme(&self) -> SignatureSchemes {
        match self {
            Self::Basic(_) => SignatureSchemes::Basic,
            Self::MessageAugmentation(_) => SignatureSchemes::MessageAugmentation,
            Self::ProofOfPossession(_) => SignatureSchemes::ProofOfPossession,
        }
    }

    /// Verify the signature share with the public key share
    pub fn verify<B: AsRef<[u8]>>(&self, pks: &PublicKeyShare<C>, msg: B) -> BlsResult<()> {
        pks.verify(self, msg)
    }

    /// Determine if two signature shares were signed using the same scheme
    pub fn same_scheme(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Basic(_), Self::Basic(_))
                | (Self::MessageAugmentation(_), Self::MessageAugmentation(_))
                | (Self::ProofOfPossession(_), Self::ProofOfPossession(_))
        )
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::SignatureShare {
        match self {
            Self::Basic(s) => s,
            Self::MessageAugmentation(s) => s,
            Self::ProofOfPossession(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        let s = SignatureShare::<Bls12381G2Impl>::default();
        let bytes = Vec::<u8>::try_from(&s).unwrap();
        let s2 = SignatureShare::<Bls12381G2Impl>::try_from(&bytes).unwrap();
        assert_eq!(s, s2);

        let s = SignatureShare::<Bls12381G1Impl>::default();
        let bytes = Vec::<u8>::try_from(&s).unwrap();
        let s2 = SignatureShare::<Bls12381G1Impl>::try_from(&bytes).unwrap();
        assert_eq!(s, s2);
    }
}
