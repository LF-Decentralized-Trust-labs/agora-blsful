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

impl<C: BlsSignatureImpl> Display for SignatureShare<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for SignatureShare<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for SignatureShare<C> {}

impl<C: BlsSignatureImpl> Clone for SignatureShare<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for SignatureShare<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (Self::Basic(a), Self::Basic(b)) => Self::Basic(
                <C as Pairing>::SignatureShare::conditional_select(a, b, choice),
            ),
            (Self::MessageAugmentation(a), Self::MessageAugmentation(b)) => {
                Self::MessageAugmentation(<C as Pairing>::SignatureShare::conditional_select(
                    a, b, choice,
                ))
            }
            (Self::ProofOfPossession(a), Self::ProofOfPossession(b)) => Self::ProofOfPossession(
                <C as Pairing>::SignatureShare::conditional_select(a, b, choice),
            ),
            _ => panic!("SignatureShare::conditional_select: mismatched variants"),
        }
    }
}

impl_from_derivatives_generic!(SignatureShare);

impl<C: BlsSignatureImpl> From<&SignatureShare<C>> for Vec<u8> {
    fn from(s: &SignatureShare<C>) -> Self {
        match s {
            SignatureShare::Basic(s) => serde_bare::to_vec(&(SignatureSchemes::Basic, s)).unwrap(),
            SignatureShare::MessageAugmentation(s) => {
                serde_bare::to_vec(&(SignatureSchemes::MessageAugmentation, s)).unwrap()
            }
            SignatureShare::ProofOfPossession(s) => {
                serde_bare::to_vec(&(SignatureSchemes::ProofOfPossession, s)).unwrap()
            }
        }
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignatureShare<C> {
    type Error = BlsError;

    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        let (scheme, s): (SignatureSchemes, <C as Pairing>::SignatureShare) =
            serde_bare::from_slice(bytes)
                .map_err(|_| BlsError::InvalidInputs("invalid byte sequence".to_string()))?;
        match scheme {
            SignatureSchemes::Basic => Ok(Self::Basic(s)),
            SignatureSchemes::MessageAugmentation => Ok(Self::MessageAugmentation(s)),
            SignatureSchemes::ProofOfPossession => Ok(Self::ProofOfPossession(s)),
        }
    }
}

impl<C: BlsSignatureImpl> SignatureShare<C> {
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

    /// Convert a share byte sequence from version 1 to a signature share
    /// that was output from converting to Vec<u8>
    pub fn from_v1_inner_bytes(raw_bytes: &[u8]) -> BlsResult<Self> {
        let mut repr = <C::Signature as GroupEncoding>::Repr::default();
        if repr.as_ref().len() != raw_bytes.len() - 2 {
            return Err(BlsError::InvalidInputs("invalid byte sequence".to_string()));
        }

        let identifier = IdentifierPrimeField(<<C as Pairing>::Signature as Group>::Scalar::from(
            raw_bytes[1] as u64,
        ));
        repr.as_mut().copy_from_slice(&raw_bytes[2..]);
        let value = Option::<C::Signature>::from(C::Signature::from_bytes(&repr))
            .ok_or(BlsError::InvalidSignature)?;
        let inner = <C as Pairing>::SignatureShare::with_identifier_and_value(
            identifier,
            ValueGroup(value),
        );
        match raw_bytes[0] {
            0 => Ok(Self::Basic(inner)),
            1 => Ok(Self::MessageAugmentation(inner)),
            2 => Ok(Self::ProofOfPossession(inner)),
            _ => Err(BlsError::InvalidInputs("invalid byte sequence".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        let s = SignatureShare::<Bls12381G2Impl>::default();
        let bytes = Vec::<u8>::from(&s);
        let s2 = SignatureShare::<Bls12381G2Impl>::try_from(&bytes).unwrap();
        assert_eq!(s, s2);

        let mut bytes = [0u8; 98];
        bytes[0] = 2;
        bytes[2] = 192; // set the point at identity flag
        let s2 = SignatureShare::from_v1_inner_bytes(&bytes).unwrap();
        assert_eq!(s, s2);

        let s = SignatureShare::<Bls12381G1Impl>::default();
        let bytes = Vec::<u8>::from(&s);
        let s2 = SignatureShare::<Bls12381G1Impl>::try_from(&bytes).unwrap();
        assert_eq!(s, s2);

        let mut bytes = [0u8; 50];
        bytes[0] = 2;
        bytes[2] = 192; // set the point at identity flag
        let s2 = SignatureShare::from_v1_inner_bytes(&bytes).unwrap();
        assert_eq!(s, s2);
    }
}
