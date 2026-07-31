use crate::*;
use subtle::Choice;

/// A public key share is a point on the curve.
///
/// See Section 4.3 of <https://eprint.iacr.org/2016/663.pdf>.
/// A public key share must be combined with other public key shares to produce
/// the complete key, or it can be used to create partial signatures that can
/// be combined into a complete signature.
#[derive(Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyShare<C: BlsSignatureImpl>(pub <C as Pairing>::PublicKeyShare);

impl<C: BlsSignatureImpl> Copy for PublicKeyShare<C> {}

impl<C: BlsSignatureImpl> Clone for PublicKeyShare<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for PublicKeyShare<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKeyShare::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureImpl> Display for PublicKeyShare<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl_from_derivatives_generic!(PublicKeyShare);

impl<C: BlsSignatureImpl> TryFrom<&PublicKeyShare<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(pk: &PublicKeyShare<C>) -> BlsResult<Self> {
        serde_bare::to_vec(&pk.0).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for PublicKeyShare<C> {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes)
            .map(Self)
            .map_err(BlsError::from)
    }
}

impl<C: BlsSignatureImpl> PublicKeyShare<C> {
    /// Verify the signature share with the public key share.
    pub fn verify<B: AsRef<[u8]>>(&self, sig: &SignatureShare<C>, msg: B) -> BlsResult<()> {
        if self.0.identifier() != sig.as_raw_value().identifier() {
            return Err(BlsError::InvalidInputs(
                "signature and public key share identifiers differ".to_string(),
            ));
        }
        let pk = *self.0.value();
        match sig {
            SignatureShare::Basic(sig) => {
                let sig = *sig.value();
                <C as BlsSignatureBasic>::verify(pk.0, sig.0, msg)
            }
            SignatureShare::MessageAugmentation(sig) => {
                let sig = *sig.value();
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, sig.0, msg)
            }
            SignatureShare::ProofOfPossession(sig) => {
                let sig = *sig.value();
                <C as BlsSignaturePop>::verify(pk.0, sig.0, msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        let pk = PublicKeyShare::<Bls12381G2Impl>::default();
        let bytes = Vec::<u8>::try_from(&pk).unwrap();
        let pk2 = PublicKeyShare::try_from(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }
}
