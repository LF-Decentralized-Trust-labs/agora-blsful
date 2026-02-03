use crate::*;
use subtle::Choice;

/// A public key share is point on the curve.
///
/// See Section 4.3 in <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other public key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
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

impl<C: BlsSignatureImpl> From<&PublicKeyShare<C>> for Vec<u8> {
    fn from(pk: &PublicKeyShare<C>) -> Vec<u8> {
        serde_bare::to_vec(&pk.0).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for PublicKeyShare<C> {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes)
            .map(Self)
            .map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> PublicKeyShare<C> {
    /// Verify the signature share with the public key share
    pub fn verify<B: AsRef<[u8]>>(&self, sig: &SignatureShare<C>, msg: B) -> BlsResult<()> {
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

    /// Convert a share byte sequence from version 1 to a public key share
    /// that was output from converting to Vec<u8>
    pub fn from_v1_inner_bytes(raw_bytes: &[u8]) -> BlsResult<Self> {
        let mut repr = <C::PublicKey as GroupEncoding>::Repr::default();
        if repr.as_ref().len() != raw_bytes.len() - 1 {
            return Err(BlsError::InvalidInputs("invalid byte sequence".to_string()));
        }

        let identifier = IdentifierPrimeField(<<C as Pairing>::PublicKey as Group>::Scalar::from(
            raw_bytes[0] as u64,
        ));
        repr.as_mut().copy_from_slice(&raw_bytes[1..]);
        let value = Option::<C::PublicKey>::from(C::PublicKey::from_bytes(&repr))
            .ok_or(BlsError::InvalidSignature)?;
        let inner = <C as Pairing>::PublicKeyShare::with_identifier_and_value(
            identifier,
            ValueGroup(value),
        );
        Ok(Self(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        let pk = PublicKeyShare::<Bls12381G2Impl>::default();
        let bytes = Vec::<u8>::from(&pk);
        let pk2 = PublicKeyShare::try_from(&bytes).unwrap();
        assert_eq!(pk, pk2);

        let mut bytes = [0u8; 49];
        bytes[1] = 192;
        let pk2 = PublicKeyShare::<Bls12381G2Impl>::from_v1_inner_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }
}
