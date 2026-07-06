use crate::*;
use subtle::{Choice, ConditionallySelectable};

/// A proof of possession for either supported BLS12-381 signature group.
///
/// This is the dynamic counterpart to [`ProofOfPossession<C>`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofOfPossessionEnum {
    /// A proof for signatures in G1 and public keys in G2.
    G1(ProofOfPossession<Bls12381G1Impl>),
    /// A proof for signatures in G2 and public keys in G1.
    G2(ProofOfPossession<Bls12381G2Impl>),
}

impl Default for ProofOfPossessionEnum {
    fn default() -> Self {
        Self::G1(ProofOfPossession::default())
    }
}

impl From<&ProofOfPossessionEnum> for Vec<u8> {
    fn from(value: &ProofOfPossessionEnum) -> Self {
        let (t, output) = match value {
            ProofOfPossessionEnum::G1(pop) => (Bls12381::G1, Vec::from(pop)),
            ProofOfPossessionEnum::G2(pop) => (Bls12381::G2, Vec::from(pop)),
        };
        typed_bytes(t, output)
    }
}

impl TryFrom<&[u8]> for ProofOfPossessionEnum {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (t, value) = Bls12381::split_typed_bytes(value)?;
        match t {
            Bls12381::G1 => ProofOfPossession::<Bls12381G1Impl>::try_from(value).map(Self::G1),
            Bls12381::G2 => ProofOfPossession::<Bls12381G2Impl>::try_from(value).map(Self::G2),
        }
    }
}

impl_from_derivatives!(ProofOfPossessionEnum);

impl ProofOfPossessionEnum {
    /// Return the concrete BLS12-381 signature group for this proof.
    pub fn curve(&self) -> Bls12381 {
        match self {
            Self::G1(_) => Bls12381::G1,
            Self::G2(_) => Bls12381::G2,
        }
    }

    /// Verify this proof of possession with a matching dynamic public key.
    pub fn verify(&self, pk: PublicKeyEnum) -> BlsResult<()> {
        match (self, pk) {
            (Self::G1(pop), PublicKeyEnum::G1(pk)) => pop.verify(pk),
            (Self::G2(pop), PublicKeyEnum::G2(pk)) => pop.verify(pk),
            _ => Err(BlsError::InvalidInputs(
                "proof and public key curve variants differ".to_string(),
            )),
        }
    }
}

/// A proof of possession of the secret key
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofOfPossession<C: BlsSignatureImpl>(
    /// The BLS proof of possession raw value
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub <C as Pairing>::Signature,
);

impl<C: BlsSignatureImpl> Default for ProofOfPossession<C> {
    fn default() -> Self {
        Self(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> Display for ProofOfPossession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for ProofOfPossession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ProofOfPossession{{ {:?} }}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for ProofOfPossession<C> {}

impl<C: BlsSignatureImpl> Clone for ProofOfPossession<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> ConditionallySelectable for ProofOfPossession<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::Signature::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl_from_derivatives_generic!(ProofOfPossession);

impl<C: BlsSignatureImpl> From<&ProofOfPossession<C>> for Vec<u8> {
    fn from(value: &ProofOfPossession<C>) -> Self {
        value.0.to_bytes().as_ref().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofOfPossession<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = C::Signature::default().to_bytes();
        let len = repr.as_ref().len();

        if len != value.len() {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }

        repr.as_mut().copy_from_slice(value);
        let key: Option<C::Signature> = C::Signature::from_bytes(&repr).into();
        key.map(Self)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid byte sequence".to_string()))
    }
}

impl<C: BlsSignatureImpl> ProofOfPossession<C> {
    /// Verify this proof of possession
    pub fn verify(&self, pk: PublicKey<C>) -> BlsResult<()> {
        <C as BlsSignaturePop>::pop_verify(pk.0, self.0)
    }
}
