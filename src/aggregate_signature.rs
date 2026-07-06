use crate::impls::inner_types::*;
use crate::*;

/// Represents a BLS signature for multiple signatures that signed different messages
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AggregateSignature<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession scheme
    ProofOfPossession(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<C: BlsSignatureImpl> Default for AggregateSignature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl_signature_enum_traits!(
    AggregateSignature,
    <C as Pairing>::Signature,
    "Signature::conditional_select: mismatched variants"
);

impl<C: BlsSignatureImpl> TryFrom<&[Signature<C>]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(sigs: &[Signature<C>]) -> Result<Self, Self::Error> {
        if sigs.len() < 2 {
            return Err(BlsError::InvalidSignature);
        }
        let mut g = <C as Pairing>::Signature::identity();
        for s in &sigs[1..] {
            if !s.same_scheme(&sigs[0]) {
                return Err(BlsError::InvalidSignatureScheme);
            }
            let ss = match s {
                Signature::Basic(sig) => sig,
                Signature::MessageAugmentation(sig) => sig,
                Signature::ProofOfPossession(sig) => sig,
            };
            g += ss;
        }
        match sigs[0] {
            Signature::Basic(s) => Ok(Self::Basic(g + s)),
            Signature::MessageAugmentation(s) => Ok(Self::MessageAugmentation(g + s)),
            Signature::ProofOfPossession(s) => Ok(Self::ProofOfPossession(g + s)),
        }
    }
}

impl_from_derivatives_generic!(AggregateSignature);

impl<C: BlsSignatureImpl> From<&AggregateSignature<C>> for Vec<u8> {
    fn from(value: &AggregateSignature<C>) -> Self {
        serde_bare::to_vec(value).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> AggregateSignature<C> {
    /// Accumulate multiple signatures into a single signature
    /// Verify fails if any signed message is a duplicate
    pub fn from_signatures<B: AsRef<[Signature<C>]>>(signatures: B) -> BlsResult<Self> {
        Self::try_from(signatures.as_ref())
    }

    /// Verify the aggregated signature using the public keys
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKey<C>, B)]) -> BlsResult<()> {
        let ii = data.iter().map(|(pk, m)| (pk.0, m));
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::aggregate_verify(ii, *sig),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::aggregate_verify(ii, *sig)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::aggregate_verify(ii, *sig),
        }
    }
}
