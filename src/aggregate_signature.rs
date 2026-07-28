use crate::*;
use std::collections::HashMap;

/// A BLS aggregate signature combining signatures over different messages.
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

impl_signature_enum_traits!(AggregateSignature, <C as Pairing>::Signature);

impl<C: BlsSignatureImpl> TryFrom<&[Signature<C>]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(sigs: &[Signature<C>]) -> Result<Self, Self::Error> {
        if sigs.len() < 2 {
            return Err(BlsError::InvalidSignature);
        }
        let first = &sigs[0];
        let mut aggregate = *first.as_raw_value();
        for s in &sigs[1..] {
            if !s.same_scheme(first) {
                return Err(BlsError::InvalidSignatureScheme);
            }
            aggregate += s.as_raw_value();
        }
        match first {
            Signature::Basic(_) => Ok(Self::Basic(aggregate)),
            Signature::MessageAugmentation(_) => Ok(Self::MessageAugmentation(aggregate)),
            Signature::ProofOfPossession(_) => Ok(Self::ProofOfPossession(aggregate)),
        }
    }
}

impl_from_derivatives_generic!(AggregateSignature);

impl<C: BlsSignatureImpl> TryFrom<&AggregateSignature<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(value: &AggregateSignature<C>) -> BlsResult<Self> {
        serde_bare::to_vec(value).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(BlsError::from)
    }
}

impl<C: BlsSignatureImpl> AggregateSignature<C> {
    /// Return the signature scheme used to create this aggregate signature.
    pub const fn scheme(&self) -> SignatureSchemes {
        match self {
            Self::Basic(_) => SignatureSchemes::Basic,
            Self::MessageAugmentation(_) => SignatureSchemes::MessageAugmentation,
            Self::ProofOfPossession(_) => SignatureSchemes::ProofOfPossession,
        }
    }

    /// Accumulate multiple signatures into one aggregate signature.
    pub fn from_signatures<B: AsRef<[Signature<C>]>>(signatures: B) -> BlsResult<Self> {
        Self::try_from(signatures.as_ref())
    }

    /// Verify the aggregate signature.
    ///
    /// Basic-scheme verification rejects duplicate messages as required by that
    /// ciphersuite. Message Augmentation and Proof of Possession permit them.
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKey<C>, B)]) -> BlsResult<()> {
        if data.len() < 2 {
            return Err(BlsError::InvalidInputs(
                "at least two public key and message pairs are required".to_string(),
            ));
        }
        match self {
            Self::Basic(sig) => {
                let mut messages = HashMap::with_capacity(data.len());
                for (index, (_, message)) in data.iter().enumerate() {
                    if let Some(previous) = messages.insert(message.as_ref(), index) {
                        return Err(BlsError::InvalidInputs(format!(
                            "duplicate messages detected at {} and {}",
                            previous, index
                        )));
                    }
                }
                <C as BlsSignatureCore>::core_aggregate_verify(
                    data.iter().map(|(pk, message)| (pk.0, message.as_ref())),
                    *sig,
                    <C as BlsSignatureBasic>::DST,
                )
            }
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::aggregate_verify(
                    data.iter().map(|(pk, message)| (pk.0, message)),
                    *sig,
                )
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::aggregate_verify(
                data.iter().map(|(pk, message)| (pk.0, message)),
                *sig,
            ),
        }
    }
}
