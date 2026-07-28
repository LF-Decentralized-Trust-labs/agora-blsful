use crate::*;

/// A BLS multi-signature combining signatures over the same message.
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MultiSignature<C: BlsSignatureImpl> {
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

impl<C: BlsSignatureImpl> Default for MultiSignature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl_signature_enum_traits!(MultiSignature, <C as Pairing>::Signature);

impl<C: BlsSignatureImpl> TryFrom<&[Signature<C>]> for MultiSignature<C> {
    type Error = BlsError;

    fn try_from(sigs: &[Signature<C>]) -> Result<Self, Self::Error> {
        if sigs.len() < 2 {
            return Err(BlsError::InvalidSignature);
        }
        let first = &sigs[0];
        if matches!(first, Signature::MessageAugmentation(_)) {
            return Err(BlsError::InvalidSignatureScheme);
        }
        let mut aggregate = *first.as_raw_value();
        for s in &sigs[1..] {
            if !s.same_scheme(first) {
                return Err(BlsError::InvalidSignatureScheme);
            }
            aggregate += s.as_raw_value();
        }
        match first {
            Signature::Basic(_) => Ok(Self::Basic(aggregate)),
            Signature::MessageAugmentation(_) => Err(BlsError::InvalidSignatureScheme),
            Signature::ProofOfPossession(_) => Ok(Self::ProofOfPossession(aggregate)),
        }
    }
}

impl_from_derivatives_generic!(MultiSignature);

impl<C: BlsSignatureImpl> TryFrom<&MultiSignature<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(value: &MultiSignature<C>) -> BlsResult<Self> {
        serde_bare::to_vec(value).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for MultiSignature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(BlsError::from)
    }
}

impl<C: BlsSignatureImpl> MultiSignature<C> {
    /// Return the signature scheme used to create this multi-signature.
    pub const fn scheme(&self) -> SignatureSchemes {
        match self {
            Self::Basic(_) => SignatureSchemes::Basic,
            Self::MessageAugmentation(_) => SignatureSchemes::MessageAugmentation,
            Self::ProofOfPossession(_) => SignatureSchemes::ProofOfPossession,
        }
    }

    /// Verify the multi-signature using the multi-public key.
    pub fn verify<B: AsRef<[u8]>>(&self, pk: &MultiPublicKey<C>, msg: B) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::verify(pk.0, *sig, msg),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, *sig, msg)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::verify(pk.0, *sig, msg),
        }
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::Signature {
        match self {
            Self::Basic(s) => s,
            Self::MessageAugmentation(s) => s,
            Self::ProofOfPossession(s) => s,
        }
    }

    /// Accumulate multiple signatures into a single signature
    pub fn from_signatures<B: AsRef<[Signature<C>]>>(signatures: B) -> BlsResult<Self> {
        Self::try_from(signatures.as_ref())
    }
}
