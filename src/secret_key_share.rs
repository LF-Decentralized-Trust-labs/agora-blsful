use crate::*;
use serde::{Deserialize, Serialize};

/// A secret key share is field element 0 < `x` < `r`
/// where `r` is the curve order.
///
/// See Section 4.3 in <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other secret key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyShare<C: BlsSignatureImpl>(
    #[serde(serialize_with = "traits::secret_key_share::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::secret_key_share::deserialize::<C, _>")]
    pub <C as Pairing>::SecretKeyShare,
);

impl<C: BlsSignatureImpl> Clone for SecretKeyShare<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl_from_derivatives_generic!(SecretKeyShare);

impl<C: BlsSignatureImpl> TryFrom<&SecretKeyShare<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(sk: &SecretKeyShare<C>) -> BlsResult<Self> {
        serde_bare::to_vec(sk).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SecretKeyShare<C> {
    type Error = BlsError;

    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes).map_err(BlsError::from)
    }
}

impl<C: BlsSignatureImpl> SecretKeyShare<C> {
    /// Compute the public key
    pub fn public_key(&self) -> BlsResult<PublicKeyShare<C>> {
        Ok(PublicKeyShare(<C as BlsSignatureCore>::public_key_share(
            &self.0,
        )?))
    }

    /// Sign a message with this secret key using the specified scheme
    pub fn sign<B: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
    ) -> BlsResult<SignatureShare<C>> {
        match scheme {
            SignatureSchemes::Basic => Ok(SignatureShare::Basic(
                <C as BlsSignatureBasic>::partial_sign(&self.0, msg)?,
            )),
            SignatureSchemes::MessageAugmentation => Err(BlsError::SigningError(
                "Message Augmentation not supported".to_string(),
            )),
            SignatureSchemes::ProofOfPossession => Ok(SignatureShare::ProofOfPossession(
                <C as BlsSignaturePop>::partial_sign(&self.0, msg)?,
            )),
        }
    }

    /// Sign a message share using the basic signature scheme.
    pub fn sign_basic(&self, msg: impl AsRef<[u8]>) -> BlsResult<SignatureShare<C>> {
        self.sign(SignatureSchemes::Basic, msg)
    }

    /// Sign a message share using the proof-of-possession signature scheme.
    pub fn sign_pop(&self, msg: impl AsRef<[u8]>) -> BlsResult<SignatureShare<C>> {
        self.sign(SignatureSchemes::ProofOfPossession, msg)
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::SecretKeyShare {
        &self.0
    }
}
