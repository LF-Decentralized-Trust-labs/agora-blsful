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

impl<C: BlsSignatureImpl> From<&SecretKeyShare<C>> for Vec<u8> {
    fn from(sk: &SecretKeyShare<C>) -> Self {
        serde_bare::to_vec(sk).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SecretKeyShare<C> {
    type Error = BlsError;

    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes).map_err(|e| BlsError::InvalidInputs(e.to_string()))
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

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::SecretKeyShare {
        &self.0
    }

    /// Convert secret share from SecretKeyShare v1 to the newer v2 format
    pub fn from_v1_bytes(bytes: &[u8]) -> BlsResult<Self> {
        if bytes.len() != 33 {
            return Err(BlsError::InvalidInputs(
                "Invalid byte sequence length".to_string(),
            ));
        }

        let identifier = IdentifierPrimeField(<<C as Pairing>::PublicKey as Group>::Scalar::from(
            bytes[0] as u64,
        ));
        let mut repr =
            <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes[1..]);
        let inner_value = Option::<<<C as Pairing>::PublicKey as Group>::Scalar>::from(
            <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr),
        )
        .ok_or_else(|| BlsError::InvalidInputs("Invalid scalar".to_string()))?;
        let value = IdentifierPrimeField(inner_value);
        Ok(Self(C::SecretKeyShare::with_identifier_and_value(
            identifier, value,
        )))
    }
}
