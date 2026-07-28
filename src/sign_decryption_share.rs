use crate::*;

/// A public key share is point on the curve.
///
/// See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other public key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct SignDecryptionShare<C: BlsSignatureImpl>(pub <C as Pairing>::PublicKeyShare);

impl<C: BlsSignatureImpl> Clone for SignDecryptionShare<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> Copy for SignDecryptionShare<C> {}

impl<C: BlsSignatureImpl> fmt::Debug for SignDecryptionShare<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> TryFrom<&SignDecryptionShare<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(share: &SignDecryptionShare<C>) -> BlsResult<Self> {
        serde_bare::to_vec(&share.0).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignDecryptionShare<C> {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes)
            .map(Self)
            .map_err(BlsError::from)
    }
}

impl_from_derivatives_generic!(SignDecryptionShare);

impl<C: BlsSignatureImpl> SignDecryptionShare<C> {
    /// Verify the signcrypt decryption share with the corresponding public key and ciphertext
    pub fn verify(&self, pks: &PublicKeyShare<C>, sig: &SignCryptCiphertext<C>) -> BlsResult<()> {
        if self.0.identifier() != pks.0.identifier() {
            return Err(BlsError::InvalidDecryptionShare);
        }
        let share = *self.0.value();
        let pk = *pks.0.value();
        let dst = signature_dst::<C>(sig.scheme);
        if <C as BlsSignCrypt>::verify_share(share.0, pk.0, sig.u, &sig.v, sig.w, dst).into() {
            Ok(())
        } else {
            Err(BlsError::InvalidDecryptionShare)
        }
    }
}
