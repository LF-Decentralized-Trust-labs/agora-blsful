use crate::*;
use subtle::CtOption;

/// Time-lock ciphertext for either supported BLS12-381 signature group.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TimeCryptCiphertextEnum {
    /// A ciphertext using signatures in G1 and public keys in G2.
    G1(TimeCryptCiphertext<Bls12381G1Impl>),
    /// A ciphertext using signatures in G2 and public keys in G1.
    G2(TimeCryptCiphertext<Bls12381G2Impl>),
}

impl Default for TimeCryptCiphertextEnum {
    fn default() -> Self {
        Self::G1(TimeCryptCiphertext::default())
    }
}

impl TimeCryptCiphertextEnum {
    /// Return the concrete BLS12-381 signature group for this ciphertext.
    pub fn curve(&self) -> Bls12381 {
        match self {
            Self::G1(_) => Bls12381::G1,
            Self::G2(_) => Bls12381::G2,
        }
    }

    /// Decrypt the time-lock ciphertext with a matching dynamic signature.
    pub fn decrypt(&self, sig: &SignatureEnum) -> CtOption<Vec<u8>> {
        match (self, sig) {
            (Self::G1(ciphertext), SignatureEnum::G1(sig)) => ciphertext.decrypt(sig),
            (Self::G2(ciphertext), SignatureEnum::G2(sig)) => ciphertext.decrypt(sig),
            _ => CtOption::new(vec![], 0u8.into()),
        }
    }
}

/// The ciphertext output from time lock encryption
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TimeCryptCiphertext<C: BlsSignatureImpl> {
    /// The `u` component
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub u: <C as Pairing>::PublicKey,
    /// The `v` component
    pub v: [u8; 32],
    /// The `w` component
    pub w: Vec<u8>,
    /// The signature scheme used to generate this ciphertext
    pub scheme: SignatureSchemes,
}

impl<C: BlsSignatureImpl> From<&TimeCryptCiphertext<C>> for Vec<u8> {
    fn from(value: &TimeCryptCiphertext<C>) -> Self {
        serde_bare::to_vec(value).expect("failed to serialize time crypt ciphertext")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for TimeCryptCiphertext<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives_generic!(TimeCryptCiphertext);

impl<C: BlsSignatureImpl> TimeCryptCiphertext<C> {
    /// Decrypt the time lock ciphertext using a signature over an identifier
    pub fn decrypt(&self, sig: &Signature<C>) -> CtOption<Vec<u8>> {
        let (s, valid) = match (sig, self.scheme) {
            (Signature::Basic(s), SignatureSchemes::Basic) => (*s, 1u8.into()),
            (Signature::MessageAugmentation(s), SignatureSchemes::MessageAugmentation) => {
                (*s, 1u8.into())
            }
            (Signature::ProofOfPossession(s), SignatureSchemes::ProofOfPossession) => {
                (*s, 1u8.into())
            }
            (_, _) => (<C as Pairing>::Signature::default(), 0u8.into()),
        };
        <C as BlsTimeCrypt>::unseal(self.u, &self.v, &self.w, s, valid)
    }
}
