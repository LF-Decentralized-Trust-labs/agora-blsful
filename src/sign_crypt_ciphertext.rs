use crate::*;
use subtle::CtOption;

/// Signcryption ciphertext for either supported BLS12-381 signature group.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SignCryptCiphertextEnum {
    /// A ciphertext using signatures in G1 and public keys in G2.
    G1(SignCryptCiphertext<Bls12381G1Impl>),
    /// A ciphertext using signatures in G2 and public keys in G1.
    G2(SignCryptCiphertext<Bls12381G2Impl>),
}

impl Default for SignCryptCiphertextEnum {
    fn default() -> Self {
        Self::G1(SignCryptCiphertext::default())
    }
}

impl SignCryptCiphertextEnum {
    /// Return the concrete BLS12-381 signature group for this ciphertext.
    pub fn curve(&self) -> Bls12381 {
        match self {
            Self::G1(_) => Bls12381::G1,
            Self::G2(_) => Bls12381::G2,
        }
    }

    /// Return the signature scheme used to create this ciphertext.
    pub const fn scheme(&self) -> SignatureSchemes {
        match self {
            Self::G1(ciphertext) => ciphertext.scheme(),
            Self::G2(ciphertext) => ciphertext.scheme(),
        }
    }

    /// Decrypt the signcryption ciphertext with a matching dynamic secret key.
    pub fn decrypt(&self, sk: &SecretKeyEnum) -> CtOption<Vec<u8>> {
        match (self, sk) {
            (Self::G1(ciphertext), SecretKeyEnum::G1(sk)) => ciphertext.decrypt(sk),
            (Self::G2(ciphertext), SecretKeyEnum::G2(sk)) => ciphertext.decrypt(sk),
            _ => CtOption::new(vec![], 0u8.into()),
        }
    }

    /// Check if the ciphertext is internally valid.
    pub fn is_valid(&self) -> Choice {
        match self {
            Self::G1(ciphertext) => ciphertext.is_valid(),
            Self::G2(ciphertext) => ciphertext.is_valid(),
        }
    }
}

/// A signcryption ciphertext.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignCryptCiphertext<C: BlsSignatureImpl> {
    /// The `u` component
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub u: <C as Pairing>::PublicKey,
    /// The `v` component
    pub v: Vec<u8>,
    /// The `w` component
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub w: <C as Pairing>::Signature,
    /// The signature scheme used to generate this ciphertext
    pub scheme: SignatureSchemes,
}

impl<C: BlsSignatureImpl> Display for SignCryptCiphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ u: {}, v: {:?}, w: {}, scheme: {:?} }}",
            self.u, self.v, self.w, self.scheme
        )
    }
}

impl<C: BlsSignatureImpl> TryFrom<&SignCryptCiphertext<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(value: &SignCryptCiphertext<C>) -> BlsResult<Self> {
        serde_bare::to_vec(value).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignCryptCiphertext<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives_generic!(SignCryptCiphertext);

impl<C: BlsSignatureImpl> SignCryptCiphertext<C> {
    /// Return the signature scheme used to create this ciphertext.
    pub const fn scheme(&self) -> SignatureSchemes {
        self.scheme
    }

    /// Create a decryption share from a secret key share.
    pub fn create_decryption_share(
        &self,
        sks: &SecretKeyShare<C>,
    ) -> BlsResult<SignDecryptionShare<C>> {
        Ok(SignDecryptionShare(
            <C as BlsSignatureCore>::public_key_share_with_generator(&sks.0, self.u)?,
        ))
    }

    /// Open the ciphertext given the decryption shares.
    pub fn decrypt_with_shares<B: AsRef<[SignDecryptionShare<C>]>>(
        &self,
        shares: B,
    ) -> CtOption<Vec<u8>> {
        let dst = signature_dst::<C>(self.scheme);

        let shares = shares.as_ref().iter().map(|s| s.0).collect::<Vec<_>>();
        <C as BlsSignCrypt>::unseal_with_shares(self.u, &self.v, self.w, shares.as_slice(), dst)
    }

    /// Decrypt the signcryption ciphertext.
    pub fn decrypt(&self, sk: &SecretKey<C>) -> CtOption<Vec<u8>> {
        let dst = signature_dst::<C>(self.scheme);

        <C as BlsSignCrypt>::unseal(self.u, &self.v, self.w, &sk.0, dst)
    }

    /// Check whether the ciphertext is valid.
    pub fn is_valid(&self) -> Choice {
        <C as BlsSignCrypt>::valid(self.u, &self.v, self.w, signature_dst::<C>(self.scheme))
    }
}

/// A signcryption decryption key derived from a secret key or combined shares.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCryptDecryptionKey<C: BlsSignatureImpl>(
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> fmt::Debug for SignCryptDecryptionKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Clone for SignCryptDecryptionKey<C> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureImpl> TryFrom<&SignCryptDecryptionKey<C>> for Vec<u8> {
    type Error = BlsError;

    fn try_from(value: &SignCryptDecryptionKey<C>) -> BlsResult<Self> {
        serde_bare::to_vec(value).map_err(|e| BlsError::SerializationError(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignCryptDecryptionKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives_generic!(SignCryptDecryptionKey);

impl<C: BlsSignatureImpl> SignCryptDecryptionKey<C> {
    /// Decrypt a signcryption ciphertext.
    pub fn decrypt(&self, ciphertext: &SignCryptCiphertext<C>) -> CtOption<Vec<u8>> {
        let dst = signature_dst::<C>(ciphertext.scheme);

        let choice = <C as BlsSignCrypt>::valid(ciphertext.u, &ciphertext.v, ciphertext.w, dst);
        <C as BlsSignCrypt>::decrypt(&ciphertext.v, self.0, choice)
    }

    /// Combine decryption shares into a signcryption decryption key.
    pub fn from_shares(shares: &[SignDecryptionShare<C>]) -> BlsResult<Self> {
        if shares.len() < 2 {
            return Err(BlsError::InvalidInputs(
                "at least two decryption shares are required".to_string(),
            ));
        }
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
