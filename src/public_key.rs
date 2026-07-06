use crate::impls::inner_types::*;
use crate::*;

/// A public key for either supported BLS12-381 signature group.
///
/// This is the dynamic counterpart to [`PublicKey<C>`]. Use it when the G1/G2
/// choice is only known at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PublicKeyEnum {
    /// A public key for signatures in G1 and public keys in G2.
    G1(PublicKey<Bls12381G1Impl>),
    /// A public key for signatures in G2 and public keys in G1.
    G2(PublicKey<Bls12381G2Impl>),
}

impl Default for PublicKeyEnum {
    fn default() -> Self {
        Self::G1(PublicKey::default())
    }
}

impl From<&PublicKeyEnum> for Vec<u8> {
    fn from(value: &PublicKeyEnum) -> Self {
        let (t, output) = match value {
            PublicKeyEnum::G1(pk) => (Bls12381::G1, Vec::from(pk)),
            PublicKeyEnum::G2(pk) => (Bls12381::G2, Vec::from(pk)),
        };
        typed_bytes(t, output)
    }
}

impl TryFrom<&[u8]> for PublicKeyEnum {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (t, value) = Bls12381::split_typed_bytes(value)?;
        match t {
            Bls12381::G1 => PublicKey::<Bls12381G1Impl>::try_from(value).map(PublicKeyEnum::G1),
            Bls12381::G2 => PublicKey::<Bls12381G2Impl>::try_from(value).map(PublicKeyEnum::G2),
        }
    }
}

impl_from_derivatives!(PublicKeyEnum);

impl PublicKeyEnum {
    /// Return the concrete BLS12-381 signature group for this public key.
    pub fn curve(&self) -> Bls12381 {
        match self {
            Self::G1(_) => Bls12381::G1,
            Self::G2(_) => Bls12381::G2,
        }
    }

    /// Encrypt a message using signcryption.
    pub fn sign_crypt<B: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
    ) -> SignCryptCiphertextEnum {
        match self {
            Self::G1(pk) => SignCryptCiphertextEnum::G1(pk.sign_crypt(scheme, msg)),
            Self::G2(pk) => SignCryptCiphertextEnum::G2(pk.sign_crypt(scheme, msg)),
        }
    }

    /// Encrypt a message using time lock encryption.
    pub fn encrypt_time_lock<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
        id: D,
    ) -> BlsResult<TimeCryptCiphertextEnum> {
        match self {
            Self::G1(pk) => pk
                .encrypt_time_lock(scheme, msg, id)
                .map(TimeCryptCiphertextEnum::G1),
            Self::G2(pk) => pk
                .encrypt_time_lock(scheme, msg, id)
                .map(TimeCryptCiphertextEnum::G2),
        }
    }
}

/// A BLS public key
#[derive(Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicKey<C: BlsSignatureImpl>(
    /// The BLS public key raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> From<&SecretKey<C>> for PublicKey<C> {
    fn from(s: &SecretKey<C>) -> Self {
        Self(<C as Pairing>::PublicKey::generator() * s.0)
    }
}

impl<C: BlsSignatureImpl> Display for PublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for PublicKey<C> {}

impl<C: BlsSignatureImpl> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for PublicKey<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKey::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl_from_derivatives_generic!(PublicKey);

impl<C: BlsSignatureImpl> From<&PublicKey<C>> for Vec<u8> {
    fn from(value: &PublicKey<C>) -> Self {
        value.0.to_bytes().as_ref().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for PublicKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = C::PublicKey::default().to_bytes();
        let len = repr.as_ref().len();

        if len != value.len() {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }

        repr.as_mut().copy_from_slice(value);
        let key: Option<C::PublicKey> = C::PublicKey::from_bytes(&repr).into();
        key.map(Self)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid byte sequence".to_string()))
    }
}

impl<C: BlsSignatureImpl> PublicKey<C> {
    /// Encrypt a message using signcryption
    pub fn sign_crypt<B: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
    ) -> SignCryptCiphertext<C> {
        let dst = match scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };
        let (u, v, w) = <C as BlsSignCrypt>::seal(self.0, msg.as_ref(), dst);
        SignCryptCiphertext { u, v, w, scheme }
    }

    /// Encrypt a message using time lock encryption
    pub fn encrypt_time_lock<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
        id: D,
    ) -> BlsResult<TimeCryptCiphertext<C>> {
        let dst = match scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };
        let (u, v, w) = <C as BlsTimeCrypt>::seal(self.0, msg.as_ref(), id.as_ref(), dst)?;
        Ok(TimeCryptCiphertext { u, v, w, scheme })
    }

    /// Encrypt a message using ElGamal
    pub fn encrypt_key_el_gamal(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalCiphertext<C>> {
        let (c1, c2) = <C as BlsElGamal>::seal_scalar(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalCiphertext { c1, c2 })
    }

    /// Encrypt a message using ElGamal and generate a proof
    pub fn encrypt_key_el_gamal_with_proof(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalProof<C>> {
        let (c1, c2, message_proof, blinder_proof, challenge) =
            <C as BlsElGamal>::seal_scalar_with_proof(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalProof {
            ciphertext: ElGamalCiphertext { c1, c2 },
            message_proof,
            blinder_proof,
            challenge,
        })
    }

    /// Create a public key from secret shares
    pub fn from_shares(shares: &[PublicKeyShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
