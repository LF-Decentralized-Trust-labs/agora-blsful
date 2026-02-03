use crate::helpers::{KEYGEN_SALT, get_crypto_rng};
use crate::impls::inner_types::*;
use crate::*;
use core::fmt::{self, Formatter};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::de::{SeqAccess, Visitor};
use subtle::CtOption;
use vsss_rs::*;

/// Number of bytes needed to represent the secret key
pub const SECRET_KEY_BYTES: usize = 32;

/// A BLS secret key implementation
///
/// This doesn't expose the underlying curve
/// and signature scheme and can be used in situations where the specific
/// implementation is not known at compile time and where trait objects
/// are desirable but can't be used due to the lack of `Sized` trait.
/// The downside is the type is now indicated with a byte or string
/// for serialization and deserialization. If this is not desirable,
/// then use [`SecretKey<C>`](struct.SecretKey.html) instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretKeyEnum {
    /// A secret key for signatures in G1 and public keys in G2
    G1(SecretKey<Bls12381G1Impl>),
    /// A secret key for signatures in G2 and public keys in G1
    G2(SecretKey<Bls12381G2Impl>),
}

impl Serialize for SecretKeyEnum {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            SecretKeyEnum::G1(sk) => (Bls12381::G1, sk).serialize(s),
            SecretKeyEnum::G2(sk) => (Bls12381::G2, sk).serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for SecretKeyEnum {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SecretKeyEnumVisitor;

        impl<'de> Visitor<'de> for SecretKeyEnumVisitor {
            type Value = SecretKeyEnum;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "a tuple of the type and secret key")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let ee = seq
                    .next_element::<Bls12381>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                match ee {
                    Bls12381::G1 => {
                        let sk = seq
                            .next_element::<SecretKey<Bls12381G1Impl>>()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(SecretKeyEnum::G1(sk))
                    }
                    Bls12381::G2 => {
                        let sk = seq
                            .next_element::<SecretKey<Bls12381G2Impl>>()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(SecretKeyEnum::G2(sk))
                    }
                }
            }
        }
        d.deserialize_tuple(2, SecretKeyEnumVisitor)
    }
}

impl Default for SecretKeyEnum {
    fn default() -> Self {
        Self::G1(SecretKey(Scalar::default()))
    }
}

impl From<&SecretKeyEnum> for Vec<u8> {
    fn from(value: &SecretKeyEnum) -> Self {
        let (tt, mut output) = match value {
            SecretKeyEnum::G1(sk) => (Bls12381::G1, Vec::from(sk)),
            SecretKeyEnum::G2(sk) => (Bls12381::G2, Vec::from(sk)),
        };
        output.insert(0, tt as u8);
        output
    }
}

impl TryFrom<&[u8]> for SecretKeyEnum {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let ee = Bls12381::try_from(value[0])?;
        match ee {
            Bls12381::G1 => {
                let sk = SecretKey::<Bls12381G1Impl>::try_from(&value[1..])?;
                Ok(SecretKeyEnum::G1(sk))
            }
            Bls12381::G2 => {
                let sk = SecretKey::<Bls12381G2Impl>::try_from(&value[1..])?;
                Ok(SecretKeyEnum::G2(sk))
            }
        }
    }
}

impl_from_derivatives!(SecretKeyEnum);

impl SecretKeyEnum {
    /// Create a new random secret key
    pub fn new(t: Bls12381) -> Self {
        match t {
            Bls12381::G1 => SecretKeyEnum::G1(SecretKey::new()),
            Bls12381::G2 => SecretKeyEnum::G2(SecretKey::new()),
        }
    }

    /// Compute a secret key from a hash
    pub fn from_hash<B: AsRef<[u8]>>(t: Bls12381, data: B) -> Self {
        match t {
            Bls12381::G1 => SecretKeyEnum::G1(SecretKey::from_hash(data)),
            Bls12381::G2 => SecretKeyEnum::G2(SecretKey::from_hash(data)),
        }
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random(t: Bls12381, rng: impl RngCore + CryptoRng) -> Self {
        match t {
            Bls12381::G1 => SecretKeyEnum::G1(SecretKey::random(rng)),
            Bls12381::G2 => SecretKeyEnum::G2(SecretKey::random(rng)),
        }
    }

    /// Get the big-endian byte representation of this key
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let (t, mut output) = match self {
            SecretKeyEnum::G1(sk) => (Bls12381::G1, Vec::from(sk.to_be_bytes())),
            SecretKeyEnum::G2(sk) => (Bls12381::G2, Vec::from(sk.to_be_bytes())),
        };
        output.insert(0, t as u8);
        output
    }

    /// Get the little-endian byte representation of this key
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let (t, mut output) = match self {
            SecretKeyEnum::G1(sk) => (Bls12381::G1, Vec::from(sk.to_le_bytes())),
            SecretKeyEnum::G2(sk) => (Bls12381::G2, Vec::from(sk.to_le_bytes())),
        };
        output.insert(0, t as u8);
        output
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_be_bytes(bytes: &[u8]) -> CtOption<Self> {
        let t = match Bls12381::try_from(bytes[0]) {
            Ok(t) => t,
            Err(_) => return CtOption::new(Self::default(), Choice::from(0u8)),
        };
        match (&bytes[1..]).try_into() {
            Ok(sk) => match t {
                Bls12381::G1 => {
                    let ct_sk = SecretKey::from_be_bytes(&sk);
                    let choice = ct_sk.is_some();
                    let val = if choice.into() {
                        SecretKeyEnum::G1(ct_sk.unwrap())
                    } else {
                        Self::default()
                    };
                    CtOption::new(val, choice)
                }
                Bls12381::G2 => {
                    let ct_sk = SecretKey::from_be_bytes(&sk);
                    let choice = ct_sk.is_some();
                    let val = if choice.into() {
                        SecretKeyEnum::G2(ct_sk.unwrap())
                    } else {
                        Self::default()
                    };
                    CtOption::new(val, choice)
                }
            },
            Err(_) => CtOption::new(Self::default(), Choice::from(0u8)),
        }
    }

    /// Convert a little-endian representation of the secret key.
    pub fn from_le_bytes(bytes: &[u8]) -> CtOption<Self> {
        let t = match Bls12381::try_from(bytes[0]) {
            Ok(t) => t,
            Err(_) => return CtOption::new(Self::default(), Choice::from(0u8)),
        };
        match (&bytes[1..]).try_into() {
            Ok(sk) => match t {
                Bls12381::G1 => {
                    let ct_sk = SecretKey::from_le_bytes(&sk);
                    let choice = ct_sk.is_some();
                    let val = if choice.into() {
                        SecretKeyEnum::G1(ct_sk.unwrap())
                    } else {
                        Self::default()
                    };
                    CtOption::new(val, choice)
                }
                Bls12381::G2 => {
                    let ct_sk = SecretKey::from_le_bytes(&sk);
                    let choice = ct_sk.is_some();
                    let val = if choice.into() {
                        SecretKeyEnum::G2(ct_sk.unwrap())
                    } else {
                        Self::default()
                    };
                    CtOption::new(val, choice)
                }
            },
            Err(_) => CtOption::new(Self::default(), Choice::from(0u8)),
        }
    }
}

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey<C: BlsSignatureImpl>(
    /// The secret key raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl<C: BlsSignatureImpl> From<SecretKey<C>> for [u8; SECRET_KEY_BYTES] {
    fn from(sk: SecretKey<C>) -> [u8; SECRET_KEY_BYTES] {
        sk.to_be_bytes()
    }
}

impl<'a, C: BlsSignatureImpl> From<&'a SecretKey<C>> for [u8; SECRET_KEY_BYTES] {
    fn from(sk: &'a SecretKey<C>) -> [u8; SECRET_KEY_BYTES] {
        sk.to_be_bytes()
    }
}

impl_from_derivatives_generic!(SecretKey);

impl<C: BlsSignatureImpl> From<&SecretKey<C>> for Vec<u8> {
    fn from(value: &SecretKey<C>) -> Self {
        value.to_be_bytes().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SecretKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value)
            .map_err(|_| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))?;
        Option::from(Self::from_be_bytes(&bytes))
            .ok_or_else(|| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))
    }
}

impl<C: BlsSignatureImpl> SecretKey<C> {
    /// Create a new random secret key
    pub fn new() -> Self {
        Self::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn from_hash<B: AsRef<[u8]>>(data: B) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            rng.r#gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Get the big-endian byte representation of this key
    pub fn to_be_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Get the little-endian byte representation of this key
    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_le_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_be_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Convert a little-endian representation of the secret key.
    pub fn from_le_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_le_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Secret share this key by creating `limit` shares where `threshold` are required
    /// to combine back into this secret
    pub fn split(&self, threshold: usize, limit: usize) -> BlsResult<Vec<SecretKeyShare<C>>> {
        self.split_with_rng(threshold, limit, get_crypto_rng())
    }

    /// Secret share this key by creating `limit` shares where `threshold` are required
    /// to combine back into this secret using a specified RNG
    pub fn split_with_rng(
        &self,
        threshold: usize,
        limit: usize,
        rng: impl RngCore + CryptoRng,
    ) -> BlsResult<Vec<SecretKeyShare<C>>> {
        let secret = IdentifierPrimeField(self.0);
        let shares =
            shamir::split_secret::<<C as Pairing>::SecretKeyShare>(threshold, limit, &secret, rng)?
                .into_iter()
                .map(SecretKeyShare)
                .collect::<Vec<_>>();
        Ok(shares)
    }

    /// Reconstruct a secret from shares created from `split`
    pub fn combine(shares: &[SecretKeyShare<C>]) -> BlsResult<Self> {
        let ss = shares.iter().map(|s| s.0.clone()).collect::<Vec<_>>();
        let secret = ss.combine()?;
        Ok(Self(secret.0))
    }

    /// Compute the public key
    pub fn public_key(&self) -> PublicKey<C> {
        PublicKey(<C as BlsSignatureCore>::public_key(&self.0))
    }

    /// Create a proof of possession
    pub fn proof_of_possession(&self) -> BlsResult<ProofOfPossession<C>> {
        Ok(ProofOfPossession(<C as BlsSignaturePop>::pop_prove(
            &self.0,
        )?))
    }

    /// Sign a message with this secret key using the specified scheme
    pub fn sign(&self, scheme: SignatureSchemes, msg: &[u8]) -> BlsResult<Signature<C>> {
        match scheme {
            SignatureSchemes::Basic => {
                let inner = <C as BlsSignatureBasic>::sign(&self.0, msg)?;
                Ok(Signature::Basic(inner))
            }
            SignatureSchemes::MessageAugmentation => {
                let inner = <C as BlsSignatureMessageAugmentation>::sign(&self.0, msg)?;
                Ok(Signature::MessageAugmentation(inner))
            }
            SignatureSchemes::ProofOfPossession => {
                let inner = <C as BlsSignaturePop>::sign(&self.0, msg)?;
                Ok(Signature::ProofOfPossession(inner))
            }
        }
    }

    /// Create a Signcrypt decryption key where the secret key is hidden
    /// that can decrypt ciphertext
    pub fn sign_decryption_key<B: AsRef<[u8]>>(
        &self,
        ciphertext: &SignCryptCiphertext<C>,
    ) -> SignCryptDecryptionKey<C> {
        SignCryptDecryptionKey(ciphertext.u * self.0)
    }
}
