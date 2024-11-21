//! The implementations of the BLS signature scheme
//! and all supporting types and algorithms

mod g1;
mod g2;

pub use g1::*;
pub use g2::*;

use crate::*;
use core::{
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    str::FromStr,
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// Types that implement BLS signatures
pub trait BlsSignatureImpl:
    BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop
{
}

/// A BLS signature implementation
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct BlsSignature<T: BlsSignatureImpl>(PhantomData<T>);

impl Default for BlsSignature<Bls12381G1Impl> {
    fn default() -> Self {
        BlsSignature(PhantomData)
    }
}

impl<T: BlsSignatureImpl> BlsSignature<T> {
    /// Create a new BLS signature implementation
    pub fn new() -> Self {
        BlsSignature(PhantomData)
    }

    /// Create a new random secret key
    pub fn new_secret_key() -> SecretKey<T> {
        SecretKey::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn secret_key_from_hash<B: AsRef<[u8]>>(data: B) -> SecretKey<T> {
        SecretKey(<T as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random_secret_key(mut rng: impl RngCore + CryptoRng) -> SecretKey<T> {
        SecretKey(<T as HashToScalar>::hash_to_scalar(
            rng.gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Create a new random commitment challenge for signature proofs of knowledge
    /// as step 2
    pub fn new_proof_challenge() -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::new()
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a hash
    /// as step 2
    pub fn proof_challenge_from_hash<B: AsRef<[u8]>>(data: B) -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::from_hash(data)
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a CS-PRNG
    /// as step 2
    pub fn random_proof_challenge(
        mut rng: impl RngCore + CryptoRng,
    ) -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::random(&mut rng)
    }
}

/// A BLS signature implementation using G1 for signatures and G2 for public keys
pub type Bls12381G1 = BlsSignature<Bls12381G1Impl>;

/// A BLS signature implementation using G2 for signatures and G1 for public keys
pub type Bls12381G2 = BlsSignature<Bls12381G2Impl>;

/// A convenience wrapper for the two BLS signature implementations
/// that doesn't require specifying the generics and can be used in
/// trait object like situations.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Bls12381 {
    /// A BLS signature implementation using G1 for signatures and G2 for public keys
    #[default]
    G1,
    /// A BLS signature implementation using G2 for signatures and G1 for public keys
    G2,
}

impl From<Bls12381> for u8 {
    fn from(bls: Bls12381) -> u8 {
        match bls {
            Bls12381::G1 => 1,
            Bls12381::G2 => 2,
        }
    }
}

impl From<&Bls12381> for u8 {
    fn from(bls: &Bls12381) -> u8 {
        u8::from(*bls)
    }
}

impl TryFrom<u8> for Bls12381 {
    type Error = BlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Bls12381::G1),
            2 => Ok(Bls12381::G2),
            _ => Err(BlsError::DeserializationError(
                "Invalid BLS12381 type".to_string(),
            )),
        }
    }
}

impl TryFrom<&u8> for Bls12381 {
    type Error = BlsError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl Display for Bls12381 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Bls12381::G1 => write!(f, "BLS12381G1"),
            Bls12381::G2 => write!(f, "BLS12381G2"),
        }
    }
}

impl FromStr for Bls12381 {
    type Err = BlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BLS12381G1" => Ok(Bls12381::G1),
            "BLS12381G2" => Ok(Bls12381::G2),
            _ => Err(BlsError::DeserializationError(
                "Invalid BLS12381 type".to_string(),
            )),
        }
    }
}

impl Serialize for Bls12381 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(u8::from(self))
        }
    }
}

impl<'de> Deserialize<'de> for Bls12381 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Bls12381::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let u = u8::deserialize(d)?;
            Bls12381::try_from(u).map_err(serde::de::Error::custom)
        }
    }
}

/// The inner representation types
pub mod inner_types {
    #[cfg(not(feature = "blst"))]
    pub use bls12_381_plus::{
        elliptic_curve::hash2curve::{
            ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander, ExpanderXmd,
        },
        ff::{Field, FieldBits, FromUniformBytes, PrimeField, PrimeFieldBits},
        group::{
            cofactor::*, prime::*, Curve, Group, GroupEncoding, GroupOps, GroupOpsOwned, ScalarMul,
            ScalarMulOwned, UncompressedEncoding,
        },
        multi_miller_loop, pairing, Bls12, Bls12381G1 as InnerBls12381G1,
        Bls12381G2 as InnerBls12381G2, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
        Gt, MillerLoopResult, Scalar, ScalarLe,
    };
    #[cfg(feature = "blst")]
    pub use blstrs_plus::{
        elliptic_curve::hash2curve::{
            ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander, ExpanderXmd,
        },
        ff::{Field, FieldBits, FromUniformBytes, PrimeField, PrimeFieldBits},
        group::{
            cofactor::*, prime::*, Curve, Group, GroupEncoding, GroupOps, GroupOpsOwned, ScalarMul,
            ScalarMulOwned, UncompressedEncoding,
        },
        multi_miller_loop, pairing,
        pairing_lib::{Engine, MillerLoopResult, MultiMillerLoop, PairingCurveAffine},
        Bls12, Bls12381G1 as InnerBls12381G1, Bls12381G2 as InnerBls12381G2, G1Affine,
        G1Compressed, G1Projective, G2Affine, G2Compressed, G2Prepared, G2Projective, Gt, Scalar,
    };
}
