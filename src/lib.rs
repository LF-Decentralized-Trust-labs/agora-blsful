//! This crate implements BLS signatures according to the IETF latest draft
//!
//! for the Proof of Possession Cipher Suite
//!
//! Since BLS signatures can use either G1 or G2 fields, there are two types of
//! public keys and signatures.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

#[cfg(all(not(feature = "rust"), not(feature = "blst")))]
compile_error!("At least `rust` or `blst` must be selected");

#[macro_use]
mod macros;
mod helpers;

use helpers::*;

mod aggregate_signature;
mod elgamal_ciphertext;
mod elgamal_decryption_share;
mod elgamal_proof;
mod error;
mod impls;
mod multi_public_key;
mod multi_signature;
mod proof_commitment;
mod proof_of_knowledge;
mod proof_of_possession;
mod public_key;
mod public_key_share;
mod secret_key;
mod secret_key_share;
mod sig_types;
mod sign_crypt_ciphertext;
mod sign_decryption_share;
mod signature;
mod signature_share;
mod time_crypt_ciphertext;
mod traits;

pub use error::*;
pub use impls::*;

pub use aggregate_signature::*;
pub use elgamal_ciphertext::*;
pub use elgamal_decryption_share::*;
pub use elgamal_proof::*;
pub use multi_public_key::*;
pub use multi_signature::*;
pub use proof_commitment::*;
pub use proof_of_knowledge::*;
pub use proof_of_possession::*;
pub use public_key::*;
pub use public_key_share::*;
pub use secret_key::*;
pub use secret_key_share::*;
pub use sig_types::*;
pub use sign_crypt_ciphertext::*;
pub use sign_decryption_share::*;
pub use signature::*;
pub use signature_share::*;
pub use time_crypt_ciphertext::*;
pub use traits::*;

pub use vsss_rs;

use inner_types::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Display, Formatter, LowerHex, UpperHex},
    hash::Hash,
};
use subtle::Choice;
use vsss_rs::{DefaultShare, IdentifierPrimeField, Share, ValueGroup};
use zeroize::DefaultIsZeroes;

/// The share type for points in G1
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct InnerPointShareG1(
    pub DefaultShare<IdentifierPrimeField<Scalar>, ValueGroup<G1Projective>>,
);

impl subtle::ConditionallySelectable for InnerPointShareG1 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let identifier1 = a.0.identifier.0;
        let identifier2 = b.0.identifier.0;
        let value1 = b.0.value.to_affine();
        let value2 = b.0.value.to_affine();

        let identifier = Scalar::conditional_select(&identifier1, &identifier2, choice);
        let value = G1Affine::conditional_select(&value1, &value2, choice);
        Self((identifier, G1Projective::from(value)).into())
    }
}

impl_from_derivatives!(InnerPointShareG1);

impl TryFrom<&[u8]> for InnerPointShareG1 {
    type Error = BlsError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() != Scalar::BYTES + G1Projective::COMPRESSED_BYTES {
            return Err(BlsError::DeserializationError(
                "Invalid length for InnerPointShareG1".to_string(),
            ));
        }
        let identifier_bytes: [u8; Scalar::BYTES] =
            (&input[0..Scalar::BYTES]).try_into().map_err(|_| {
                BlsError::DeserializationError("Invalid length for Identifier".to_string())
            })?;
        let identifier = Option::<Scalar>::from(Scalar::from_be_bytes(&identifier_bytes))
            .ok_or_else(|| {
                BlsError::DeserializationError(
                    "Invalid Identifier, cannot convert to scalar".to_string(),
                )
            })?;
        let value_bytes: [u8; G1Projective::COMPRESSED_BYTES] = (&input[Scalar::BYTES..])
            .try_into()
            .map_err(|_| BlsError::DeserializationError("Invalid length for Value".to_string()))?;
        let value = Option::<G1Projective>::from(G1Projective::from_compressed(&value_bytes))
            .ok_or_else(|| {
                BlsError::DeserializationError(
                    "Invalid Value, cannot convert to G1Projective".to_string(),
                )
            })?;

        Ok(Self((identifier, value).into()))
    }
}

impl From<&InnerPointShareG1> for Vec<u8> {
    fn from(value: &InnerPointShareG1) -> Self {
        let mut output = vec![0u8; Scalar::BYTES + G1Projective::COMPRESSED_BYTES];
        output[..Scalar::BYTES].copy_from_slice(&value.0.identifier.0.to_be_bytes());
        output[Scalar::BYTES..].copy_from_slice(&value.0.value.0.to_compressed());
        output
    }
}

impl LowerHex for InnerPointShareG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &Vec::from(self) {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for InnerPointShareG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &Vec::from(self) {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Display for InnerPointShareG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ identifier: {}, value: {} }}",
            self.0.identifier.0, self.0.value.0
        )
    }
}

impl Share for InnerPointShareG1 {
    type Identifier = IdentifierPrimeField<Scalar>;

    type Value = ValueGroup<G1Projective>;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        Self(DefaultShare { identifier, value })
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.0.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0.identifier
    }

    fn value(&self) -> &Self::Value {
        &self.0.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.0.value
    }
}

impl InnerPointShareG1 {
    /// Convert secret share from InnerPointShareG1 v1 to the newer v2 format
    pub fn from_v1_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        #[derive(Deserialize)]
        struct V1(#[serde(deserialize_with = "fixed_arr::BigArray::deserialize")] [u8; 49]);
        let v1 = serde_bare::from_slice::<V1>(bytes)
            .map_err(|e| BlsError::InvalidInputs(e.to_string()))?;
        let identifier = Scalar::from(v1.0[0] as u64);
        let mut repr = [0u8; 48];
        repr.copy_from_slice(&v1.0[1..]);
        let value = Option::from(G1Projective::from_compressed(&repr)).ok_or_else(|| {
            BlsError::InvalidInputs("Invalid compressed G1Projective".to_string())
        })?;
        Ok(Self((identifier, value).into()))
    }
}

/// The share type for points in G2
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct InnerPointShareG2(
    pub DefaultShare<IdentifierPrimeField<Scalar>, ValueGroup<G2Projective>>,
);

impl DefaultIsZeroes for InnerPointShareG2 {}

impl subtle::ConditionallySelectable for InnerPointShareG2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let identifier1 = a.0.identifier.0;
        let identifier2 = b.0.identifier.0;
        let value1 = b.0.value.to_affine();
        let value2 = b.0.value.to_affine();
        let identifier = Scalar::conditional_select(&identifier1, &identifier2, choice);
        let value = G2Affine::conditional_select(&value1, &value2, choice);
        Self((identifier, G2Projective::from(value)).into())
    }
}

impl_from_derivatives!(InnerPointShareG2);

impl TryFrom<&[u8]> for InnerPointShareG2 {
    type Error = BlsError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        if input.len() != Scalar::BYTES + G2Projective::COMPRESSED_BYTES {
            return Err(BlsError::DeserializationError(
                "Invalid length for InnerPointShareG2".to_string(),
            ));
        }
        let identifier_bytes: [u8; Scalar::BYTES] =
            (&input[0..Scalar::BYTES]).try_into().map_err(|_| {
                BlsError::DeserializationError("Invalid length for Identifier".to_string())
            })?;
        let identifier = Option::<Scalar>::from(Scalar::from_be_bytes(&identifier_bytes))
            .ok_or_else(|| {
                BlsError::DeserializationError(
                    "Invalid Identifier, cannot convert to scalar".to_string(),
                )
            })?;
        let value_bytes: [u8; G2Projective::COMPRESSED_BYTES] = (&input[Scalar::BYTES..])
            .try_into()
            .map_err(|_| BlsError::DeserializationError("Invalid length for Value".to_string()))?;
        let value = Option::<G2Projective>::from(G2Projective::from_compressed(&value_bytes))
            .ok_or_else(|| {
                BlsError::DeserializationError(
                    "Invalid Value, cannot convert to G2Projective".to_string(),
                )
            })?;
        Ok(Self((identifier, value).into()))
    }
}

impl From<&InnerPointShareG2> for Vec<u8> {
    fn from(value: &InnerPointShareG2) -> Self {
        let mut output = vec![0u8; Scalar::BYTES + G2Projective::COMPRESSED_BYTES];
        output[..Scalar::BYTES].copy_from_slice(&value.0.identifier.0.to_be_bytes());
        output[Scalar::BYTES..].copy_from_slice(&value.0.value.0.to_compressed());
        output
    }
}

impl LowerHex for InnerPointShareG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &Vec::from(self) {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for InnerPointShareG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for &b in &Vec::from(self) {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl Display for InnerPointShareG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ identifier: {}, value: {} }}",
            self.0.identifier, self.0.value
        )
    }
}

impl Share for InnerPointShareG2 {
    type Identifier = IdentifierPrimeField<Scalar>;
    type Value = ValueGroup<G2Projective>;

    fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
        Self(DefaultShare { identifier, value })
    }

    fn identifier(&self) -> &Self::Identifier {
        &self.0.identifier
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0.identifier
    }

    fn value(&self) -> &Self::Value {
        &self.0.value
    }

    fn value_mut(&mut self) -> &mut Self::Value {
        &mut self.0.value
    }
}

impl InnerPointShareG2 {
    /// Convert secret share from InnerPointShareG1 v1 to the newer v2 format
    pub fn from_v1_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        #[derive(Deserialize)]
        struct V1(#[serde(deserialize_with = "fixed_arr::BigArray::deserialize")] [u8; 97]);
        let v1 = serde_bare::from_slice::<V1>(bytes)
            .map_err(|e| BlsError::InvalidInputs(e.to_string()))?;
        let identifier = Scalar::from(v1.0[0] as u64);
        let mut repr = [0u8; 96];
        repr.copy_from_slice(&v1.0[1..]);
        let value = Option::from(G2Projective::from_compressed(&repr)).ok_or_else(|| {
            BlsError::InvalidInputs("Invalid compressed G1Projective".to_string())
        })?;
        Ok(Self((identifier, value).into()))
    }
}
