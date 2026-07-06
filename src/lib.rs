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

impl_inner_point_share!(
    InnerPointShareG1,
    "for points in G1",
    G1Projective,
    G1Affine,
    [.identifier.0],
    [.value.0],
    49,
    48
);

impl_inner_point_share!(
    InnerPointShareG2,
    "for points in G2",
    G2Projective,
    G2Affine,
    [.identifier],
    [.value],
    97,
    96
);

impl DefaultIsZeroes for InnerPointShareG2 {}
