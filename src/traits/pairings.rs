use crate::impls::inner_types::*;
use core::fmt::Display;
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConditionallySelectable;
use vsss_rs::*;

/// Operations that support pairing trait
pub trait Pairing {
    /// The secret key share
    type SecretKeyShare: Share<
            Identifier = IdentifierPrimeField<<Self::PublicKey as Group>::Scalar>,
            Value = ValuePrimeField<<Self::PublicKey as Group>::Scalar>,
        > + core::fmt::Debug
        + DeserializeOwned
        + Default;
    /// The public key group
    type PublicKey: Group + GroupEncoding + Default + Display + ConditionallySelectable;
    /// The public key share
    type PublicKeyShare: Share<
            Identifier = IdentifierPrimeField<<Self::PublicKey as Group>::Scalar>,
            Value = ValueGroup<Self::PublicKey>,
        > + Copy
        + Display
        + core::fmt::Debug
        + ConditionallySelectable
        + Serialize
        + DeserializeOwned
        + Default;
    /// The signature group
    type Signature: Group<Scalar = <Self::PublicKey as Group>::Scalar>
        + GroupEncoding
        + Default
        + Display
        + ConditionallySelectable;
    /// The signature share
    type SignatureShare: Share<
            Identifier = IdentifierPrimeField<<Self::Signature as Group>::Scalar>,
            Value = ValueGroup<Self::Signature>,
        > + Copy
        + Display
        + core::fmt::Debug
        + ConditionallySelectable
        + Serialize
        + DeserializeOwned
        + Default;
    /// The target group from a pairing computation
    type PairingResult: Group + GroupEncoding + Default + Display + ConditionallySelectable;
    /// Compute the pairing based on supplied points
    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult;
}
