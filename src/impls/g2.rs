use crate::impls::inner_types::*;
use crate::*;

/// Represents BLS signatures on the BLS12-381 curve where
/// Signatures are in G2 and Public Keys are in G1 or
/// i.e. signatures are large and public keys are small
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct Bls12381G2Impl;

impl HashToPoint for Bls12381G2Impl {
    type Output = G2Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2_010::Sha256>>(m.as_ref(), dst.as_ref())
    }
}

impl HashToScalar for Bls12381G2Impl {
    type Output = Scalar;

    fn hash_to_scalar<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        scalar_from_hkdf_bytes(Some(dst.as_ref()), m.as_ref())
    }
}

impl Pairing for Bls12381G2Impl {
    type SecretKeyShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
    type PublicKey = G1Projective;
    type PublicKeyShare = InnerPointShareG1;
    type Signature = G2Projective;
    type SignatureShare = InnerPointShareG2;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        pairing_g2_g1(points)
    }
}

impl BlsSerde for Bls12381G2Impl {
    fn serialize_scalar<S: Serializer>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error> {
        <Scalar as Serialize>::serialize(scalar, serializer)
    }

    fn serialize_scalar_share<S: Serializer>(
        share: &Self::SecretKeyShare,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        share.serialize(serializer)
    }

    fn serialize_signature<S: Serializer>(
        signature: &Self::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        signature.serialize(serializer)
    }

    fn serialize_public_key<S: Serializer>(
        public_key: &Self::PublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        public_key.serialize(serializer)
    }

    fn serialize_public_key_share<S: Serializer>(
        public_key_share: &Self::PublicKeyShare,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        public_key_share.serialize(serializer)
    }

    fn deserialize_scalar<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<<Self::PublicKey as Group>::Scalar, D::Error> {
        <Scalar as Deserialize<'de>>::deserialize(deserializer)
    }

    fn deserialize_scalar_share<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::SecretKeyShare, D::Error> {
        Self::SecretKeyShare::deserialize(deserializer)
    }

    fn deserialize_signature<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Signature, D::Error> {
        Self::Signature::deserialize(deserializer)
    }

    fn deserialize_public_key<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::PublicKey, D::Error> {
        Self::PublicKey::deserialize(deserializer)
    }

    fn deserialize_public_key_share<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::PublicKeyShare, D::Error> {
        Self::PublicKeyShare::deserialize(deserializer)
    }
}

impl BlsSignatureCore for Bls12381G2Impl {}

impl BlsSignatureBasic for Bls12381G2Impl {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
}

impl BlsSignatureMessageAugmentation for Bls12381G2Impl {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
}

impl BlsSignaturePop for Bls12381G2Impl {
    const SIG_DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
}

impl BlsSignatureProof for Bls12381G2Impl {}

impl BlsSignCrypt for Bls12381G2Impl {}

impl BlsTimeCrypt for Bls12381G2Impl {}

impl BlsElGamal for Bls12381G2Impl {
    const ENC_DST: &'static [u8] = b"BLS_ELGAMAL_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    type PublicKeyHasher = Bls12381G2Hasher;

    fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> <Self::PublicKey as Group>::Scalar {
        Scalar::from_bytes_wide(bytes)
    }
}

impl BlsMultiKey for Bls12381G2Impl {}

impl BlsMultiSignature for Bls12381G2Impl {}

impl BlsSignatureImpl for Bls12381G2Impl {}

/// The BLS12381 G1 hash to public key group
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Bls12381G2Hasher;

impl HashToPoint for Bls12381G2Hasher {
    type Output = G1Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2_010::Sha256>>(m.as_ref(), dst.as_ref())
    }
}
