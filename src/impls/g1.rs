use crate::impls::inner_types::*;
use crate::*;
use serde::{Deserialize, Serialize};
use vsss_rs::*;

/// Represents BLS signatures on the BLS12-381 curve where
/// Signatures are in G1 and Public Keys are in G2 or
/// i.e. signatures are small and public keys are large
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct Bls12381G1Impl;

impl HashToPoint for Bls12381G1Impl {
    type Output = G1Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2_010::Sha256>>(m.as_ref(), dst.as_ref())
    }
}

impl HashToScalar for Bls12381G1Impl {
    type Output = Scalar;

    fn hash_to_scalar<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        scalar_from_hkdf_bytes(Some(dst.as_ref()), m.as_ref())
    }
}

impl Pairing for Bls12381G1Impl {
    type SecretKeyShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
    type PublicKey = G2Projective;
    type PublicKeyShare = InnerPointShareG2;
    type Signature = G1Projective;
    type SignatureShare = InnerPointShareG1;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        pairing_g1_g2(points)
    }
}

impl_bls_serde!(Bls12381G1Impl);

impl BlsSignatureCore for Bls12381G1Impl {}

impl BlsSignatureBasic for Bls12381G1Impl {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
}

impl BlsSignatureMessageAugmentation for Bls12381G1Impl {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
}

impl BlsSignaturePop for Bls12381G1Impl {
    const SIG_DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
}

impl BlsSignatureProof for Bls12381G1Impl {}

impl BlsSignCrypt for Bls12381G1Impl {}

impl BlsTimeCrypt for Bls12381G1Impl {}

impl BlsElGamal for Bls12381G1Impl {
    const ENC_DST: &'static [u8] = b"BLS_ELGAMAL_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    type PublicKeyHasher = Bls12381G1Hasher;

    fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> <Self::PublicKey as Group>::Scalar {
        Scalar::from_bytes_wide(bytes)
    }
}

impl BlsMultiKey for Bls12381G1Impl {}

impl BlsMultiSignature for Bls12381G1Impl {}

impl BlsSignatureImpl for Bls12381G1Impl {}

/// The BLS12381 G1 hash to public key group
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Bls12381G1Hasher;

impl HashToPoint for Bls12381G1Hasher {
    type Output = G2Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2_010::Sha256>>(m.as_ref(), dst.as_ref())
    }
}
