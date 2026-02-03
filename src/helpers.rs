use crate::impls::inner_types::*;
use crate::{BlsSignatureImpl, Pairing};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use subtle::{Choice, CtOption};

pub const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

pub fn scalar_from_hkdf_bytes(salt: Option<&[u8]>, ikm: &[u8]) -> Scalar {
    const INFO: [u8; 2] = [0u8, 48u8];

    let mut extractor = hkdf::HkdfExtract::<sha2::Sha256>::new(salt);
    extractor.input_ikm(ikm);
    extractor.input_ikm(&[0u8]);
    let (_, h) = extractor.finalize();

    let mut output = [0u8; 48];
    let mut s = Scalar::ZERO;
    // Odds of this happening are extremely low but check anyway
    while s == Scalar::ZERO {
        // Unwrap allowed since 48 is a valid length
        h.expand(&INFO, &mut output).unwrap();
        s = Scalar::from_okm(&output);
    }
    s
}

pub fn byte_xor(arr1: &[u8], arr2: &[u8]) -> Vec<u8> {
    debug_assert_eq!(arr1.len(), arr2.len());
    let mut o = Vec::with_capacity(arr1.len());
    for (a, b) in arr1.iter().zip(arr2.iter()) {
        o.push(*a ^ *b)
    }
    o
}

pub fn get_crypto_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

pub fn pairing_g1_g2(points: &[(G1Projective, G2Projective)]) -> Gt {
    let t = points
        .iter()
        .map(|(p1, p2)| (p1.to_affine(), G2Prepared::from(p2.to_affine())))
        .collect::<Vec<(G1Affine, G2Prepared)>>();
    let ref_t = t
        .iter()
        .map(|(p1, p2)| (p1, p2))
        .collect::<Vec<(&G1Affine, &G2Prepared)>>();
    multi_miller_loop(ref_t.as_slice()).final_exponentiation()
}

pub fn pairing_g2_g1(points: &[(G2Projective, G1Projective)]) -> Gt {
    let t = points
        .iter()
        .map(|(p1, p2)| (p2.to_affine(), G2Prepared::from(p1.to_affine())))
        .collect::<Vec<(G1Affine, G2Prepared)>>();
    let ref_t = t
        .iter()
        .map(|(p1, p2)| (p1, p2))
        .collect::<Vec<(&G1Affine, &G2Prepared)>>();
    multi_miller_loop(ref_t.as_slice()).final_exponentiation()
}

pub fn scalar_to_be_bytes<C: BlsSignatureImpl, const N: usize>(
    s: <<C as Pairing>::PublicKey as Group>::Scalar,
) -> [u8; N] {
    let mut bytes = s.to_repr();
    let ptr = bytes.as_mut();
    // Make big endian
    ptr.reverse();
    <[u8; N]>::try_from(ptr).unwrap()
}

pub fn scalar_to_le_bytes<C: BlsSignatureImpl, const N: usize>(
    s: <<C as Pairing>::PublicKey as Group>::Scalar,
) -> [u8; N] {
    let mut bytes = s.to_repr();
    let ptr = bytes.as_mut();
    <[u8; N]>::try_from(ptr).unwrap()
}

pub fn scalar_from_be_bytes<C: BlsSignatureImpl, const N: usize>(
    input: &[u8; N],
) -> CtOption<<<C as Pairing>::PublicKey as Group>::Scalar> {
    if input.is_zero().into() {
        return CtOption::new(
            <<C as Pairing>::PublicKey as Group>::Scalar::ZERO,
            Choice::from(0u8),
        );
    }
    let mut repr = <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
    let t = repr.as_mut();
    t.copy_from_slice(input);
    t.reverse();
    <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr)
}

pub fn scalar_from_le_bytes<C: BlsSignatureImpl, const N: usize>(
    input: &[u8; N],
) -> CtOption<<<C as Pairing>::PublicKey as Group>::Scalar> {
    if input.is_zero().into() {
        return CtOption::new(
            <<C as Pairing>::PublicKey as Group>::Scalar::ZERO,
            Choice::from(0u8),
        );
    }
    let mut repr = <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
    let t = repr.as_mut();
    t.copy_from_slice(input);
    <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr)
}

pub mod fixed_arr {
    use core::fmt::{self, Formatter};
    use serde::{
        Deserialize, Deserializer,
        de::{self, SeqAccess, Visitor},
    };

    pub trait BigArray<'de>: Sized {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>;
    }

    impl<'de, const N: usize> BigArray<'de> for [u8; N] {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if d.is_human_readable() {
                let hex_str = <&str>::deserialize(d)?;
                let mut share = [0u8; N];
                hex::decode_to_slice(hex_str, &mut share).map_err(de::Error::custom)?;
                return Ok(share);
            }

            struct ArrayVisitor<const N: usize>;

            impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
                type Value = [u8; N];

                fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                    write!(formatter, "an array of length {}", N)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<[u8; N], A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut arr = [0u8; N];
                    for (i, b) in arr.iter_mut().enumerate() {
                        *b = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }

            d.deserialize_tuple(N, ArrayVisitor)
        }
    }
}

pub trait IsZero {
    fn is_zero(&self) -> Choice;
}

impl IsZero for [u8] {
    fn is_zero(&self) -> Choice {
        let mut t: i8 = 0;
        for b in self {
            t |= *b as i8;
        }

        Choice::from((((t | -t) >> 7) + 1) as u8)
    }
}
