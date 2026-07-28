use crate::impls::inner_types::*;
use crate::{
    Bls12381, BlsSignatureBasic, BlsSignatureImpl, BlsSignatureMessageAugmentation,
    BlsSignaturePop, Pairing, SignatureSchemes,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shake::{ExtendableOutput, Shake128, Update, XofReader};
use subtle::{Choice, CtOption};

pub const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

pub fn scalar_from_hkdf_bytes(salt: Option<&[u8]>, ikm: &[u8]) -> Scalar {
    const INFO: [u8; 2] = [0u8, 48u8];

    let mut counter = 0u32;
    let mut output = [0u8; 48];
    loop {
        let mut extractor = hkdf::HkdfExtract::<sha2::Sha256>::new(salt);
        extractor.input_ikm(ikm);
        extractor.input_ikm(&[0u8]);
        if counter != 0 {
            extractor.input_ikm(&counter.to_be_bytes());
        }
        let (_, h) = extractor.finalize();
        if h.expand(&INFO, &mut output).is_err() {
            return Scalar::ZERO;
        }
        let scalar = Scalar::from_okm(&output);
        if scalar != Scalar::ZERO {
            return scalar;
        }
        let Some(next) = counter.checked_add(1) else {
            return Scalar::ZERO;
        };
        counter = next;
    }
}

pub fn shake128_xor(seed: &[u8], input: &[u8]) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut output = vec![0u8; input.len()];
    reader.read(&mut output);
    debug_assert!(!output.iter().all(|x| *x == 0));
    for (output, input) in output.iter_mut().zip(input.iter()) {
        *output ^= input;
    }
    output
}

pub fn encode_message_with_len(message: &[u8], min_len: usize) -> Vec<u8> {
    let overhead = uint_zigzag::Uint::from(message.len());
    let mut encoded = overhead.to_vec();
    encoded.extend_from_slice(message);
    encoded.resize(encoded.len().max(min_len), 0u8);
    encoded
}

pub fn decode_message_with_len(encoded: &[u8]) -> Option<Vec<u8>> {
    let overhead = uint_zigzag::Uint::peek(encoded)?;
    let prefix = encoded.get(..overhead)?;
    let len = uint_zigzag::Uint::try_from(prefix).ok()?.0 as usize;
    let end = overhead.checked_add(len)?;
    encoded.get(overhead..end).map(<[u8]>::to_vec)
}

pub fn typed_bytes(t: Bls12381, value: impl AsRef<[u8]>) -> Vec<u8> {
    let value = value.as_ref();
    let mut output = Vec::with_capacity(value.len() + 1);
    output.push(u8::from(t));
    output.extend_from_slice(value);
    output
}

pub fn get_crypto_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_rng(&mut rand::rng())
}

pub fn signature_dst<C: BlsSignatureImpl>(scheme: SignatureSchemes) -> &'static [u8] {
    match scheme {
        SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
        SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
        SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
    }
}

/// Compute the pairing of `(G1, G2)` point pairs where the first element of
/// each pair lives in G1 and the second in G2.
fn pairing_prepared<'a>(pairs: impl Iterator<Item = (&'a G1Projective, &'a G2Projective)>) -> Gt {
    let t = pairs
        .map(|(g1, g2)| (g1.to_affine(), G2Prepared::from(g2.to_affine())))
        .collect::<Vec<_>>();
    let ref_t = t.iter().map(|(p1, p2)| (p1, p2)).collect::<Vec<_>>();
    multi_miller_loop(ref_t.as_slice()).final_exponentiation()
}

pub fn pairing_g1_g2(points: &[(G1Projective, G2Projective)]) -> Gt {
    pairing_prepared(points.iter().map(|(g1, g2)| (g1, g2)))
}

pub fn pairing_g2_g1(points: &[(G2Projective, G1Projective)]) -> Gt {
    pairing_prepared(points.iter().map(|(g2, g1)| (g1, g2)))
}

fn scalar_to_bytes<C: BlsSignatureImpl, const N: usize>(
    s: <<C as Pairing>::PublicKey as Group>::Scalar,
    big_endian: bool,
) -> [u8; N] {
    let mut bytes = s.to_repr();
    let ptr = bytes.as_mut();
    if big_endian {
        ptr.reverse();
    }
    let mut output = [0u8; N];
    output
        .iter_mut()
        .zip(ptr.iter())
        .for_each(|(output, input)| *output = *input);
    output
}

pub fn scalar_to_be_bytes<C: BlsSignatureImpl, const N: usize>(
    s: <<C as Pairing>::PublicKey as Group>::Scalar,
) -> [u8; N] {
    scalar_to_bytes::<C, N>(s, true)
}

pub fn scalar_to_le_bytes<C: BlsSignatureImpl, const N: usize>(
    s: <<C as Pairing>::PublicKey as Group>::Scalar,
) -> [u8; N] {
    scalar_to_bytes::<C, N>(s, false)
}

fn scalar_from_bytes<C: BlsSignatureImpl, const N: usize>(
    input: &[u8; N],
    big_endian: bool,
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
    if big_endian {
        t.reverse();
    }
    <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr)
}

pub fn scalar_from_be_bytes<C: BlsSignatureImpl, const N: usize>(
    input: &[u8; N],
) -> CtOption<<<C as Pairing>::PublicKey as Group>::Scalar> {
    scalar_from_bytes::<C, N>(input, true)
}

pub fn scalar_from_le_bytes<C: BlsSignatureImpl, const N: usize>(
    input: &[u8; N],
) -> CtOption<<<C as Pairing>::PublicKey as Group>::Scalar> {
    scalar_from_bytes::<C, N>(input, false)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_length_decoding_rejects_truncated_inputs() {
        for byte in 0..=u8::MAX {
            let _ = decode_message_with_len(&[byte]);
        }

        let encoded = encode_message_with_len(b"message", 0);
        for end in 0..encoded.len() {
            assert!(decode_message_with_len(&encoded[..end]).is_none());
        }
        assert_eq!(decode_message_with_len(&encoded), Some(b"message".to_vec()));
    }
}
