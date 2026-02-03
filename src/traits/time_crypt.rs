use crate::helpers::*;
use crate::impls::inner_types::*;
use crate::traits::{HashToPoint, HashToScalar, Pairing};
use crate::*;
use rand::Rng;
use sha2::Sha256;
use sha3::{
    Shake128,
    digest::{Digest, ExtendableOutput, FixedOutput, Update, XofReader},
};
use subtle::CtOption;

const SALT: &[u8] = b"TIMELOCK_BLS12381_XOF:HKDF-SHA2-256_";

/// Implement time lock encryption
pub trait BlsTimeCrypt:
    Pairing
    + HashToPoint<Output = Self::Signature>
    + HashToScalar<Output = <Self::Signature as Group>::Scalar>
{
    /// Create a new ciphertext
    fn seal(
        pk: Self::PublicKey,
        message: &[u8],
        id: &[u8],
        dst: &[u8],
    ) -> BlsResult<(Self::PublicKey, [u8; 32], Vec<u8>)> {
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }

        // \alpha ← Zq
        let alpha = Self::hash_to_scalar(get_crypto_rng().r#gen::<[u8; 32]>(), SALT);
        debug_assert_eq!(alpha.is_zero().unwrap_u8(), 0u8);
        let msg_dst = Sha256::digest(message);
        // r = HZq(\alpha  || M)
        let r_input: Vec<u8> = alpha
            .to_repr()
            .as_ref()
            .iter()
            .copied()
            .chain(msg_dst.as_slice().iter().copied())
            .collect();
        let r = Self::hash_to_scalar(r_input.as_slice(), SALT);
        debug_assert_eq!(r.is_zero().unwrap_u8(), 0u8);

        // K = e(A^r, HG2(ρ))
        let k_rhs = pk * r;
        debug_assert_eq!(k_rhs.is_identity().unwrap_u8(), 0u8);
        let k_lhs = Self::hash_to_point(id, dst);
        debug_assert_eq!(k_lhs.is_identity().unwrap_u8(), 0u8);
        let k = Self::pairing(&[(k_lhs, k_rhs)]);
        debug_assert_eq!(k.is_identity().unwrap_u8(), 0u8);

        // U = P^r
        let u = Self::PublicKey::generator() * r;
        debug_assert_eq!(u.is_identity().unwrap_u8(), 0u8);
        // V = Hℓ(K) ⊕ \alpha
        let v = Self::compute_v(k, alpha.to_repr().as_ref());
        // W = HℓX(\alpha) ⊕ M
        let overhead = uint_zigzag::Uint::from(message.len());
        let mut overhead_bytes = overhead.to_vec();
        overhead_bytes.extend_from_slice(message);
        while overhead_bytes.len() < 32 {
            overhead_bytes.push(0u8);
        }

        let w = Self::compute_w(alpha.to_repr().as_ref(), overhead_bytes.as_slice());

        Ok((u, v, w))
    }

    /// Open a ciphertext if the secret can verify the signature
    fn unseal(
        u: Self::PublicKey,
        v: &[u8; 32],
        w: &[u8],
        decryption_key: Self::Signature,
        is_valid: Choice,
    ) -> CtOption<Vec<u8>> {
        let valid_sk = !decryption_key.is_identity() & !u.is_identity();

        let k = Self::pairing(&[(decryption_key, u)]);
        let alpha = Self::compute_v(k, v);
        let plaintext = Self::compute_w(&alpha, w);

        let mut message = vec![];
        if let Some(overhead) = uint_zigzag::Uint::peek(plaintext.as_slice()) {
            // If peek succeeds then try_from will also, so unwrap is okay.
            // peek returns the amount actually used whereas try_from does not
            // thus both are used.
            let len = uint_zigzag::Uint::try_from(&plaintext[..overhead])
                .unwrap()
                .0 as usize;
            if len <= plaintext.len() - overhead {
                message = plaintext[overhead..overhead + len].to_vec();
            } else {
                return CtOption::new(w.to_vec(), 0u8.into());
            }
        }

        let msg_dst = Sha256::digest(&message);
        let r_input: Vec<u8> = alpha
            .iter()
            .copied()
            .chain(msg_dst.as_slice().iter().copied())
            .collect();
        let r = Self::hash_to_scalar(r_input.as_slice(), SALT);
        debug_assert_eq!(r.is_zero().unwrap_u8(), 0u8);
        CtOption::new(
            message,
            ((Self::PublicKey::generator() * r) - u).is_identity() & is_valid & valid_sk,
        )
    }

    /// Compute the `V` value
    fn compute_v(k_tick: Self::PairingResult, alpha_or_v: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::default();
        <Sha256 as Digest>::update(&mut hasher, k_tick.to_bytes().as_ref());
        // Hℓ(K)
        let output = hasher.finalize_fixed();
        // V = Hℓ(K') ⊕ \alpha
        let result = byte_xor(alpha_or_v, &output);
        <[u8; 32]>::try_from(result.as_slice()).unwrap()
    }

    /// Compute the `W` value
    fn compute_w(alpha: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut hasher = Shake128::default();
        hasher.update(alpha);
        // HℓX(\alpha)
        let mut reader = hasher.finalize_xof();

        let mut w = vec![0u8; msg.len()];
        reader.read(&mut w);
        debug_assert!(!w.iter().all(|x| *x == 0));
        // W = HℓX(\alpha) ⊕ M
        byte_xor(msg, &w)
    }
}
