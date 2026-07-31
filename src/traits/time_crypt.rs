use crate::helpers::*;
use crate::impls::inner_types::*;
use crate::traits::{HashToPoint, HashToScalar, Pairing};
use crate::*;
use rand::CryptoRng;
use rand::RngExt;
use sha2::{Digest, Sha256};
use subtle::CtOption;

const SALT: &[u8] = b"TIMELOCK_BLS12381_XOF:HKDF-SHA2-256_";

/// Named components produced when sealing a time-lock ciphertext.
///
/// This replaces the three-value `(U, V, W)` return tuple used before version 4.
pub struct TimeCryptCiphertextParts<P> {
    /// The ephemeral public-key component.
    pub u: P,
    /// The encrypted scalar component.
    pub v: [u8; 32],
    /// The encrypted message component.
    pub w: Vec<u8>,
}

/// Implements time-lock encryption.
pub trait BlsTimeCrypt:
    Pairing
    + HashToPoint<Output = Self::Signature>
    + HashToScalar<Output = <Self::Signature as Group>::Scalar>
{
    /// Create a new ciphertext.
    ///
    /// Returns the `U`, `V`, and `W` components as [`TimeCryptCiphertextParts`].
    fn seal(
        pk: Self::PublicKey,
        message: &[u8],
        id: &[u8],
        dst: &[u8],
    ) -> BlsResult<TimeCryptCiphertextParts<Self::PublicKey>> {
        Self::seal_with_rng(pk, message, id, dst, get_crypto_rng())
    }

    /// Create a new ciphertext using a caller-provided random number generator.
    ///
    /// Returns the `U`, `V`, and `W` components as [`TimeCryptCiphertextParts`].
    fn seal_with_rng(
        pk: Self::PublicKey,
        message: &[u8],
        id: &[u8],
        dst: &[u8],
        mut rng: impl CryptoRng,
    ) -> BlsResult<TimeCryptCiphertextParts<Self::PublicKey>> {
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }

        // \alpha ← Zq
        let alpha = Self::hash_to_scalar(rng.random::<[u8; 32]>(), SALT);
        debug_assert_eq!(alpha.is_zero().unwrap_u8(), 0u8);
        let msg_dst = Sha256::digest(message);
        // r = HZq(\alpha  || M)
        let alpha_bytes = alpha.to_repr();
        let mut r_input = Vec::with_capacity(alpha_bytes.as_ref().len() + msg_dst.len());
        r_input.extend_from_slice(alpha_bytes.as_ref());
        r_input.extend_from_slice(&msg_dst);
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
        let overhead_bytes = encode_message_with_len(message, 32);
        let w = Self::compute_w(alpha.to_repr().as_ref(), overhead_bytes.as_slice());

        Ok(TimeCryptCiphertextParts { u, v, w })
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

        let Some(message) = decode_message_with_len(&plaintext) else {
            return CtOption::new(w.to_vec(), 0u8.into());
        };

        let msg_dst = Sha256::digest(&message);
        let mut r_input = Vec::with_capacity(alpha.len() + msg_dst.len());
        r_input.extend_from_slice(&alpha);
        r_input.extend_from_slice(&msg_dst);
        let r = Self::hash_to_scalar(r_input.as_slice(), SALT);
        debug_assert_eq!(r.is_zero().unwrap_u8(), 0u8);
        CtOption::new(
            message,
            ((Self::PublicKey::generator() * r) - u).is_identity() & is_valid & valid_sk,
        )
    }

    /// Compute the `V` value
    fn compute_v(k_tick: Self::PairingResult, alpha_or_v: &[u8]) -> [u8; 32] {
        assert_eq!(alpha_or_v.len(), 32, "time-lock XOR input must be 32 bytes");
        // Hℓ(K)
        let output = Sha256::digest(k_tick.to_bytes().as_ref());
        // V = Hℓ(K') ⊕ \alpha
        let mut value = [0u8; 32];
        for (value, (alpha, hash)) in value.iter_mut().zip(alpha_or_v.iter().zip(output.iter())) {
            *value = alpha ^ hash;
        }
        value
    }

    /// Compute the `W` value
    fn compute_w(alpha: &[u8], msg: &[u8]) -> Vec<u8> {
        // W = HℓX(\alpha) ⊕ M
        shake128_xor(alpha, msg)
    }
}
