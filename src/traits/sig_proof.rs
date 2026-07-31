use crate::impls::inner_types::*;
use crate::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SALT: &[u8] = b"BLS_POK__BLS12381_XOF:HKDF-SHA2-256_";

/// Named components of a timestamped signature proof.
///
/// This replaces the three-value `(U, V, timestamp)` return tuple used before
/// version 4.
pub struct TimestampProofParts<S> {
    /// The proof commitment.
    pub u: S,
    /// The proof response.
    pub v: S,
    /// The proof-generation timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,
}

/// Methods for creating a signature proof of knowledge as in
/// <https://miracl.com/assets/pdf-downloads/mpin4.pdf>
pub trait BlsSignatureProof:
    Pairing
    + HashToPoint<Output = Self::Signature>
    + HashToScalar<Output = <Self::Signature as Group>::Scalar>
{
    /// Create the values `U` and `x`.
    fn generate_commitment<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        msg: B,
        dst: D,
    ) -> BlsResult<(Self::Signature, <Self::Signature as Group>::Scalar)> {
        let mut rng = get_crypto_rng();
        let mut x = <Self::Signature as Group>::Scalar::random(&mut rng);
        // This should happen only with negligible probability, but retry just in case.
        while x.is_zero().into() {
            x = <Self::Signature as Group>::Scalar::random(&mut rng);
        }
        let a = Self::hash_to_point(msg, dst);
        Ok((a * x, x))
    }

    /// Create the timestamp-based challenge for `y`.
    fn generate_timestamp_based_y(
        u: Self::Signature,
    ) -> BlsResult<(<Self::Signature as Group>::Scalar, u64)> {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BlsError::InvalidInputs(e.to_string()))?
            .as_millis() as u64;
        Ok((Self::compute_y(u, t), t))
    }

    /// Generate the shared `y` challenge.
    fn compute_y(u: Self::Signature, t: u64) -> <Self::Signature as Group>::Scalar {
        let u_bytes = u.to_bytes();
        let u_ref = u_bytes.as_ref();
        let u_len = u_ref.len();
        let mut bytes = vec![0u8; 8 + u_len];
        bytes[..u_len].copy_from_slice(u_ref);
        bytes[u_len..].copy_from_slice(&t.to_le_bytes());
        Self::hash_to_scalar(&bytes, SALT)
    }

    /// Create the value `V`.
    fn generate_proof(
        commitment: Self::Signature,
        x: <Self::Signature as Group>::Scalar,
        y: <Self::Signature as Group>::Scalar,
        sig: Self::Signature,
    ) -> BlsResult<(Self::Signature, Self::Signature)> {
        if commitment.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "commitment is the identity point".to_string(),
            ));
        }
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        if x.is_zero().into() {
            return Err(BlsError::InvalidInputs("x is zero".to_string()));
        }
        if y.is_zero().into() {
            return Err(BlsError::InvalidInputs("y is zero".to_string()));
        }
        Ok((commitment, -(sig * (x + y))))
    }

    /// Create the value `V` using a timestamp.
    ///
    /// Returns the `U`, `V`, and timestamp components as [`TimestampProofParts`].
    fn generate_timestamp_proof<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        msg: B,
        dst: D,
        sig: Self::Signature,
    ) -> BlsResult<TimestampProofParts<Self::Signature>> {
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        let mut rng = get_crypto_rng();
        let mut x = <Self::Signature as Group>::Scalar::random(&mut rng);
        // This should happen only with negligible probability, but retry just in case.
        while x.is_zero().into() {
            x = <Self::Signature as Group>::Scalar::random(&mut rng);
        }
        let a = Self::hash_to_point(msg, dst);
        debug_assert_eq!(a.is_identity().unwrap_u8(), 0u8);
        let u = a * x;
        debug_assert_eq!(u.is_identity().unwrap_u8(), 0u8);
        let (y, t) = Self::generate_timestamp_based_y(u)?;
        debug_assert_eq!(y.is_zero().unwrap_u8(), 0u8);
        let v = sig * (x + y);
        debug_assert_eq!(v.is_identity().unwrap_u8(), 0u8);
        Ok(TimestampProofParts {
            u,
            v: -v,
            timestamp: t,
        })
    }

    /// Verify the signature proof of knowledge.
    fn verify<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        commitment: Self::Signature,
        proof: Self::Signature,
        pk: Self::PublicKey,
        y: <Self::Signature as Group>::Scalar,
        msg: B,
        dst: D,
    ) -> BlsResult<()> {
        if commitment.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "commitment is the identity point".to_string(),
            ));
        }
        if proof.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "proof is the identity point".to_string(),
            ));
        }
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }
        if y.is_zero().into() {
            return Err(BlsError::InvalidInputs("y is zero".to_string()));
        }

        let a = Self::hash_to_point(msg, dst);
        debug_assert_eq!(a.is_identity().unwrap_u8(), 0u8);
        if Self::pairing(&[
            (proof, <Self::PublicKey as Group>::generator()),
            (commitment + a * y, pk),
        ])
        .is_identity()
        .into()
        {
            Ok(())
        } else {
            Err(BlsError::InvalidProof)
        }
    }

    /// Verify a timestamp-based proof of knowledge.
    fn verify_timestamp_proof<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        commitment: Self::Signature,
        proof: Self::Signature,
        pk: Self::PublicKey,
        t: u64,
        timeout_ms: Option<u64>,
        msg: B,
        dst: D,
    ) -> BlsResult<()> {
        if let Some(tt) = timeout_ms {
            let now = SystemTime::now();
            let since = UNIX_EPOCH + Duration::from_millis(t);
            let elapsed = now
                .duration_since(since)
                .map_err(|_| BlsError::InvalidProof)?
                .as_millis() as u64;
            if elapsed > tt {
                return Err(BlsError::InvalidProof);
            }
        }

        let y = Self::compute_y(commitment, t);
        debug_assert_eq!(y.is_zero().unwrap_u8(), 0u8);
        Self::verify(commitment, proof, pk, y, msg, dst)
    }
}
