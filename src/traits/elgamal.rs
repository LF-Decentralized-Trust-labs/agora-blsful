use super::*;
use crate::impls::inner_types::*;
use crate::{BlsError, BlsResult};
use rand::CryptoRng;

const SALT: &[u8] = b"ELGAMAL_BLS12381_XOF:HKDF-SHA2-256_";

fn random_nonzero<F: Field>(rng: &mut impl CryptoRng) -> F {
    loop {
        let scalar = F::random(&mut *rng);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}

/// The ciphertext and response values produced by ElGamal proof generation.
pub struct ElGamalProofData<G: Group> {
    /// The first ciphertext component.
    pub c1: G,
    /// The second ciphertext component.
    pub c2: G,
    /// The message response.
    pub message_response: G::Scalar,
    /// The blinder response.
    pub blinder_response: G::Scalar,
    /// The Fiat-Shamir challenge.
    pub challenge: G::Scalar,
}

/// Methods for implementing ElGamal encryption and derived zero-knowledge proofs.
pub trait BlsElGamal: Pairing + HashToScalar<Output = <Self::PublicKey as Group>::Scalar> {
    /// The hash to public key group DST
    const ENC_DST: &'static [u8];
    /// A hasher that can hash to a public key
    type PublicKeyHasher: HashToPoint<Output = Self::PublicKey>;

    /// Create a scalar from 64 bytes
    fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> <Self::PublicKey as Group>::Scalar;

    /// Generate the message generator in a deterministic manner
    fn message_generator() -> Self::PublicKey {
        let g = Self::PublicKey::generator();
        Self::PublicKeyHasher::hash_to_point(g.to_bytes().as_ref(), Self::ENC_DST)
    }

    /// Encrypt a scalar
    fn seal_scalar(
        pk: Self::PublicKey,
        message: <Self::PublicKey as Group>::Scalar,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        mut rng: impl CryptoRng,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey)> {
        let generator = generator.unwrap_or_else(|| Self::message_generator());

        if (generator.is_identity() | pk.is_identity()).into() {
            return Err(BlsError::InvalidInputs(
                "generator or public key is the identity point".to_string(),
            ));
        }

        let blinder = blinder.unwrap_or_else(|| random_nonzero(&mut rng));
        debug_assert_eq!(blinder.is_zero().unwrap_u8(), 0u8);

        let ek = generator * message;
        debug_assert_eq!(ek.is_identity().unwrap_u8(), 0u8);
        let c1 = Self::PublicKey::generator() * blinder;
        debug_assert_eq!(c1.is_identity().unwrap_u8(), 0u8);
        let c2 = pk * blinder + ek;
        debug_assert_eq!(c2.is_identity().unwrap_u8(), 0u8);

        Ok((c1, c2))
    }

    /// Encrypt a point
    fn seal_point(
        pk: Self::PublicKey,
        message: Self::PublicKey,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        mut rng: impl CryptoRng,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey)> {
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }
        let blinder = blinder.unwrap_or_else(|| random_nonzero(&mut rng));
        debug_assert_eq!(blinder.is_zero().unwrap_u8(), 0u8);
        let c1 = Self::PublicKey::generator() * blinder;
        debug_assert_eq!(c1.is_identity().unwrap_u8(), 0u8);
        let c2 = pk * blinder + message;
        debug_assert_eq!(c2.is_identity().unwrap_u8(), 0u8);
        Ok((c1, c2))
    }

    /// Encrypt a scalar and generate a ZKP
    fn seal_scalar_with_proof(
        pk: Self::PublicKey,
        message: <Self::PublicKey as Group>::Scalar,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        mut rng: impl CryptoRng,
    ) -> BlsResult<ElGamalProofData<Self::PublicKey>> {
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }
        let generator = generator.unwrap_or_else(|| Self::message_generator());
        debug_assert_eq!(generator.is_identity().unwrap_u8(), 0u8);
        let b = blinder.unwrap_or_else(|| random_nonzero(&mut rng));
        debug_assert_eq!(b.is_zero().unwrap_u8(), 0u8);
        let r: <Self::PublicKey as Group>::Scalar = random_nonzero(&mut rng);
        debug_assert_eq!(r.is_zero().unwrap_u8(), 0u8);
        // c1 = P^b
        // c2 = H^m * P^ab
        let (c1, c2) = Self::seal_scalar(pk, message, Some(generator), Some(b), &mut rng)?;
        debug_assert_eq!(c1.is_identity().unwrap_u8(), 0u8);
        debug_assert_eq!(c2.is_identity().unwrap_u8(), 0u8);
        // r1 = P^r
        // r2 = H^b * P^ar
        let (r1, r2) = Self::seal_scalar(pk, b, Some(generator), Some(r), &mut rng)?;
        debug_assert_eq!(r1.is_identity().unwrap_u8(), 0u8);
        debug_assert_eq!(r2.is_identity().unwrap_u8(), 0u8);

        let mut transcript = merlin::Transcript::new(b"ElGamalProof");
        transcript.append_message(b"dst", SALT);
        transcript.append_message(
            b"base point",
            Self::PublicKey::generator().to_bytes().as_ref(),
        );
        transcript.append_message(b"pk", pk.to_bytes().as_ref());
        transcript.append_message(b"generator", generator.to_bytes().as_ref());
        transcript.append_message(b"c1", c1.to_bytes().as_ref());
        transcript.append_message(b"c2", c2.to_bytes().as_ref());
        transcript.append_message(b"r1", r1.to_bytes().as_ref());
        transcript.append_message(b"r2", r2.to_bytes().as_ref());
        let mut challenge = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge);
        let challenge = Self::scalar_from_bytes_wide(&challenge);
        debug_assert_eq!(challenge.is_zero().unwrap_u8(), 0u8);

        let message_proof = b + challenge * message;
        debug_assert_eq!(message_proof.is_zero().unwrap_u8(), 0u8);
        let blinder_proof = r + challenge * b;
        debug_assert_eq!(blinder_proof.is_zero().unwrap_u8(), 0u8);
        Ok(ElGamalProofData {
            c1,
            c2,
            message_response: message_proof,
            blinder_response: blinder_proof,
            challenge,
        })
    }

    /// Decrypt an ElGamal ciphertext and return the resulting point.
    ///
    /// If a scalar was encrypted, the value is in the exponent.
    /// If a point was encrypted, the actual value is the result.
    fn decrypt(
        sk: <Self::PublicKey as Group>::Scalar,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
    ) -> Self::PublicKey {
        c2 - c1 * sk
    }

    /// Verify an ElGamal proof and decrypt the resulting point if the proof is valid.
    fn verify_and_decrypt(
        sk: <Self::PublicKey as Group>::Scalar,
        generator: Option<Self::PublicKey>,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
        message_proof: <Self::PublicKey as Group>::Scalar,
        blinder_proof: <Self::PublicKey as Group>::Scalar,
        challenge: <Self::PublicKey as Group>::Scalar,
    ) -> BlsResult<Self::PublicKey> {
        if sk.is_zero().into() {
            return Err(BlsError::InvalidInputs("secret key is zero".to_string()));
        }
        let pk = Self::PublicKey::generator() * sk;
        Self::verify_proof(
            pk,
            generator,
            c1,
            c2,
            message_proof,
            blinder_proof,
            challenge,
        )?;
        Ok(Self::decrypt(sk, c1, c2))
    }

    /// Verify an ElGamal proof.
    fn verify_proof(
        pk: Self::PublicKey,
        generator: Option<Self::PublicKey>,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
        message_proof: <Self::PublicKey as Group>::Scalar,
        blinder_proof: <Self::PublicKey as Group>::Scalar,
        challenge: <Self::PublicKey as Group>::Scalar,
    ) -> BlsResult<()> {
        let generator = generator.unwrap_or_else(|| Self::message_generator());
        if (pk.is_identity() | generator.is_identity() | c1.is_identity() | c2.is_identity()).into()
        {
            return Err(BlsError::InvalidInputs(
                "parameters or ciphertext values are identity points".to_string(),
            ));
        }
        if (message_proof.is_zero() | blinder_proof.is_zero() | challenge.is_zero()).into() {
            return Err(BlsError::InvalidInputs("proof values are zero".to_string()));
        }

        let neg_challenge = -challenge;
        // r1 = P^-bc P^(r + b * c)
        let r1 = c1 * neg_challenge + Self::PublicKey::generator() * blinder_proof;
        // r1 = H^-mc P^-abc H^(b + m * c) P^a(r + b * c)
        let r2 = c2 * neg_challenge + generator * message_proof + pk * blinder_proof;

        let mut transcript = merlin::Transcript::new(b"ElGamalProof");
        transcript.append_message(b"dst", SALT);
        transcript.append_message(
            b"base point",
            Self::PublicKey::generator().to_bytes().as_ref(),
        );
        transcript.append_message(b"pk", pk.to_bytes().as_ref());
        transcript.append_message(b"generator", generator.to_bytes().as_ref());
        transcript.append_message(b"c1", c1.to_bytes().as_ref());
        transcript.append_message(b"c2", c2.to_bytes().as_ref());
        transcript.append_message(b"r1", r1.to_bytes().as_ref());
        transcript.append_message(b"r2", r2.to_bytes().as_ref());
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge_verifier = Self::scalar_from_bytes_wide(&challenge_bytes);

        if challenge != challenge_verifier {
            Err(BlsError::InvalidInputs(
                "challenge values do not match".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}
