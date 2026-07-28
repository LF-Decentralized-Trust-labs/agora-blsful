use crate::impls::inner_types::*;
use crate::*;
use vsss_rs::*;

/// The core methods used by BLS signatures
pub trait BlsSignatureCore:
    Pairing
    + HashToPoint<Output = Self::Signature>
    + BlsSerde
    + BlsSignatureProof
    + BlsSignCrypt
    + BlsTimeCrypt
    + BlsElGamal
{
    /// Get the public key corresponding to the secret key
    fn public_key(sk: &<Self::PublicKey as Group>::Scalar) -> Self::PublicKey {
        <Self::PublicKey as Group>::generator() * sk
    }

    /// Get the public key share corresponding to the secret key share
    fn public_key_share(sks: &Self::SecretKeyShare) -> BlsResult<Self::PublicKeyShare> {
        Self::public_key_share_with_generator(sks, <Self::PublicKey as Group>::generator())
    }

    /// Get the public key share corresponding to the secret key share and a generator
    fn public_key_share_with_generator(
        sks: &Self::SecretKeyShare,
        generator: Self::PublicKey,
    ) -> BlsResult<Self::PublicKeyShare> {
        let sk = *sks.value();
        let pk: Self::PublicKey = generator * sk.0;
        let pk_share =
            Self::PublicKeyShare::with_identifier_and_value(*sks.identifier(), ValueGroup(pk));
        Ok(pk_share)
    }

    /// Aggregate signatures
    fn aggregate_signatures<S>(sigs: S) -> Self::Signature
    where
        S: Iterator<Item = Self::Signature>,
    {
        let mut r = <Self::Signature as Group>::identity();
        for s in sigs {
            r += s;
        }
        r
    }

    /// Aggregate public keys
    fn aggregate_public_keys<P>(pks: P) -> Self::PublicKey
    where
        P: Iterator<Item = Self::PublicKey>,
    {
        let mut r = <Self::PublicKey as Group>::identity();
        for p in pks {
            r += p;
        }
        r
    }

    /// Compute a signature share
    fn core_partial_sign<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        sks: &Self::SecretKeyShare,
        msg: B,
        dst: C,
    ) -> BlsResult<Self::SignatureShare> {
        let sk = *sks.value();
        let sig = <Self as BlsSignatureCore>::core_sign(&sk.0, msg, dst.as_ref())?;
        let sig_share =
            Self::SignatureShare::with_identifier_and_value(*sks.identifier(), ValueGroup(sig));
        Ok(sig_share)
    }

    /// Verify a signature share
    fn core_signature_share_verify<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        pks: Self::PublicKeyShare,
        sig: Self::SignatureShare,
        msg: B,
        dst: C,
    ) -> BlsResult<()> {
        if pks.identifier() != sig.identifier() {
            return Err(BlsError::InvalidInputs(
                "signature and public shares do not correspond".to_string(),
            ));
        }
        let pk = *pks.value();
        let sig = *sig.value();
        Self::core_verify(pk.0, sig.0, msg, dst)
    }

    /// Combine signature shares to form a signature
    fn core_combine_signature_shares(
        shares: &[Self::SignatureShare],
    ) -> BlsResult<Self::Signature> {
        let sig = shares.combine()?;
        Ok(sig.0)
    }

    /// Combine public key shares to form a public key
    fn core_combine_public_key_shares(
        shares: &[Self::PublicKeyShare],
    ) -> BlsResult<Self::PublicKey> {
        let pk = shares.combine()?;
        Ok(pk.0)
    }

    /// Compute a signature
    fn core_sign<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        sk: &<Self::PublicKey as Group>::Scalar,
        msg: B,
        dst: C,
    ) -> BlsResult<Self::Signature> {
        if sk.is_zero().into() {
            return Err(BlsError::SigningError("signing key is zero".to_string()));
        }
        Ok(Self::hash_to_point(msg, dst) * sk)
    }

    /// Verify a signature and message
    fn core_verify<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        pk: Self::PublicKey,
        sig: Self::Signature,
        msg: B,
        dst: C,
    ) -> BlsResult<()> {
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }
        let a = Self::hash_to_point::<B, C>(msg, dst);
        let generator = -Self::PublicKey::generator();
        if Self::pairing(&[(a, pk), (sig, generator)])
            .is_identity()
            .into()
        {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }

    /// Verify an aggregate signature and messages
    fn core_aggregate_verify<P, B, C>(pks: P, sig: Self::Signature, dst: C) -> BlsResult<()>
    where
        P: Iterator<Item = (Self::PublicKey, B)>,
        B: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        let mut pairs = Vec::with_capacity(pks.size_hint().0.saturating_add(1));
        for (i, (pk, msg)) in pks.enumerate() {
            if pk.is_identity().into() {
                return Err(BlsError::InvalidInputs(format!(
                    "public key at {} is the identity point",
                    i + 1
                )));
            }
            let a = Self::hash_to_point::<_, _>(msg.as_ref(), dst.as_ref());
            debug_assert_eq!(a.is_identity().unwrap_u8(), 0u8);
            pairs.push((a, pk));
        }
        pairs.push((sig, -<Self::PublicKey as Group>::generator()));
        if Self::pairing(pairs.as_slice()).is_identity().into() {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }
}
