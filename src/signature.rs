use crate::*;

/// A BLS signature for either supported BLS12-381 signature group.
///
/// This is the dynamic counterpart to [`Signature<C>`]. Use it with
/// [`PublicKeyEnum`] when the G1/G2 choice is only known at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureEnum {
    /// A signature in G1 with public keys in G2.
    G1(Signature<Bls12381G1Impl>),
    /// A signature in G2 with public keys in G1.
    G2(Signature<Bls12381G2Impl>),
}

impl Default for SignatureEnum {
    fn default() -> Self {
        Self::G1(Signature::default())
    }
}

impl From<&SignatureEnum> for Vec<u8> {
    fn from(value: &SignatureEnum) -> Self {
        let (t, output) = match value {
            SignatureEnum::G1(sig) => (Bls12381::G1, Vec::from(sig)),
            SignatureEnum::G2(sig) => (Bls12381::G2, Vec::from(sig)),
        };
        typed_bytes(t, output)
    }
}

impl TryFrom<&[u8]> for SignatureEnum {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (t, value) = Bls12381::split_typed_bytes(value)?;
        match t {
            Bls12381::G1 => Signature::<Bls12381G1Impl>::try_from(value).map(SignatureEnum::G1),
            Bls12381::G2 => Signature::<Bls12381G2Impl>::try_from(value).map(SignatureEnum::G2),
        }
    }
}

impl_from_derivatives!(SignatureEnum);

impl SignatureEnum {
    /// Return the concrete BLS12-381 signature group for this signature.
    pub fn curve(&self) -> Bls12381 {
        match self {
            Self::G1(_) => Bls12381::G1,
            Self::G2(_) => Bls12381::G2,
        }
    }

    /// Verify the signature using a public key from the same curve variant.
    pub fn verify<B: AsRef<[u8]>>(&self, pk: &PublicKeyEnum, msg: B) -> BlsResult<()> {
        match (self, pk) {
            (Self::G1(sig), PublicKeyEnum::G1(pk)) => sig.verify(pk, msg),
            (Self::G2(sig), PublicKeyEnum::G2(pk)) => sig.verify(pk, msg),
            _ => Err(BlsError::InvalidInputs(
                "signature and public key curve variants differ".to_string(),
            )),
        }
    }

    /// Determine if two signatures use the same signature scheme and curve variant.
    pub fn same_scheme(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::G1(a), Self::G1(b)) => a.same_scheme(b),
            (Self::G2(a), Self::G2(b)) => a.same_scheme(b),
            _ => false,
        }
    }
}

/// A BLS signature wrapped in the appropriate scheme used to generate it
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Signature<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession scheme
    ProofOfPossession(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<C: BlsSignatureImpl> Default for Signature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl_signature_enum_traits!(
    Signature,
    <C as Pairing>::Signature,
    "Signature::conditional_select: mismatched variants"
);

impl_from_derivatives_generic!(Signature);

impl<C: BlsSignatureImpl> From<&Signature<C>> for Vec<u8> {
    fn from(value: &Signature<C>) -> Self {
        serde_bare::to_vec(value).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for Signature<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_bare::from_slice(value).map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> Signature<C> {
    /// Verify the signature using the public key
    pub fn verify<B: AsRef<[u8]>>(&self, pk: &PublicKey<C>, msg: B) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::verify(pk.0, *sig, msg),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, *sig, msg)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::verify(pk.0, *sig, msg),
        }
    }

    /// Determine if two signature were signed using the same scheme
    pub fn same_scheme(&self, &other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Basic(_), Self::Basic(_))
                | (Self::MessageAugmentation(_), Self::MessageAugmentation(_))
                | (Self::ProofOfPossession(_), Self::ProofOfPossession(_))
        )
    }

    /// Create a signature from shares
    pub fn from_shares(shares: &[SignatureShare<C>]) -> BlsResult<Self> {
        if !shares.iter().skip(1).all(|s| s.same_scheme(&shares[0])) {
            return Err(BlsError::InvalidSignatureScheme);
        }
        let points = shares
            .iter()
            .map(|s| *s.as_raw_value())
            .collect::<Vec<<C as Pairing>::SignatureShare>>();
        let sig = <C as BlsSignatureCore>::core_combine_signature_shares(&points)?;
        match shares[0] {
            SignatureShare::Basic(_) => Ok(Self::Basic(sig)),
            SignatureShare::MessageAugmentation(_) => Ok(Self::MessageAugmentation(sig)),
            SignatureShare::ProofOfPossession(_) => Ok(Self::ProofOfPossession(sig)),
        }
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::Signature {
        match self {
            Self::Basic(s) => s,
            Self::MessageAugmentation(s) => s,
            Self::ProofOfPossession(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::g1(Bls12381G1Impl, 49)]
    #[case::g2(Bls12381G2Impl, 97)]
    fn try_from<C: BlsSignatureImpl + PartialEq + Eq + fmt::Debug>(
        #[case] _c: C,
        #[case] expected_len: usize,
    ) {
        const TEST_MSG: &[u8] = b"test_try_from";

        let sk = SecretKey::<C>::from_hash(TEST_MSG);
        let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
        let sig_ma = sk
            .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
            .unwrap();
        let sig_pop = sk
            .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
            .unwrap();

        let test: Vec<u8> = sig_b.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_b2 = Signature::<C>::try_from(test);
        assert!(res_sig_b2.is_ok());
        assert_eq!(sig_b, res_sig_b2.unwrap());

        let test: Vec<u8> = sig_ma.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_ma2 = Signature::<C>::try_from(test);
        assert!(res_sig_ma2.is_ok());
        assert_eq!(sig_ma, res_sig_ma2.unwrap());

        let test: Vec<u8> = sig_pop.into();
        assert_eq!(test.len(), expected_len);
        let res_sig_pop2 = Signature::<C>::try_from(test);
        assert!(res_sig_pop2.is_ok());
        assert_eq!(sig_pop, res_sig_pop2.unwrap());
    }
}
