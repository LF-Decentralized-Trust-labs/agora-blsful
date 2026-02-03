use crate::impls::inner_types::*;
use crate::*;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use subtle::CtOption;

/// The commitment portion of the signature proof of knowledge
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofCommitment<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession signature scheme
    ProofOfPossession(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<C: BlsSignatureImpl> Default for ProofCommitment<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> Display for ProofCommitment<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for ProofCommitment<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for ProofCommitment<C> {}

impl<C: BlsSignatureImpl> Clone for ProofCommitment<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for ProofCommitment<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (Self::Basic(a), Self::Basic(b)) => {
                Self::Basic(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            (Self::MessageAugmentation(a), Self::MessageAugmentation(b)) => {
                Self::MessageAugmentation(<C as Pairing>::Signature::conditional_select(
                    a, b, choice,
                ))
            }
            (Self::ProofOfPossession(a), Self::ProofOfPossession(b)) => {
                Self::ProofOfPossession(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            _ => panic!("Cannot conditional select between different proof commitments"),
        }
    }
}

impl_from_derivatives_generic!(ProofCommitment);

impl<C: BlsSignatureImpl> From<&ProofCommitment<C>> for Vec<u8> {
    fn from(value: &ProofCommitment<C>) -> Self {
        serde_bare::to_vec(value).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofCommitment<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = C::Signature::default().to_bytes().as_ref().len() + 1;
        if value.len() != len {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }
        serde_bare::from_slice(value).map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> ProofCommitment<C> {
    /// Generate a new proof of knowledge commitment
    /// This is step 1 in the 3 step process
    pub fn generate<B: AsRef<[u8]>>(
        msg: B,
        signature: Signature<C>,
    ) -> BlsResult<(Self, ProofCommitmentSecret<C>)> {
        match signature {
            Signature::Basic(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignatureBasic>::DST,
                )?;
                Ok((Self::Basic(u), ProofCommitmentSecret(x)))
            }
            Signature::MessageAugmentation(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignatureMessageAugmentation>::DST,
                )?;
                Ok((Self::MessageAugmentation(u), ProofCommitmentSecret(x)))
            }
            Signature::ProofOfPossession(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignaturePop>::SIG_DST,
                )?;
                Ok((Self::ProofOfPossession(u), ProofCommitmentSecret(x)))
            }
        }
    }

    /// Finish the commitment value by converting it into a proof of knowledge
    /// Step 3 in the 3 step process
    pub fn finalize(
        self,
        x: ProofCommitmentSecret<C>,
        y: ProofCommitmentChallenge<C>,
        sig: Signature<C>,
    ) -> BlsResult<ProofOfKnowledge<C>> {
        match (self, sig) {
            (Self::Basic(u), Signature::Basic(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::Basic { u, v })
            }
            (Self::MessageAugmentation(u), Signature::MessageAugmentation(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::MessageAugmentation { u, v })
            }
            (Self::ProofOfPossession(u), Signature::ProofOfPossession(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::ProofOfPossession { u, v })
            }
            (_, _) => Err(BlsError::InvalidProof),
        }
    }
}

/// A commitment secret used to create the proof of knowledge
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofCommitmentSecret<C: BlsSignatureImpl>(
    /// The commitment secret raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl_from_derivatives_generic!(ProofCommitmentSecret);

impl<C: BlsSignatureImpl> From<&ProofCommitmentSecret<C>> for Vec<u8> {
    fn from(value: &ProofCommitmentSecret<C>) -> Self {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(value.0).to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofCommitmentSecret<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value)
            .map_err(|_| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))?;
        let value = scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(&bytes).map(Self);
        Option::from(value)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))
    }
}

impl<C: BlsSignatureImpl> ProofCommitmentSecret<C> {
    /// Get the big-endian byte representation of this key
    pub fn to_be_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Get the little-endian byte representation of this key
    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_le_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_be_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Convert a little-endian representation of the secret key.
    pub fn from_le_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_le_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }
}

/// The proof of knowledge challenge value generated by the server in
/// step 2 of the proof generation process
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofCommitmentChallenge<C: BlsSignatureImpl>(
    /// The commitment challenge raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl_from_derivatives_generic!(ProofCommitmentChallenge);

impl<C: BlsSignatureImpl> From<&ProofCommitmentChallenge<C>> for Vec<u8> {
    fn from(value: &ProofCommitmentChallenge<C>) -> Self {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(value.0).to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofCommitmentChallenge<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value)
            .map_err(|_| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))?;
        let value = scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(&bytes).map(Self);
        Option::from(value)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))
    }
}

impl<C: BlsSignatureImpl> ProofCommitmentChallenge<C> {
    /// Create a new random secret key
    pub fn new() -> Self {
        Self::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn from_hash<B: AsRef<[u8]>>(data: B) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a random challenge from a CS-PRNG
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            rng.r#gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Get the big-endian byte representation of this key
    pub fn to_be_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Get the little-endian byte representation of this key
    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_le_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_be_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Convert a little-endian representation of the secret key.
    pub fn from_le_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_le_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }
}
