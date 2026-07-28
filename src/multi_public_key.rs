use crate::impls::inner_types::*;
use crate::*;

/// An accumulated public key
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPublicKey<C: BlsSignatureImpl>(
    /// The inner raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> Display for MultiPublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for MultiPublicKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for MultiPublicKey<C> {}

impl<C: BlsSignatureImpl> Clone for MultiPublicKey<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for MultiPublicKey<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKey::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[PublicKey<C>]> for MultiPublicKey<C> {
    type Error = BlsError;

    fn try_from(keys: &[PublicKey<C>]) -> BlsResult<Self> {
        Self::from_public_keys(keys)
    }
}

impl_from_derivatives_generic!(MultiPublicKey);

impl<C: BlsSignatureImpl> From<&MultiPublicKey<C>> for Vec<u8> {
    fn from(pk: &MultiPublicKey<C>) -> Self {
        pk.0.to_bytes().as_ref().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for MultiPublicKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = C::PublicKey::default().to_bytes();
        let len = repr.as_ref().len();

        if len != value.len() {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }

        repr.as_mut().copy_from_slice(value);
        let key: Option<C::PublicKey> = C::PublicKey::from_bytes(&repr).into();
        key.map(Self)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid byte sequence".to_string()))
    }
}

impl<C: BlsSignatureImpl> MultiPublicKey<C> {
    /// Accumulate multiple public keys into a single public key
    pub fn from_public_keys<B: AsRef<[PublicKey<C>]>>(keys: B) -> BlsResult<Self> {
        let keys = keys.as_ref();
        if keys.len() < 2 {
            return Err(BlsError::InvalidInputs(
                "at least two public keys are required".to_string(),
            ));
        }
        Ok(Self(<C as BlsMultiKey>::from_public_keys(
            keys.iter().map(|k| k.0),
        )))
    }
}
