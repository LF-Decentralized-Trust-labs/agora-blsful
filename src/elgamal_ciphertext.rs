use crate::*;
use core::ops::{Add, AddAssign};

/// An ElGamal ciphertext
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext<C: BlsSignatureImpl> {
    /// The first component of the ciphertext
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub c1: <C as Pairing>::PublicKey,
    /// The second component of the ciphertext
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub c2: <C as Pairing>::PublicKey,
}

impl<C: BlsSignatureImpl> Display for ElGamalCiphertext<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{{c1: {}, c2: {}}}", self.c1, self.c2)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for ElGamalCiphertext<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "ElGamalCiphertext{{c1: {:?}, c2: {:?}}}",
            self.c1, self.c2
        )
    }
}

impl<C: BlsSignatureImpl> Copy for ElGamalCiphertext<C> {}

impl<C: BlsSignatureImpl> Clone for ElGamalCiphertext<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for ElGamalCiphertext<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c1: <C as Pairing>::PublicKey::conditional_select(&a.c1, &b.c1, choice),
            c2: <C as Pairing>::PublicKey::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl<'b, C: BlsSignatureImpl> Add<&'b ElGamalCiphertext<C>> for &ElGamalCiphertext<C> {
    type Output = ElGamalCiphertext<C>;

    fn add(self, rhs: &'b ElGamalCiphertext<C>) -> Self::Output {
        *self + *rhs
    }
}

impl<'a, C: BlsSignatureImpl> Add<&'a ElGamalCiphertext<C>> for ElGamalCiphertext<C> {
    type Output = Self;

    fn add(self, rhs: &'a ElGamalCiphertext<C>) -> Self::Output {
        self + *rhs
    }
}

impl<C: BlsSignatureImpl> Add<ElGamalCiphertext<C>> for &ElGamalCiphertext<C> {
    type Output = ElGamalCiphertext<C>;

    fn add(self, rhs: ElGamalCiphertext<C>) -> Self::Output {
        *self + rhs
    }
}

impl<C: BlsSignatureImpl> Add<ElGamalCiphertext<C>> for ElGamalCiphertext<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl<C: BlsSignatureImpl> AddAssign<ElGamalCiphertext<C>> for ElGamalCiphertext<C> {
    fn add_assign(&mut self, rhs: ElGamalCiphertext<C>) {
        self.c1 += rhs.c1;
        self.c2 += rhs.c2;
    }
}

impl<'a, C: BlsSignatureImpl> AddAssign<&'a ElGamalCiphertext<C>> for ElGamalCiphertext<C> {
    fn add_assign(&mut self, rhs: &'a ElGamalCiphertext<C>) {
        self.c1 += rhs.c1;
        self.c2 += rhs.c2;
    }
}

impl<C: BlsSignatureImpl> From<&ElGamalCiphertext<C>> for Vec<u8> {
    fn from(value: &ElGamalCiphertext<C>) -> Self {
        serde_bare::to_vec(value).expect("failed to serialize ElGamalCiphertext")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ElGamalCiphertext<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let ciphertext = serde_bare::from_slice(value)?;
        Ok(ciphertext)
    }
}

impl_from_derivatives_generic!(ElGamalCiphertext);

impl<C: BlsSignatureImpl> ElGamalCiphertext<C> {
    /// Decrypt this ciphertext
    pub fn decrypt(&self, sk: &SecretKey<C>) -> <C as Pairing>::PublicKey {
        <C as BlsElGamal>::decrypt(sk.0, self.c1, self.c2)
    }
}
