use crate::impls::inner_types::*;
use core::fmt::Display;

/// The hash to scalar methods
pub trait HashToScalar {
    /// The output scalar field.
    type Output: PrimeField + Display;

    /// Compute the output from a hash method
    fn hash_to_scalar<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output;
}
