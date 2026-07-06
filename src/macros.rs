macro_rules! impl_from_derivatives_generic {
    ($name:ident) => {
        impl<C: BlsSignatureImpl> From<$name<C>> for Vec<u8> {
            fn from(value: $name<C>) -> Self {
                Vec::from(&value)
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<Vec<u8>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<&Vec<u8>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<Box<[u8]>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }
    };
}

macro_rules! impl_from_derivatives {
    ($name:ident) => {
        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                Vec::from(&value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = BlsError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl TryFrom<&Vec<u8>> for $name {
            type Error = BlsError;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<Box<[u8]>> for $name {
            type Error = BlsError;

            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }
    };
}

/// Generate the full set of impls for an inner point-share newtype
/// (`InnerPointShareG1` / `InnerPointShareG2`).
///
/// Parameters:
/// - `$name`: the newtype identifier.
/// - `$group_doc`: the trailing text of the struct-level doc comment
///   (`"for points in G1"` / `"for points in G2"`).
/// - `$projective`/`$affine`: the projective and affine point types.
/// - `$id_access`/`$value_access`: the field-access token fragments used by the
///   `Display` impl, preserving the historical G1 (`.0`-suffixed) vs G2 output.
/// - `$v1_len`: length of the version-1 fixed byte array (`49` / `97`).
/// - `$compressed_len`: length of the compressed point (`48` / `96`).
macro_rules! impl_inner_point_share {
    (
        $name:ident,
        $group_doc:literal,
        $projective:ident,
        $affine:ident,
        [ $($id_access:tt)* ],
        [ $($value_access:tt)* ],
        $v1_len:literal,
        $compressed_len:literal
    ) => {
        #[doc = concat!("The share type ", $group_doc)]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[repr(transparent)]
        pub struct $name(
            pub DefaultShare<IdentifierPrimeField<Scalar>, ValueGroup<$projective>>,
        );

        impl subtle::ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let identifier1 = a.0.identifier.0;
                let identifier2 = b.0.identifier.0;
                let value1 = a.0.value.to_affine();
                let value2 = b.0.value.to_affine();

                let identifier = Scalar::conditional_select(&identifier1, &identifier2, choice);
                let value = $affine::conditional_select(&value1, &value2, choice);
                Self((identifier, $projective::from(value)).into())
            }
        }

        impl_from_derivatives!($name);

        impl TryFrom<&[u8]> for $name {
            type Error = BlsError;

            fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
                if input.len() != Scalar::BYTES + $projective::COMPRESSED_BYTES {
                    return Err(BlsError::DeserializationError(
                        concat!("Invalid length for ", stringify!($name)).to_string(),
                    ));
                }
                let identifier_bytes: [u8; Scalar::BYTES] =
                    (&input[0..Scalar::BYTES]).try_into().map_err(|_| {
                        BlsError::DeserializationError("Invalid length for Identifier".to_string())
                    })?;
                let identifier = Option::<Scalar>::from(Scalar::from_be_bytes(&identifier_bytes))
                    .ok_or_else(|| {
                        BlsError::DeserializationError(
                            "Invalid Identifier, cannot convert to scalar".to_string(),
                        )
                    })?;
                let value_bytes: [u8; $projective::COMPRESSED_BYTES] = (&input[Scalar::BYTES..])
                    .try_into()
                    .map_err(|_| {
                        BlsError::DeserializationError("Invalid length for Value".to_string())
                    })?;
                let value = Option::<$projective>::from($projective::from_compressed(&value_bytes))
                    .ok_or_else(|| {
                        BlsError::DeserializationError(
                            concat!("Invalid Value, cannot convert to ", stringify!($projective))
                                .to_string(),
                        )
                    })?;

                Ok(Self((identifier, value).into()))
            }
        }

        impl From<&$name> for Vec<u8> {
            fn from(value: &$name) -> Self {
                let mut output = vec![0u8; Scalar::BYTES + $projective::COMPRESSED_BYTES];
                output[..Scalar::BYTES].copy_from_slice(&value.0.identifier.0.to_be_bytes());
                output[Scalar::BYTES..].copy_from_slice(&value.0.value.0.to_compressed());
                output
            }
        }

        impl LowerHex for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                for b in self
                    .0
                    .identifier
                    .0
                    .to_be_bytes()
                    .iter()
                    .chain(self.0.value.0.to_compressed().iter())
                {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }

        impl UpperHex for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                for b in self
                    .0
                    .identifier
                    .0
                    .to_be_bytes()
                    .iter()
                    .chain(self.0.value.0.to_compressed().iter())
                {
                    write!(f, "{:02X}", b)?;
                }
                Ok(())
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "{{ identifier: {}, value: {} }}",
                    self.0 $($id_access)*,
                    self.0 $($value_access)*
                )
            }
        }

        impl Share for $name {
            type Identifier = IdentifierPrimeField<Scalar>;

            type Value = ValueGroup<$projective>;

            fn with_identifier_and_value(identifier: Self::Identifier, value: Self::Value) -> Self {
                Self(DefaultShare { identifier, value })
            }

            fn identifier(&self) -> &Self::Identifier {
                &self.0.identifier
            }

            fn identifier_mut(&mut self) -> &mut Self::Identifier {
                &mut self.0.identifier
            }

            fn value(&self) -> &Self::Value {
                &self.0.value
            }

            fn value_mut(&mut self) -> &mut Self::Value {
                &mut self.0.value
            }
        }

        impl $name {
            /// Convert secret share from InnerPointShareG1 v1 to the newer v2 format
            pub fn from_v1_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
                #[derive(Deserialize)]
                struct V1(
                    #[serde(deserialize_with = "fixed_arr::BigArray::deserialize")] [u8; $v1_len],
                );
                let v1 = serde_bare::from_slice::<V1>(bytes)
                    .map_err(|e| BlsError::InvalidInputs(e.to_string()))?;
                let identifier = Scalar::from(v1.0[0] as u64);
                let mut repr = [0u8; $compressed_len];
                repr.copy_from_slice(&v1.0[1..]);
                let value =
                    Option::from($projective::from_compressed(&repr)).ok_or_else(|| {
                        BlsError::InvalidInputs("Invalid compressed G1Projective".to_string())
                    })?;
                Ok(Self((identifier, value).into()))
            }
        }
    };
}

/// Generate `Display`, `Debug`, `Copy`, `Clone`, and `ConditionallySelectable`
/// for a signature enum with `Basic` / `MessageAugmentation` /
/// `ProofOfPossession` variants that each wrap a single inner value.
///
/// Parameters:
/// - `$name`: the enum identifier.
/// - `$inner`: the inner value type (`<C as Pairing>::Signature` etc).
/// - `$panic_msg`: the exact panic message for the mismatched-variant arm,
///   preserved verbatim per enum.
macro_rules! impl_signature_enum_traits {
    ($name:ident, $inner:ty, $panic_msg:literal) => {
        impl<C: BlsSignatureImpl> Display for $name<C> {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                match self {
                    Self::Basic(s) => write!(f, "Basic({})", s),
                    Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
                    Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
                }
            }
        }

        impl<C: BlsSignatureImpl> fmt::Debug for $name<C> {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                match self {
                    Self::Basic(s) => write!(f, "Basic({:?})", s),
                    Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
                    Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
                }
            }
        }

        impl<C: BlsSignatureImpl> Copy for $name<C> {}

        impl<C: BlsSignatureImpl> Clone for $name<C> {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for $name<C> {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                match (a, b) {
                    (Self::Basic(a), Self::Basic(b)) => {
                        Self::Basic(<$inner>::conditional_select(a, b, choice))
                    }
                    (Self::MessageAugmentation(a), Self::MessageAugmentation(b)) => {
                        Self::MessageAugmentation(<$inner>::conditional_select(a, b, choice))
                    }
                    (Self::ProofOfPossession(a), Self::ProofOfPossession(b)) => {
                        Self::ProofOfPossession(<$inner>::conditional_select(a, b, choice))
                    }
                    _ => panic!($panic_msg),
                }
            }
        }
    };
}

/// Generate the `BlsSerde` impl for a concrete signature-impl marker type
/// (`Bls12381G1Impl` / `Bls12381G2Impl`). The two impls are identical apart
/// from the marker name.
macro_rules! impl_bls_serde {
    ($name:ident) => {
        impl BlsSerde for $name {
            fn serialize_scalar<S: serde::Serializer>(
                scalar: &Scalar,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                <Scalar as serde::Serialize>::serialize(scalar, serializer)
            }

            fn serialize_scalar_share<S: serde::Serializer>(
                share: &Self::SecretKeyShare,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                share.serialize(serializer)
            }

            fn serialize_signature<S: serde::Serializer>(
                signature: &Self::Signature,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                signature.serialize(serializer)
            }

            fn serialize_public_key<S: serde::Serializer>(
                public_key: &Self::PublicKey,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                public_key.serialize(serializer)
            }

            fn serialize_public_key_share<S: serde::Serializer>(
                public_key_share: &Self::PublicKeyShare,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                public_key_share.serialize(serializer)
            }

            fn deserialize_scalar<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<<Self::PublicKey as Group>::Scalar, D::Error> {
                <Scalar as serde::Deserialize<'de>>::deserialize(deserializer)
            }

            fn deserialize_scalar_share<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self::SecretKeyShare, D::Error> {
                Self::SecretKeyShare::deserialize(deserializer)
            }

            fn deserialize_signature<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self::Signature, D::Error> {
                Self::Signature::deserialize(deserializer)
            }

            fn deserialize_public_key<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self::PublicKey, D::Error> {
                Self::PublicKey::deserialize(deserializer)
            }

            fn deserialize_public_key_share<'de, D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self::PublicKeyShare, D::Error> {
                Self::PublicKeyShare::deserialize(deserializer)
            }
        }
    };
}
