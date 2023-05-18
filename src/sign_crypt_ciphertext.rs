use crate::*;
use subtle::CtOption;

/// The ciphertext output from sign crypt encryption
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignCryptCiphertext<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
        + BlsSignCrypt
        + BlsTimeCrypt
        + BlsSignatureProof
        + BlsSerde,
> {
    /// The `u` component
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub u: <C as Pairing>::PublicKey,
    /// The `v` component
    pub v: Vec<u8>,
    /// The `w` component
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub w: <C as Pairing>::Signature,
    /// The signature scheme used to generate this ciphertext
    pub scheme: SignatureSchemes,
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Display for SignCryptCiphertext<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{{ u: {}, v: {:?}, w: {}, scheme: {:?} }}",
            self.u, self.v, self.w, self.scheme
        )
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > SignCryptCiphertext<C>
{
    /// Decrypt the signcrypt ciphertext
    pub fn decrypt(&self, sk: &SecretKey<C>) -> CtOption<Vec<u8>> {
        let dst = match self.scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };

        <C as BlsSignCrypt>::unseal(self.u, &self.v, self.w, &sk.0, dst)
    }

    /// Check if the ciphertext is valid
    pub fn is_valid(&self) -> Choice {
        match self.scheme {
            SignatureSchemes::Basic => {
                <C as BlsSignCrypt>::valid(self.u, &self.v, self.w, <C as BlsSignatureBasic>::DST)
            }
            SignatureSchemes::MessageAugmentation => <C as BlsSignCrypt>::valid(
                self.u,
                &self.v,
                self.w,
                <C as BlsSignatureMessageAugmentation>::DST,
            ),
            SignatureSchemes::ProofOfPossession => {
                <C as BlsSignCrypt>::valid(self.u, &self.v, self.w, <C as BlsSignaturePop>::SIG_DST)
            }
        }
    }
}

/// A Signcrypt decryption key where the secret key is hidden or combined from shares
/// that can decrypt ciphertext
#[derive(Default, PartialEq, Eq)]
pub struct SignCryptDecryptionKey<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
        + BlsSignCrypt
        + BlsTimeCrypt
        + BlsSignatureProof
        + BlsSerde,
>(pub <C as Pairing>::PublicKey);

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Serialize for SignCryptDecryptionKey<C>
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <C as BlsSerde>::serialize_public_key(&self.0, s)
    }
}

impl<
        'de,
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Deserialize<'de> for SignCryptDecryptionKey<C>
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <C as BlsSerde>::deserialize_public_key(d).map(Self)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Debug for SignCryptDecryptionKey<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Clone for SignCryptDecryptionKey<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > SignCryptDecryptionKey<C>
{
    /// Decrypt signcrypt ciphertext
    pub fn decrypt(&self, ciphertext: &SignCryptCiphertext<C>) -> CtOption<Vec<u8>> {
        let dst = match ciphertext.scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };

        let choice = <C as BlsSignCrypt>::valid(ciphertext.u, &ciphertext.v, ciphertext.w, dst);
        <C as BlsSignCrypt>::decrypt(&ciphertext.v, self.0, choice)
    }

    /// Combine decryption shares into a signcrypt decryption key
    pub fn from_shares(shares: &[SignDecryptionShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}