use blsful::inner_types::{G1Projective, G2Projective};
use blsful::*;
use rand_core::{Infallible, Rng, SeedableRng, TryRng};
use rstest::*;

const TEST_MSG: &[u8] = b"signatures_work";

struct MockRng(rand_xorshift::XorShiftRng);

impl SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

impl rand_core::TryCryptoRng for MockRng {}

impl TryRng for MockRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl Default for MockRng {
    fn default() -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed([7u8; 16]))
    }
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn basic_types_serialize_json<C: BlsSignatureImpl + PartialEq + Eq + std::fmt::Debug>(
    #[case] _c: C,
) {
    let sk = SecretKey::<C>::random(MockRng::default());
    let pk = sk.public_key();
    let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig_ma = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig_pop = sk
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();

    let res = serde_json::to_vec(&sk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<SecretKey<C>>(&text);
    assert!(res.is_ok());
    let sk2 = res.unwrap();
    assert_eq!(sk, sk2);

    let res = serde_json::to_vec(&pk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<PublicKey<C>>(&text);
    assert!(res.is_ok());
    let pk2 = res.unwrap();
    assert_eq!(pk, pk2);

    let res = serde_json::to_vec(&sig_b);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_b2 = res.unwrap();
    assert_eq!(sig_b, sig_b2);

    let res = serde_json::to_vec(&sig_ma);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_ma2 = res.unwrap();
    assert_eq!(sig_ma, sig_ma2);

    let res = serde_json::to_vec(&sig_pop);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_pop2 = res.unwrap();
    assert_eq!(sig_pop, sig_pop2);
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn basic_types_serialize_binary<C: BlsSignatureImpl + PartialEq + Eq + std::fmt::Debug>(
    #[case] _c: C,
) {
    let sk = SecretKey::<C>::random(MockRng::default());
    let pk = sk.public_key();
    let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig_ma = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig_pop = sk
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();

    let res = serde_bare::to_vec(&sk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<SecretKey<C>>(&text);
    assert!(res.is_ok());
    let sk2 = res.unwrap();
    assert_eq!(sk, sk2);

    let res = serde_bare::to_vec(&pk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<PublicKey<C>>(&text);
    assert!(res.is_ok());
    let pk2 = res.unwrap();
    assert_eq!(pk, pk2);

    let res = serde_bare::to_vec(&sig_b);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_b2 = res.unwrap();
    assert_eq!(sig_b, sig_b2);

    let res = serde_bare::to_vec(&sig_ma);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_ma2 = res.unwrap();
    assert_eq!(sig_ma, sig_ma2);

    let res = serde_bare::to_vec(&sig_pop);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_pop2 = res.unwrap();
    assert_eq!(sig_pop, sig_pop2);
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn shares_serialize<
    C: BlsSignatureImpl
        + PartialEq
        + Eq
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned,
>(
    #[case] _c: C,
) {
    let sk = SecretKey::<C>::from_hash(b"shares_serialize_json");
    // High number to test for fuzzing
    let sk_shares = sk.split(10, 20).unwrap();
    for share in &sk_shares {
        let text = serde_json::to_vec(&share).unwrap_or_else(|e| panic!("{e:?}"));
        let share2 =
            serde_json::from_slice::<SecretKeyShare<C>>(&text).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share, &share2);

        let text = serde_bare::to_vec(&share).unwrap_or_else(|e| panic!("{e:?}"));
        let share2 =
            serde_bare::from_slice::<SecretKeyShare<C>>(&text).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share, &share2);

        let pks = share.public_key().unwrap();
        let text = serde_json::to_vec(&pks).unwrap_or_else(|e| panic!("{e:?}"));
        let pks2 =
            serde_json::from_slice::<PublicKeyShare<C>>(&text).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pks, pks2);

        let sgs = share
            .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
            .unwrap();
        let res = serde_json::to_vec(&sgs);
        assert!(res.is_ok());
        let text = res.unwrap();
        let res = serde_json::from_slice::<SignatureShare<C>>(&text);
        assert!(res.is_ok());
        let sgs2 = res.unwrap();
        assert_eq!(sgs, sgs2);
    }
}

#[test]
fn shares_serialize_test() {
    let sk = SecretKey::<Bls12381G1Impl>::from_hash(b"shares_serialize_json");
    // High number to test for fuzzing
    let sk_shares = sk.split(10, 20).unwrap();
    for share in &sk_shares {
        let text = serde_json::to_vec(&share).unwrap_or_else(|e| panic!("{e:?}"));
        let share2 = serde_json::from_slice::<SecretKeyShare<Bls12381G1Impl>>(&text)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share, &share2);

        let pks = share.public_key().unwrap();
        let text = serde_json::to_vec(&pks).unwrap_or_else(|e| panic!("{e:?}"));
        let pks2 = serde_json::from_slice::<PublicKeyShare<Bls12381G1Impl>>(&text)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pks, pks2);

        let sgs = share
            .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
            .unwrap();
        let res = serde_json::to_vec(&sgs);
        assert!(res.is_ok());
        let text = res.unwrap();
        let res = serde_json::from_slice::<SignatureShare<Bls12381G1Impl>>(&text);
        assert!(res.is_ok());
        let sgs2 = res.unwrap();
        assert_eq!(sgs, sgs2);
    }
}

#[test]
fn legacy_shares_test() {
    let sk = SecretKey::<Bls12381G1Impl>::from_hash("legacy_shares_test");
    let sk_shares = sk.split(10, 20).unwrap();
    for share in &sk_shares {
        let mut v1 = [0u8; 33];
        v1[0] = share.0.identifier.to_le_bytes()[0];
        v1[1..].copy_from_slice(&share.0.value.to_le_bytes());

        let share2 = SecretKeyShare::<Bls12381G1Impl>::from_v1_bytes(&v1)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share, &share2);

        let mut v1 = [0u8; 49];
        v1[0] = share.0.identifier.to_le_bytes()[0];
        let t = G1Projective::GENERATOR * share.0.value.0;
        v1[1..].copy_from_slice(&t.to_compressed());

        let share2 = InnerPointShareG1::from_v1_bytes(&v1).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share.0.identifier, share2.0.identifier);
        assert_eq!(t, share2.0.value.0);

        let mut v1 = [0u8; 97];
        v1[0] = share.0.identifier.to_le_bytes()[0];
        let t = G2Projective::GENERATOR * share.0.value.0;
        v1[1..].copy_from_slice(&t.to_compressed());

        let share2 = InnerPointShareG2::from_v1_bytes(&v1).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(share.0.identifier, share2.0.identifier);
        assert_eq!(t, share2.0.value.0);
    }
}
