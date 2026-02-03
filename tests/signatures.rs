mod utils;
use blsful::{
    AggregateSignature, Bls12381G1, Bls12381G1Impl, Bls12381G2, Bls12381G2Impl, BlsSignatureImpl,
    MultiPublicKey, MultiSignature, PublicKey, SecretKey, Signature, SignatureSchemes,
};
use rstest::*;
use utils::*;

#[test]
fn signatures_work() {
    for scheme in &[
        SignatureSchemes::Basic,
        SignatureSchemes::MessageAugmentation,
        SignatureSchemes::ProofOfPossession,
    ] {
        let sk1 = Bls12381G1::new_secret_key();
        let sk2 = Bls12381G2::new_secret_key();

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let res1 = sk1.sign(*scheme, TEST_MSG);
        let res2 = sk2.sign(*scheme, TEST_MSG);

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        let sig1 = res1.unwrap();
        let sig2 = res2.unwrap();

        assert!(sig1.verify(&pk1, TEST_MSG).is_ok());
        assert!(sig2.verify(&pk2, TEST_MSG).is_ok());
        assert!(sig1.verify(&pk1, BAD_MSG).is_err());
        assert!(sig2.verify(&pk2, BAD_MSG).is_err());
    }
}

#[test]
fn proof_of_possession_works() {
    let sk = Bls12381G1::new_secret_key();
    let pk = sk.public_key();
    let pop = sk.proof_of_possession().unwrap();
    assert!(pop.verify(pk).is_ok());

    let sk = SecretKey::<Bls12381G2Impl>(sk.0);
    let pk = sk.public_key();
    let pop = sk.proof_of_possession().unwrap();
    assert!(pop.verify(pk).is_ok());

    let sk2 = Bls12381G2::new_secret_key();
    let pk2 = sk2.public_key();
    assert!(pop.verify(pk2).is_err());
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn shares_work<C: BlsSignatureImpl + PartialEq + Eq>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pko = sk.public_key();
    let shares = sk.split_with_rng(2, 3, rand_core::OsRng).unwrap();
    let sig1 = shares[0].sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig2 = shares[1].sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig3 = shares[2].sign(SignatureSchemes::Basic, TEST_MSG).unwrap();

    let res = shares[0].sign(SignatureSchemes::MessageAugmentation, TEST_MSG);
    assert!(res.is_err());

    let pks1 = shares[0].public_key().unwrap();
    let pks2 = shares[1].public_key().unwrap();
    let pks3 = shares[2].public_key().unwrap();

    assert!(sig1.verify(&pks1, TEST_MSG).is_ok());
    assert!(sig2.verify(&pks2, TEST_MSG).is_ok());
    assert!(sig3.verify(&pks3, TEST_MSG).is_ok());

    let res = Signature::from_shares(&[sig1, sig2, sig3]);
    assert!(res.is_ok());
    let sig = res.unwrap();

    let res = PublicKey::from_shares(&[pks1, pks2, pks3]);
    assert!(res.is_ok());
    let pk = res.unwrap();
    assert_eq!(pk, pko);
    assert!(sig.verify(&pk, TEST_MSG).is_ok());
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn multisigs_work<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk1 = SecretKey::<C>::new();
    let sk2 = SecretKey::<C>::new();
    let sk3 = SecretKey::<C>::new();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let pk3 = sk3.public_key();

    let sig1 = sk1
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();
    let sig2 = sk2
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();
    let sig3 = sk3
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();

    let msig = MultiSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    let mpk = MultiPublicKey::from([pk1, pk2, pk3].to_vec().as_slice());
    assert!(msig.verify(mpk, TEST_MSG).is_ok());

    let off_sig = sk1.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let res = MultiSignature::from_signatures(&[sig1, sig2, sig3, off_sig]);
    assert!(res.is_err());

    // miss a key
    let mpk = MultiPublicKey::from_public_keys(&[pk1, pk2]);
    assert!(msig.verify(mpk, TEST_MSG).is_err());

    let sk4 = SecretKey::<C>::new();
    let bad_sig = sk4
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let res = MultiSignature::from_signatures(&[sig1, sig2, sig3, bad_sig]);
    assert!(res.is_err());
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn aggegratesigs_work<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk1 = SecretKey::<C>::new();
    let sk2 = SecretKey::<C>::new();
    let sk3 = SecretKey::<C>::new();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let pk3 = sk3.public_key();

    let sig1 = sk1.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig3 = sk3.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();

    let asig = AggregateSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    assert!(
        asig.verify(&[(pk1, TEST_MSG), (pk2, TEST_MSG), (pk3, TEST_MSG)])
            .is_err()
    );

    let sig1 = sk1.sign(SignatureSchemes::Basic, b"sig1").unwrap();
    let sig2 = sk2.sign(SignatureSchemes::Basic, b"sig2").unwrap();
    let sig3 = sk3.sign(SignatureSchemes::Basic, b"sig3").unwrap();
    let asig = AggregateSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    assert!(
        asig.verify(&[(pk1, b"sig1"), (pk2, b"sig2"), (pk3, b"sig3")])
            .is_ok()
    );

    let sig1 = sk1
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig2 = sk2
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig3 = sk3
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();

    let asig = AggregateSignature::from_signatures(&[sig1, sig2, sig3]).unwrap();
    assert!(
        asig.verify(&[(pk1, TEST_MSG), (pk2, TEST_MSG), (pk3, TEST_MSG)])
            .is_ok()
    );
}
