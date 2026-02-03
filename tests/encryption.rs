mod utils;
use blsful::*;
use rstest::*;
use utils::*;

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn sign_crypt_works<C: BlsSignatureImpl + PartialEq + Eq + std::fmt::Debug>(#[case] _c: C) {
    // Repeat test a few times to ensure randomness and fuzz testing
    for _ in 0..25 {
        let sk = BlsSignature::<C>::new_secret_key();
        let pk = sk.public_key();
        let ciphertext = pk.sign_crypt(SignatureSchemes::Basic, TEST_MSG);
        assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);
        let plaintext = ciphertext.decrypt(&sk);
        assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
        let plaintext = plaintext.unwrap();
        assert_eq!(plaintext.as_slice(), TEST_MSG);

        let sk2 = BlsSignature::<C>::new_secret_key();
        assert_ne!(sk, sk2);
        let plaintext = ciphertext.decrypt(&sk2);
        // Sometimes this can happen but the ciphertext should still fail
        if plaintext.is_some().into() {
            let plaintext = plaintext.unwrap();
            assert_ne!(plaintext, TEST_MSG);
        } else {
            assert_eq!(plaintext.is_none().unwrap_u8(), 1u8);
        }
    }
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn sign_crypt_with_shares_works<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let shares = sk.split(2, 3).unwrap();
    let ciphertext = pk.sign_crypt(SignatureSchemes::Basic, TEST_MSG);
    let public_key_shares = shares
        .iter()
        .map(|s| s.public_key().unwrap())
        .collect::<Vec<_>>();
    let decryption_shares = shares
        .iter()
        .map(|s| ciphertext.create_decryption_share(s).unwrap())
        .collect::<Vec<_>>();
    assert!(
        decryption_shares
            .iter()
            .zip(public_key_shares.iter())
            .all(|(d, p)| d.verify(p, &ciphertext).is_ok())
    );

    let res = ciphertext.decrypt_with_shares(&decryption_shares);
    assert_eq!(res.is_some().unwrap_u8(), 1u8);
    let plaintext = res.unwrap();
    assert_eq!(plaintext.as_slice(), TEST_MSG);
    let res = ciphertext.decrypt_with_shares(&decryption_shares[2..]);
    assert_eq!(res.is_some().unwrap_u8(), 0u8);
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn time_lock_works<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let ciphertext = pk
        .encrypt_time_lock(SignatureSchemes::Basic, TEST_MSG, TEST_ID)
        .unwrap();
    let sig = sk.sign(SignatureSchemes::Basic, TEST_ID).unwrap();
    let bad_sig = sk.sign(SignatureSchemes::Basic, BAD_MSG).unwrap();
    let bad_scheme = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_ID)
        .unwrap();

    let plaintext = ciphertext.decrypt(&sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
    let plaintext = plaintext.unwrap();
    assert_eq!(plaintext.as_slice(), TEST_MSG);

    let plaintext = ciphertext.decrypt(&bad_sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
    let plaintext = ciphertext.decrypt(&bad_scheme);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
}

#[test]
fn time_lock_works_g1() {
    let sk = SecretKey::<Bls12381G1Impl>::new();
    let pk = sk.public_key();
    let ciphertext = pk
        .encrypt_time_lock(SignatureSchemes::Basic, TEST_MSG, TEST_ID)
        .unwrap();
    let sig = sk.sign(SignatureSchemes::Basic, TEST_ID).unwrap();
    let bad_sig = sk.sign(SignatureSchemes::Basic, BAD_MSG).unwrap();
    let bad_scheme = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_ID)
        .unwrap();

    let plaintext = ciphertext.decrypt(&sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
    let plaintext = plaintext.unwrap();
    assert_eq!(plaintext.as_slice(), TEST_MSG);

    let plaintext = ciphertext.decrypt(&bad_sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
    let plaintext = ciphertext.decrypt(&bad_scheme);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
}

#[rstest]
#[case::basic(SignatureSchemes::Basic)]
#[case::proof_of_possession(SignatureSchemes::ProofOfPossession)]
fn time_lock_all_schemes(#[case] scheme: SignatureSchemes) {
    let sk = Bls12381G2::new_secret_key();
    let pk = sk.public_key();
    let shares = sk.split(2, 3).unwrap();
    let sig_shares = shares
        .iter()
        .map(|s| s.sign(scheme, TEST_ID).unwrap())
        .collect::<Vec<_>>();
    let ciphertext = pk.encrypt_time_lock(scheme, TEST_MSG, TEST_ID).unwrap();
    let res = ciphertext.decrypt(&Signature::from_shares(&sig_shares).unwrap());
    assert_eq!(res.is_some().unwrap_u8(), 1u8);
}

#[rstest]
#[case::g1_basic(Bls12381G1Impl, SignatureSchemes::Basic)]
#[case::g1_pop(Bls12381G1Impl, SignatureSchemes::ProofOfPossession)]
#[case::g2_basic(Bls12381G2Impl, SignatureSchemes::Basic)]
#[case::g2_pop(Bls12381G2Impl, SignatureSchemes::ProofOfPossession)]
fn encrypt_bigger_than_32<C: BlsSignatureImpl>(#[case] _c: C, #[case] scheme: SignatureSchemes) {
    const BIG_MSG: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum venenatis convallis nunc, in ullamcorper lectus fringilla in. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Sed posuere in quam ac ultricies. Proin rhoncus nisl eget urna accumsan porttitor. Nulla quis est et sem cursus gravida quis ac enim. Fusce congue tincidunt lobortis. Interdum et malesuada fames ac ante ipsum primis in faucibus. Praesent vel urna nisi. Pellentesque lacinia placerat lacus sed laoreet. Sed ullamcorper, nulla eu cursus varius, ligula metus ornare diam, a ultrices tellus dolor a diam. Phasellus lobortis leo non tincidunt molestie. Aliquam molestie est quis nulla porta pellentesque. Nam rutrum hendrerit lorem. Sed malesuada dolor eu felis pulvinar, in euismod sapien feugiat. Duis consequat mi dictum, faucibus velit quis, egestas felis.";
    let sk = BlsSignature::<C>::new_secret_key();
    let pk = sk.public_key();
    let ciphertext = pk.encrypt_time_lock(scheme, BIG_MSG, TEST_ID);
    assert!(ciphertext.is_ok());
    let ciphertext = ciphertext.unwrap();
    let sig = sk.sign(scheme, TEST_ID).unwrap();
    let plaintext = ciphertext.decrypt(&sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
    let plaintext = plaintext.unwrap();
    assert_eq!(plaintext.as_slice(), BIG_MSG);

    let ciphertext = pk.sign_crypt(scheme, BIG_MSG);
    let plaintext = ciphertext.decrypt(&sk);
    assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
    let plaintext = plaintext.unwrap();
    assert_eq!(plaintext.as_slice(), BIG_MSG);
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn elgamal_ciphertext_works<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let one = SecretKey::<C>::new();
    let two = SecretKey::<C>::new();
    let three = SecretKey::<C>::new();
    let pk = sk.public_key();

    let res = pk.encrypt_key_el_gamal(&one);
    assert!(res.is_ok());
    let ciphertext_one = res.unwrap();

    let res = ciphertext_one.decrypt(&sk);
    assert_eq!(res, <C as BlsElGamal>::message_generator() * one.0);

    let res = pk.encrypt_key_el_gamal(&two);
    assert!(res.is_ok());
    let ciphertext_two = res.unwrap();
    let res = pk.encrypt_key_el_gamal(&three);
    assert!(res.is_ok());
    let ciphertext_three = res.unwrap();

    let ciphertext = ciphertext_one + ciphertext_two + ciphertext_three;
    let sum = ciphertext.decrypt(&sk);

    assert_eq!(
        <C as BlsElGamal>::message_generator() * (one.0 + two.0 + three.0),
        sum
    );
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn elgamal_proofs_work<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();

    let secret = SecretKey::<C>::new();
    let res = pk.encrypt_key_el_gamal_with_proof(&secret);
    assert!(res.is_ok());
    let proof = res.unwrap();
    assert!(proof.verify(pk).is_ok());
    let res = proof.verify_and_decrypt(&sk);
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        <C as BlsElGamal>::message_generator() * secret.0
    );
}
