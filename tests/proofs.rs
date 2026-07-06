use blsful::*;
use rstest::*;

const TEST_MSG: &[u8] = b"signatures_work";

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn proof_of_knowledge_works<C: BlsSignatureImpl + Copy>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let sig = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let res = ProofCommitment::generate(TEST_MSG, sig);
    assert!(res.is_ok());
    let (comm, x) = res.unwrap();
    let y = ProofCommitmentChallenge::<C>::new();
    let res = comm.finalize(x, y, sig);
    assert!(res.is_ok());
    let proof = res.unwrap();
    assert!(proof.verify(pk, TEST_MSG, y).is_ok());
    let y2 = ProofCommitmentChallenge::<C>::new();
    assert!(proof.verify(pk, TEST_MSG, y2).is_err());
}

#[rstest]
#[case::g1(Bls12381G1Impl)]
#[case::g2(Bls12381G2Impl)]
fn proof_of_knowledge_timestamp_works<C: BlsSignatureImpl>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let sig = sk
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .unwrap();
    let mut proof = ProofOfKnowledgeTimestamp::generate(TEST_MSG, sig).unwrap();
    assert!(proof.verify(pk, TEST_MSG, None).is_ok());
    proof.timestamp -= 10;
    assert!(proof.verify(pk, TEST_MSG, Some(3)).is_err());
}
