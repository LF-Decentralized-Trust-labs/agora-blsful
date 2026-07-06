//! Wire-format stability tests.
//!
//! These vectors pin the serialized byte format of the core types. If any of
//! these assertions fail, the serialization format has changed and previously
//! stored data will no longer deserialize — that is a breaking change and
//! must be called out in the CHANGELOG with a migration path.
use blsful::*;
use rand_core::{Infallible, Rng, SeedableRng, TryRng};

const TEST_MSG: &[u8] = b"wire_format_stability";

const G1_SK_BARE: &str = "14e2b68ef9d53f01d5b348c70c71df1d94b8fc847752eccbdf21cfe10ed28df7";
const G1_PK_BARE: &str = "a7de034428657c384aec9abc0ffa7fd0b8e76fbd2b729b28795217c1c25a2b18309eb92b3c8c606290a0d8fe1b5106750f4f0095010b5a197cf11a84e60a9c8367b28b85ad0e7fd0731907c5d26d62ee49bcee2ec89650ab518f4c0fad8266be";
const G1_SIG_BARE: &str = "02a555c59b5ea9b443c4b4f43bfad3faee2bd552ec11a82a193893c5b94772c741a113fab68a2b8d10439851339325ae7b";
const G1_SIG_JSON: &str = r#"{"ProofOfPossession":"a555c59b5ea9b443c4b4f43bfad3faee2bd552ec11a82a193893c5b94772c741a113fab68a2b8d10439851339325ae7b"}"#;

const G2_SK_BARE: &str = "14e2b68ef9d53f01d5b348c70c71df1d94b8fc847752eccbdf21cfe10ed28df7";
const G2_PK_BARE: &str = "87862ae2a05c71f6d3853b885e45ca6847775a9ef83f301c4030b704f3bbc4d0ce013328168049f806642260c2b85701";
const G2_SIG_BARE: &str = "0290fc131ccbd5867f0a054d17a94f2e91fc5eaf59b9c586204d291309ab3936f7a133cb8450e09b51fd19516e0d921cec03fd0934bc895ac3518d8dcb137719f54a2d5da4090801d64710f1d1e4026f25228ac7906c1190dc782555e17e1de70e";
const G2_SIG_JSON: &str = r#"{"ProofOfPossession":"90fc131ccbd5867f0a054d17a94f2e91fc5eaf59b9c586204d291309ab3936f7a133cb8450e09b51fd19516e0d921cec03fd0934bc895ac3518d8dcb137719f54a2d5da4090801d64710f1d1e4026f25228ac7906c1190dc782555e17e1de70e"}"#;

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

fn check_wire_format<C: BlsSignatureImpl + PartialEq + Eq + std::fmt::Debug>(
    sk_bare: &str,
    pk_bare: &str,
    sig_bare: &str,
    sig_json: &str,
) {
    let sk = SecretKey::<C>::random(MockRng::default());
    let pk = sk.public_key();
    let sig = sk
        .sign(SignatureSchemes::ProofOfPossession, TEST_MSG)
        .expect("a valid signature");

    assert_eq!(
        hex::encode(serde_bare::to_vec(&sk).expect("secret key serializes")),
        sk_bare
    );
    assert_eq!(
        hex::encode(serde_bare::to_vec(&pk).expect("public key serializes")),
        pk_bare
    );
    assert_eq!(
        hex::encode(serde_bare::to_vec(&sig).expect("signature serializes")),
        sig_bare
    );
    assert_eq!(
        serde_json::to_string(&sig).expect("signature serializes to json"),
        sig_json
    );

    // The pinned bytes must also deserialize back to equal values.
    let sk2: SecretKey<C> = serde_bare::from_slice(&hex::decode(sk_bare).expect("valid hex"))
        .expect("secret key deserializes");
    assert_eq!(sk, sk2);
    let sig2: Signature<C> = serde_json::from_str(sig_json).expect("signature deserializes");
    assert_eq!(sig, sig2);
}

#[test]
fn wire_format_g1() {
    check_wire_format::<Bls12381G1Impl>(G1_SK_BARE, G1_PK_BARE, G1_SIG_BARE, G1_SIG_JSON);
}

#[test]
fn wire_format_g2() {
    check_wire_format::<Bls12381G2Impl>(G2_SK_BARE, G2_PK_BARE, G2_SIG_BARE, G2_SIG_JSON);
}
