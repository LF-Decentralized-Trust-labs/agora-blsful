# BLS Signature Scheme

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0/MIT Licensed][license-image]

The blissful crate provides a production ready BLS signature implementation.

## Security Notes

This crate has received one security audit from Kudelski Security, with no significant findings. The audit report can be found [here](./audit/2024-15-02_LitProtoco_Crypto_Libraries_v1.1.pdf).
We'd like to thank [LIT Protocol](https://www.litprotocol.com/) for sponsoring this audit.

All operations are constant time unless explicitly noted.

# [Documentation](https://docs.rs/blsful)
BLS signatures offer the smallest known signature size as well as other benefits like one round threshold signing and signature aggregation.

BLS signatures rely on pairing-friendly curves which have two fields for points. This library provides keys and signatures for both fields.

Use `Bls12381G1Impl` for signatures in G1 and public keys in G2, or
`Bls12381G2Impl` for signatures in G2 and public keys in G1. The `*Enum`
types are available when that choice is only known at runtime.

This library supports threshold signatures in the form of `SignatureShare` values generated from `SecretKeyShare` instead of a `SecretKey`.
`SignatureShare`s can be combined to make a full `Signature` assuming there are sufficient above the threshold. `SecretKeyShare`s can
be generated using shamir secret sharing from crates like [vsss-rs](https://docs.rs/vsss-rs) or using distributed key generation methods like
[gennaro-dkg](https://docs.rs/gennaro-dkg).

Multi-signatures aggregate signatures over the same message. This allows signature compression and very fast
verification assuming rogue key attacks have been taken into account using Proofs of Possession. For now this library only provides the proof of possession scheme
as this is the most widely used.

Aggregate signatures combine signatures over different messages. While verification is not much faster,
this still allows signature compression.

# Examples

## Key operations

From random entropy source

```rust
use blsful::{Bls12381G1Impl, SecretKey};

let sk = SecretKey::<Bls12381G1Impl>::new();
let pk = sk.public_key();
let pop = sk.proof_of_possession().expect("a proof of possession");
pop.verify(&pk).expect("a valid proof");
```

From seed

```rust
let sk = SecretKey::<Bls12381G1Impl>::from_hash(b"seed phrase");
let pk = PublicKey::from(&sk);
```

Split a key into key shares

```rust
let shares = sk.split(3, 5).expect("valid threshold parameters");
```

Restore a key from shares

```rust
let sk = SecretKey::<Bls12381G1Impl>::combine(&shares).expect("enough valid shares");
```

## Signature operations

Create a signature
```rust
let message = b"00000000-0000-0000-0000-000000000000";
let sig = sk.sign_basic(message).expect("a valid signature");
```

Verify a signature
```rust
sig.verify(&pk, message).expect("a valid signature");
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

# References

1. [IETF Spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/blsful.svg
[crate-link]: https://crates.io/crates/blsful
[docs-image]: https://docs.rs/blsful/badge.svg
[docs-link]: https://docs.rs/blsful/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
