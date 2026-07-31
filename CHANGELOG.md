# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## v4.0.0 - 2026-07-31

- Add scheme-specific `sign_basic`, `sign_augmented`, and `sign_pop` convenience methods.
- Add caller-provided RNG variants for signcryption, time-lock encryption,
  ElGamal encryption, and proof generation.
- Add `scheme` accessors to signatures and signature shares.
- Add `scheme` accessors to signcryption and time-lock ciphertexts.
- Add `scheme` accessors to proof commitments and proofs of knowledge.
- Make verification APIs consistently borrow public keys.
- Reject empty signature-share collections instead of panicking.
- Reject unknown signature scheme strings and wire values instead of silently
  treating them as proof-of-possession.
- Avoid cloning messages during basic aggregate verification.
- Prevent internal XOR helpers from silently truncating mismatched inputs.
- Bounds-check encoded message lengths and consistently reject malformed
  signcryption and time-lock plaintext encodings.
- Make multi-public-key construction fallible and reject collections with fewer
  than two keys.
- Reject undersized aggregate-verification and share-reconstruction inputs
  before invoking lower-level cryptographic operations.
- Ensure zero-scalar rejection retries derive fresh HKDF output instead of
  looping forever, while preserving existing first-attempt derivations.
- Resample the negligible zero case for randomly generated ElGamal blinders.
- Remove the unused `anyhow` dependency and make `BlsError` directly
  comparable with `Eq` and `PartialEq`.
- Move `hex` to development dependencies because it is only used by wire-format
  tests.
- Preserve the original `vsss-rs` error inside `BlsError::VsssError` so callers
  can distinguish invalid thresholds, duplicate shares, and other failures.
- Normalize malformed serde byte input to `DeserializationError` and avoid
  double-wrapping generated serialization errors.
- Centralize signature-scheme domain selection across encryption, decryption,
  ciphertext validation, and decryption-share verification.
- Eliminate a temporary heap allocation from the fixed-size time-lock XOR path.
- Avoid an identity-point addition when constructing aggregate and
  multi-signatures, and pre-size aggregate-verification collections.
- Clarify and test scheme-specific duplicate-message behavior during aggregate
  verification.
- Eliminate per-message byte allocations from Basic aggregate verification when
  using the public slice-based API.
- Verify share identifiers match before accepting signature or decryption shares.
- Use the ciphertext's actual signature-scheme domain when verifying signcryption
  decryption shares.
- Remove the deprecated v1 share conversion APIs.
- Update README examples to the current API.
- Update `bls12_381_plus` and `blstrs_plus` to stable 0.9.0 releases and
  `vsss-rs` to 6.0.1.
- Update development dependencies and replace `uint-zigzag` with the maintained,
  wire-compatible `unsigned-varint` crate.
- Reduce enabled dependency features and remove direct `rand_core` and
  `rand_chacha` dependencies while preserving the public field-bit exports.
- Replace three-value trait return tuples with `SignCryptCiphertextParts`,
  `TimeCryptCiphertextParts`, and `TimestampProofParts` result structs.

## v4.0.0-rc0 - 2026-07-06

- Update to Rust edition 2024.
- Update dependencies: `vsss-rs` 6.0, `blstrs_plus`/`bls12_381_plus` 0.9,
  `rand` 0.10, and `sha2` 0.11.
- Migrate internal trait bounds to the `group` 0.14 / `ff` 0.14 trait family.
- Add non-generic enum wrappers (`Bls12381`) for trait-object-like use without generics.
- Move the repository to LF Decentralized Trust Labs (`agora-blsful`).
- Reduce internal G1/G2 code duplication via macros (with no API or serialization changes).

## v3.0.0 - 2024

- Update to the new `vsss-rs` API.
- Use `vsss_rs::DefaultShare` for shares instead of byte sequences.
- Deprecate the old byte-sequence share format.
- Fix `inner_types` exports so they do not clash with other crates.
- Add conversion methods for shares to the newer format.

## v2.5.3 - 2023-10-19

- Add conversion methods to and from `Vec`.
- Add serialization for `PublicKeyShare` values.

## v2.4.1 - 2023-09-27

- Add checks for invalid points and scalars.
- Use the canonical `Clone` implementation for `Copy` types.

## v2.4.0 - 2023-08-09

- Update the API to use endian-specific outputs.

## v2.3.0 - 2023-06-01

- Update internal dependencies.

## v2.2.0 - 2023-05-30

- Use traits instead of concrete types to reduce code duplication.
- Allow `blst` or pure-Rust implementations of BLS12-381.

## v1.1.0 - 2023-03-01

- Refactor methods for creating signature proofs of knowledge.

## v1.0.1 - 2023-03-01

- Add `BYTES` constants to `ProofOfKnowledge` structs.
- Add `to_bytes` and `from_bytes` methods to `ProofOfKnowledge` structs.

## v1.0.0 - 2023-02-28

- Initial release.
