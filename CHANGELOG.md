# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v4.0.0-rc0 - 2026-07-06

- Update to Rust edition 2024
- Update dependencies: `vsss-rs` 6.0, `blstrs_plus`/`bls12_381_plus` 0.9, `rand` 0.10, `sha2` 0.11
- Migrate internal trait bounds to the `group` 0.14 / `ff` 0.14 trait family
- Add non-generic enum wrappers (`Bls12381`) for trait-object-like use without generics
- Repository moved to LF Decentralized Trust Labs (`agora-blsful`)
- Reduce internal G1/G2 code duplication via macros (no API or serialization change)

## v3.0.0 - 2024

- Update to use vsss-rs new API
- Shares now use `vsss_rs::DefaultShare` instead of byte sequences
- Old share format is deprecate that used byte sequences
- Fix inner_types exports to not clash with other crates
- Add conversion methods for Shares to the newer format.

## v2.5.3 - 2023-10-19

- Add to and from Vec methods
- Add serialization for PublicKeyShares

## v2.4.1 - 2023-09-27

- Additional checks for invalid points and scalars
- Use canonical Clone with Copy

## v2.4.0 - 2023-08-09

- Update API to use endian specific outputs

## v2.3.0 - 2023-06-01

- Update inner dependencies

## v2.2.0 - 2023-05-30

- Change to use traits instead of concrete types which reduces code duplication
- Allow for blst or pure rust implementations of BLS12-381

## v1.1.0 - 2023-03-1

- Refactor methods for creating signature proofs of knowledge

## v1.0.1 - 2023-03-01

- Add const BYTES ProofOfKnowledge structs
- Add to_bytes and from_bytes to ProofOfKnowledge structs

## v1.0.0 - 2023-02-28

- Initial release.
