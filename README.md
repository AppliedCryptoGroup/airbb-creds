# AirBB Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Threshold Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Note: This repository implements only the non-threshold (single-issuer) variant of the scheme, to enable a direct efficiency comparison against BBS. Hence, both blind-issuance commitment elements live in the first group, reducing the CRS size as we do not need to protect against adaptive corruptions of threshold issuers.


Builds on the [arkworks](https://github.com/arkworks-rs/algebra) BLS12-381 elliptic curve implementation and uses Criterion for benchmarks.
After running the benchmarks, you can find the results in the `target/criterion` directory. 
The benchmarks include non-blind and blind signing (issuance), presentation, and verification.
For a comparison, the benchmarks additionally cover the BBS signature scheme from the [docknetwork/crypto](https://github.com/docknetwork/crypto) library.
```
cargo test                               # Run all tests
cargo bench                              # Run all benchmarks
cargo bench --bench signing              # Only run signing benchmarks of our scheme
cargo bench --bench presentation present # Only run credential presentation benchmarks of our scheme
cargo bench --bench bbs                  # Only run benchmarks for the BBS signature scheme
```
