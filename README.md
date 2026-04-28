# AirBB Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Anonymous Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Builds on the [arkworks](https://github.com/arkworks-rs/algebra) BLS12-381 curve implementation and uses Criterion for benchmarks.
For a comparison, the benchmarks additionally include the BBS signature scheme from the [docknetwork/crypto](https://github.com/docknetwork/crypto) library.
```
cargo test              # Run all tests
cargo bench             # Run all benchmarks
cargo bench --bench presentation  # Only run credential presentation benchmarks
```
