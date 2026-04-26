# AirBB Anonymous Credentials

This repository implements a Rust prototype of the "AirBB: Lightweight Anonymous Credentials without Random Oracles from BB Signatures" paper, including tests and benchmarks.

Uses the arkworks BLS12-381 implementation and Criterion for benchmarks
```
cargo test              # Run all tests
cargo bench             # Run all benchmarks
cargo bench --bench presentation  # Only run credential presentation benchmarks
```
