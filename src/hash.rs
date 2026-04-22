use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

/// Hash arbitrary bytes to an `Fr` field element via SHA-256 mod p.
pub fn hash_to_fr(data: &[u8]) -> Fr {
    let digest = Sha256::digest(data);
    Fr::from_be_bytes_mod_order(&digest)
}

/// Hash domain-separated bytes with a numeric index to `Fr`.
pub fn hash_to_fr_indexed(dst: &[u8], index: u64) -> Fr {
    let mut input = dst.to_vec();
    input.extend_from_slice(&index.to_be_bytes());
    hash_to_fr(&input)
}
