use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

use crate::hash::hash_to_fr_indexed;

/// Public parameters for the signature scheme.
///
/// Generated once for a maximum message count `l`. Contains group generators
/// used in both key derivation and signing.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams {
    /// Maximum number of messages that can be signed.
    pub l: usize,
    /// Base generator in G1.
    pub g1: G1Affine,
    /// Base generator in G2.
    pub g2: G2Affine,
    /// Message generators h_1 .. h_l in G1 (one per message slot).
    pub h: Vec<G1Affine>,
}

impl PublicParams {
    /// Derive a structured reference string for up to `l` messages.
    ///
    /// FIXME: Generators h_i are derived as `h_i = g1 * hash("bb-sigs:h" || i)`. Hash should map to group
    pub fn setup(l: usize, _rng: &mut impl Rng) -> Self {
        assert!(l > 0, "l must be at least 1");

        let g1: G1Affine = G1Projective::generator().into_affine();
        let g2: G2Affine = G2Projective::generator().into_affine();

        let h: Vec<G1Affine> = (0..l)
            .map(|i| {
                let scalar = hash_to_fr_indexed(b"bb-sigs:generator:h", i as u64);
                (G1Projective::generator() * scalar).into_affine()
            })
            .collect();

        Self { l, g1, g2, h }
    }
}
