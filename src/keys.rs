use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::PublicParams;

/// Secret key: a random scalar `sk ∈ Fr`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) Fr);

impl SecretKey {
    pub fn random(rng: &mut impl Rng) -> Self {
        Self(Fr::rand(rng))
    }
}

/// Verification key: `vk = e(g1, g2)^sk = g_t^sk`.
///
/// Computed via bilinearity as `e(sk·g1, g2)`, avoiding an explicit GT
/// exponentiation.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerificationKey(pub(crate) <Bls12_381 as Pairing>::TargetField);

impl VerificationKey {
    /// Returns true if the VK equals the GT identity (multiplicative identity = Fp12::ONE).
    /// A correctly generated VK with non-zero sk is never the identity.
    pub fn is_identity(&self) -> bool {
        use ark_ff::One;
        self.0.is_one()
    }

    pub fn from_secret(sk: &SecretKey, params: &PublicParams) -> Self {
        // e(g1, g2)^sk = e(sk * g1, g2)  by bilinearity
        let sk_g1 = (G1Projective::from(params.g1) * sk.0).into_affine();
        let gt = Bls12_381::pairing(sk_g1, params.g2);
        Self(gt.0)
    }
}

/// Derive the secret key and verification key together.
pub fn keygen(params: &PublicParams, rng: &mut impl Rng) -> (SecretKey, VerificationKey) {
    let sk = SecretKey::random(rng);
    let vk = VerificationKey::from_secret(&sk, params);
    (sk, vk)
}
