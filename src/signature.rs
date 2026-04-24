use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::Rng;
use crate::commitment::commit;
use crate::error::Error;
use crate::keys::{SecretKey, VerificationKey};
use crate::params::PublicParams;

/// An AirBB signature is of the form σ = (σ₁, σ₂) ∈ G1 × G1 where
///
/// ```text
/// σ₁ = g1^sk · C^r
/// σ₂ = g1^r
/// ```
///
/// with `sk` being the signer's secret key, `r ←$ Fr` a random scalar, and `C = h1^{a·p_M(τ)}` is
/// the set commitment on the full message set M (see `commitment::commit`).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    pub(crate) sigma1: G1Affine,
    pub(crate) sigma2: G1Affine,
}

impl Signature {
    /// Construct a signature from raw group elements (intended for tests).
    pub fn from_parts(sigma1: G1Affine, sigma2: G1Affine) -> Self {
        Self { sigma1, sigma2 }
    }
}

/// Sign a set of messages using a set commitment using `sk`.
///
/// # Signing Protocol
///
/// 1. Sample a scalar `r ←$ Fr`.
/// 2. Compute the set commitment `C = h1^{r·p_M(τ)}` over `messages` (see `commitment::commit`).
/// 3. Output the signature pair:
///    ```text
///    σ₁ = g1^sk · C^r   (in G1)
///    σ₂ = g1^r           (in G1)
///    ```
///
pub fn sign(
    params: &PublicParams,
    sk: &SecretKey,
    messages: &[Fr],
    rng: &mut impl Rng,
) -> Result<Signature, Error> {
    let r = Fr::rand(rng);
    let c = commit(params, messages, &r)?;

    let sigma1 = (G1Projective::from(sk.g1_sk) + c.0).into_affine();
    let sigma2 = (G1Projective::from(params.g1) * r).into_affine();

    Ok(Signature { sigma1, sigma2 })
}

/// Verify a signature σ = (σ₁, σ₂) against `vk` and a message set.
///
/// # Protocol
///
///
/// 1. Re-derive the set commitment `C = h2^{a·p_M(τ)}` for `messages`.
/// 2. Check the pairing equation:
///    ```text
///    e(σ₁, g2) = vk · e(σ₂, C)
pub fn verify(
    params: &PublicParams,
    vk: &VerificationKey,
    messages: &[Fr],
    sig: &Signature,
) -> Result<bool, Error> {
    let c = commit(params, messages, &Fr::one())?;

    let lhs: PairingOutput<Bls12_381> = Bls12_381::pairing(sig.sigma1, params.g2);
    // let rhs: PairingOutput<Bls12_381> = vk.0 * Bls12_381::pairing(sig.sigma2, params.h2).0;
    // let rhs = vk.0 * Bls12_381::pairing(sig.sigma2, params.h2).0;
    let rhs = PairingOutput::<Bls12_381>(vk.0) +
        Bls12_381::pairing(sig.sigma2, params.h2);


    Ok(lhs == rhs)
}
