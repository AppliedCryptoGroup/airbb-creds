use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};

use crate::error::Error;
use crate::params::PublicParams;

/// A commitment to a polynomial that encoded the messages as its roots evaluated at τ in the exponent.
#[derive(Clone, Debug)]
pub struct Commitment(pub G1Affine);

/// Commitments to the full message set and the hidden message subset.
#[derive(Clone, Debug)]
pub struct Opening {
    /// C = h1^{a · p_M(τ)} - commitment to the full message set M.
    pub c: Commitment,
    /// C_hid = g1^{a · p_hid(τ)}  - commitment to the hidden message set.
    pub c_hid: Commitment,
    /// Indices of the revealed messages in the message set.
    pub rev_indices: Vec<usize>,
}

/// Commit to the full message set `messages` with randomness `a`.
///
/// Computes p_M(x) = ∏_{i} (x − M[i]), then
/// C = h1^{a · p_M(τ)} via the powers-of-tau in `params.h1_tau`.
pub fn commit(params: &PublicParams, messages: &[Fr], a: &Fr) -> Result<Commitment, Error> {
    if messages.len() > params.l {
        return Err(Error::TooManyMessages {
            got: messages.len(),
            max: params.l,
        });
    }

    let coeffs = roots_to_coeffs(messages); // degree k, so k+1 coefficients

    // Bases: h1_tau[0..=k] = [h1^{τ^0}, h1^{τ^1}, ..., h1^{τ^k}]
    let bases = h1_bases(messages.len(), params);

    let point = G1Projective::msm(&bases, &coeffs)
        .map_err(|_| Error::MsmFailed)?;
    let c: G1Affine = (point * a).into_affine();

    Ok(Commitment(c))
}

/// Opens a commitment by revealing a subset of messages indexed by `rev_indices` using randomness `a`.
///
/// Given revealed index set Rev ⊆ [l], computes the hidden index set Hid = [l] \ Rev
/// and returns two commitments, where
///   C     = h1^{a · p_M(τ)}
///   C_hid = g1^{a · p_hid(τ)}   with p_hid(x) = ∏_{i ∈ Hid} (x − M[i])
pub fn open(
    params: &PublicParams,
    messages: &[Fr],
    a: &Fr,
    rev_indices: &[usize],
) -> Result<Opening, Error> {
    if messages.len() > params.l {
        return Err(Error::TooManyMessages {
            got: messages.len(),
            max: params.l,
        });
    }
    for &idx in rev_indices {
        if idx >= messages.len() {
            return Err(Error::InvalidRevealIndex {
                idx,
                len: messages.len(),
            });
        }
    }

    let c = commit(params, messages, a)?;

    // Hidden indices = [0...k] \ rev_indices, where k = message set size
    let hid_messages: Vec<Fr> = (0..messages.len())
        .filter(|i| !rev_indices.contains(i))
        .map(|i| messages[i])
        .collect();

    let hid_coeffs = roots_to_coeffs(&hid_messages);

    // Bases: g1_tau[0..=|Hid|] = [g1^{τ^0}, g1^{τ^1}, ..., g1^{τ^|Hid|}]
    let bases = g1_bases(hid_messages.len(), params);

    let c_hid_point = G1Projective::msm(&bases, &hid_coeffs)
        .map_err(|_| Error::MsmFailed)?;

    let c_hid: G1Affine = (c_hid_point * a).into_affine();

    Ok(Opening {
        c,
        c_hid: Commitment(c_hid),
        rev_indices: rev_indices.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build [h1, h1_tau[0], ..., h1_tau[degree-1]]  (degree+1 bases total).
fn h1_bases(degree: usize, params: &PublicParams) -> Vec<G1Affine> {
    std::iter::once(params.h1)
        .chain(params.h1_tau[..degree].iter().copied())
        .collect()
}

/// Build [g1, g1_tau[0], ..., g1_tau[degree-1]]  (degree+1 bases total).
fn g1_bases(degree: usize, params: &PublicParams) -> Vec<G1Affine> {
    std::iter::once(params.g1)
        .chain(params.g1_tau[..degree].iter().copied())
        .collect()
}

/// Convert a list of roots into polynomial coefficients (naively in O(k²)).
///
/// Given roots [m_1, ..., m_k] returns [c_0, c_1, ..., c_k] such that
///   p(x) = ∏(x − m_i) = c_0 + c_1·x + … + c_k·x^k
///
/// The leading coefficient c_k is always 1 (i.e., a monic polynomial).
pub fn roots_to_coeffs(roots: &[Fr]) -> Vec<Fr> {
    // Start with the constant polynomial 1.
    let mut coeffs = vec![Fr::one()];

    for &root in roots {
        // Multiply current poly by (x − root).
        // If coeffs represents p(x), new_coeffs represents x·p(x) − root·p(x).
        let mut new_coeffs = vec![Fr::zero(); coeffs.len() + 1];
        for (i, &c) in coeffs.iter().enumerate() {
            // −root · c·x^i
            new_coeffs[i] -= root * c;
            // x · c·x^i = c·x^{i+1}
            new_coeffs[i + 1] += c;
        }
        coeffs = new_coeffs;
    }

    coeffs
}
