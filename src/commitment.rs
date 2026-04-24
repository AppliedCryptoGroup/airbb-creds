use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};

use crate::error::Error;
use crate::params::PublicParams;

/// Specifies which group to commit in.
pub enum CommitGroup { G1, G2 }

/// A commitment to a polynomial encoding the messages as its roots, evaluated at τ in the exponent.
///
/// - `G1(p)`: `C = h1^{a·p_M(τ)}` computed via `params.h1_tau`
/// - `G2(p)`: `C = h2^{a·p_M(τ)}` computed via `params.h2_tau`
#[derive(Clone, Debug)]
pub enum Commitment {
    G1(G1Affine),
    G2(G2Affine),
}

impl Commitment {
    pub fn into_g1(self) -> Option<G1Affine> {
        if let Commitment::G1(p) = self { Some(p) } else { None }
    }

    pub fn into_g2(self) -> Option<G2Affine> {
        if let Commitment::G2(p) = self { Some(p) } else { None }
    }
}

/// Commit to the full message set `messages` with randomness `a` in the chosen group.
///
/// Computes p_M(x) = ∏_{i} (x − M[i]), then evaluates it at τ in the exponent:
/// - `CommitGroup::G1` → `C = h1^{a · p_M(τ)}` using `params.h1_tau`
/// - `CommitGroup::G2` → `C = h2^{a · p_M(τ)}` using `params.h2_tau`
pub fn commit(params: &PublicParams, messages: &[Fr], a: &Fr, group: CommitGroup) -> Result<Commitment, Error> {
    if messages.len() > params.l {
        return Err(Error::TooManyMessages {
            got: messages.len(),
            max: params.l,
        });
    }

    let coeffs = roots_to_coeffs(messages);

    match group {
        CommitGroup::G1 => {
            let bases = h1_bases(messages.len(), params);
            let point = G1Projective::msm(&bases, &coeffs).map_err(|_| Error::MsmFailed)?;
            Ok(Commitment::G1((point * a).into_affine()))
        }
        CommitGroup::G2 => {
            let bases = h2_bases(messages.len(), params);
            let point = G2Projective::msm(&bases, &coeffs).map_err(|_| Error::MsmFailed)?;
            Ok(Commitment::G2((point * a).into_affine()))
        }
    }
}

/// Opens a commitment by revealing a subset of messages indexed by `rev_indices`.
///
/// Returns `(C, C_hid)` where:
///   C     = h{1,2}^{a · p_M(τ)}       - full commitment in the specified `group`
///   C_hid = g1^{a · p_hid(τ)}         - hidden commitment (always in G1)
///   p_hid(x) = ∏_{i ∉ Rev} (x − M[i])
pub fn open(
    params: &PublicParams,
    messages: &[Fr],
    a: &Fr,
    rev_indices: &[usize],
    group: CommitGroup,
) -> Result<(Commitment, Commitment), Error> {
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

    let c = commit(params, messages, a, group)?;

    let hid_messages: Vec<Fr> = (0..messages.len())
        .filter(|i| !rev_indices.contains(i))
        .map(|i| messages[i])
        .collect();

    let hid_coeffs = roots_to_coeffs(&hid_messages);
    let bases = g1_bases(hid_messages.len(), params);
    let c_hid_point = G1Projective::msm(&bases, &hid_coeffs)
        .map_err(|_| Error::MsmFailed)?;
    let c_hid = Commitment::G1((c_hid_point * a).into_affine());

    Ok((c, c_hid))
}


/// Build [h1, h1_tau[0], ..., h1_tau[degree-1]].
fn h1_bases(degree: usize, params: &PublicParams) -> Vec<G1Affine> {
    std::iter::once(params.h1)
        .chain(params.h1_tau[..degree].iter().copied())
        .collect()
}

/// Build [h2, h2_tau[0], ..., h2_tau[degree-1]].
fn h2_bases(degree: usize, params: &PublicParams) -> Vec<G2Affine> {
    std::iter::once(params.h2)
        .chain(params.h2_tau[..degree].iter().copied())
        .collect()
}

/// Build [g1, g1_tau[0], ..., g1_tau[degree-1]].
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
    let mut coeffs = vec![Fr::one()];

    for &root in roots {
        let mut new_coeffs = vec![Fr::zero(); coeffs.len() + 1];
        for (i, &c) in coeffs.iter().enumerate() {
            new_coeffs[i] -= root * c;
            new_coeffs[i + 1] += c;
        }
        coeffs = new_coeffs;
    }

    coeffs
}
