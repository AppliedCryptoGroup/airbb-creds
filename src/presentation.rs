use crate::commitment::{commit, open, CommitGroup, Commitment};
use crate::{Error, PublicParams, Signature, VerificationKey};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::{Field, One};
use ark_std::UniformRand;
use rand::Rng;

pub struct Credential {
    pub(crate) sig: Signature,
    pub(crate) attributes: Vec<Fr>,
}

pub struct Presentation {
    pub(crate) sig: Signature,
    pub(crate) com: Commitment,
    pub(crate) com_hid: Commitment,
    pub(crate) rev_messages: Vec<Fr>,
    pub(crate) aux: Fr,
}

fn present(
    params: &PublicParams,
    cred: &Credential,
    reveal_indices: &[usize],
    aux: Fr,
    rng: &mut impl Rng
) -> Result<Presentation, Error> {
    let a0 = Fr::rand(rng);
    let a0_inv = a0.inverse().unwrap();
    let a1 = Fr::rand(rng);
    let (com, com_hid) = open(params, &cred.attributes, &a1, reveal_indices, Some(aux), CommitGroup::G2)?;

    // Compute σ₁' = σ₁ * h1^{a0·p_M(τ)}}
    let h1msg = commit(params, &cred.attributes, &a0, CommitGroup::G1)?.as_g1().unwrap();
    let s1prime = (cred.sig.sigma1 + h1msg).into_affine();

    // Compute σ₂' = (σ₂ * g1^a1) ^ {1/a0}
    let s2a1 = cred.sig.sigma2 + G1Projective::from(params.g1) * a1;
    let s2prime = (s2a1 * a0_inv).into_affine();

    Ok(Presentation {
        sig: Signature { sigma1: s1prime, sigma2: s2prime },
        com,
        com_hid,
        rev_messages: reveal_indices.iter().map(|&i| cred.attributes[i]).collect(),
        aux,
    })
}


fn verify_present(params: &PublicParams, vk: &VerificationKey, presentation: &Presentation) -> Result<bool, Error> {
    let rev_h2 = commit(params, &presentation.rev_messages, &Fr::one(), CommitGroup::G2)?.as_g2().unwrap();
    // g1^(τ-aux)
    let aux_g1 = (params.g1_tau[0] + params.g1 * (-presentation.aux)).into_affine();

    // Check e(g1^(τ-aux), C) = e(h2^{p_{M_rev}(τ)}, C_hid)
    let com = presentation.com.as_g2().unwrap();
    let com_hid = presentation.com_hid.as_g1().unwrap();
    let lhs_com: PairingOutput<Bls12_381> = Bls12_381::pairing(aux_g1, com.clone());
    let rhs_com: PairingOutput<Bls12_381> = Bls12_381::pairing(com_hid, rev_h2);

    let lhs_sig: PairingOutput<Bls12_381> = Bls12_381::pairing(presentation.sig.sigma1, params.g2);
    let rhs_sig = PairingOutput::<Bls12_381>(vk.0) +
        Bls12_381::pairing(presentation.sig.sigma1, com);

    Ok(lhs_com == rhs_com && lhs_sig == rhs_sig)
}
