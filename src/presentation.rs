use crate::commitment::Commitment;
use crate::{Error, PublicParams, Signature};
use ark_bls12_381::Fr;

pub struct Presentation {
    pub(crate) sig: Signature,
    pub(crate) com: Commitment,
    pub(crate) com_hid: Commitment,
    pub(crate) rev_messages: Vec<Fr>,
    pub(crate) aux: Fr,
}

fn present(params: &PublicParams, sig: &Signature, reveal_indices: &[usize], aux: Fr) -> Result<Presentation, Error> {
    unimplemented!()
}


fn verify_present(params: &PublicParams, presentation: Presentation) -> Result<bool, Error> {
    unimplemented!()
}