use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

use crate::error::Error;
use crate::keys::{SecretKey, VerificationKey};
use crate::params::PublicParams;

/// A signature on a vector of messages.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature(pub G1Affine);

/// Sign a vector of field-element messages under `sk`.
///
/// # TODO
pub fn sign(
    _sk: &SecretKey,
    messages: &[Fr],
    params: &PublicParams,
    _rng: &mut impl Rng,
) -> Result<Signature, Error> {
    if messages.is_empty() {
        return Err(Error::EmptyMessages);
    }
    if messages.len() > params.l {
        return Err(Error::TooManyMessages {
            got: messages.len(),
            max: params.l,
        });
    }

    // TODO: implement signing
    unimplemented!("BB-based multi-message signing")
}

/// Verify a signature against `vk` and a vector of messages.
///
/// # TODO
pub fn verify(
    vk: &VerificationKey,
    messages: &[Fr],
    sig: &Signature,
    params: &PublicParams,
) -> Result<bool, Error> {
    if messages.is_empty() {
        return Err(Error::EmptyMessages);
    }
    if messages.len() > params.l {
        return Err(Error::TooManyMessages {
            got: messages.len(),
            max: params.l,
        });
    }

    if AffineRepr::is_zero(&sig.0) {
        return Ok(false);
    }

    unimplemented!()
}
