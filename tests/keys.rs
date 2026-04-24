use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use airbnb_creds::{keygen, signature::verify, Error, PublicParams};

fn rng() -> impl rand::Rng {
    ark_std::test_rng()
}

#[test]
fn keygen_produces_non_identity_vk() {
    let mut rng = rng();
    let params = PublicParams::setup(3, &mut rng);
    let (_sk, vk) = keygen(&params, &mut rng);
    assert!(!vk.is_identity(), "vk is the GT identity — keygen is broken");
}

#[test]
fn verify_rejects_too_many_messages() {
    let mut rng = rng();
    let params = PublicParams::setup(2, &mut rng);
    let (_sk, vk) = keygen(&params, &mut rng);

    let messages: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
    let dummy_sig = airbnb_creds::Signature(params.g1);

    let result = verify(&vk, &messages, &dummy_sig, &params);
    assert!(
        matches!(result, Err(Error::TooManyMessages { got: 3, max: 2 })),
        "expected TooManyMessages, got: {result:?}"
    );
}

#[test]
fn verify_rejects_empty_messages() {
    let mut rng = rng();
    let params = PublicParams::setup(2, &mut rng);
    let (_sk, vk) = keygen(&params, &mut rng);
    let dummy_sig = airbnb_creds::Signature(params.g1);

    let result = verify(&vk, &[], &dummy_sig, &params);
    assert!(matches!(result, Err(Error::EmptyMessages)));
}
