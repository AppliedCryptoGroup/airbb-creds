use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use airbnb_creds::{keygen, signature::verify, Error, PublicParams};

fn rng() -> impl rand::Rng {
    ark_std::test_rng()
}

#[test]
fn setup_produces_correct_generator_count() {
    let mut rng = rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    assert_eq!(params.l, l);
    assert_eq!(params.h.len(), l);
}

#[test]
fn generators_are_distinct() {
    let mut rng = rng();
    let params = PublicParams::setup(4, &mut rng);
    // Each h_i should differ from g1 and from each other.
    for i in 0..params.h.len() {
        assert_ne!(params.h[i], params.g1, "h[{i}] collides with g1");
        for j in (i + 1)..params.h.len() {
            assert_ne!(params.h[i], params.h[j], "h[{i}] == h[{j}]");
        }
    }
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
    let dummy_sig = airbnb_creds::Signature(params.g1); // placeholder point

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
