use ark_bls12_381::Fr;
use ark_ff::One;
use ark_std::UniformRand;
use rand::Rng;
use airbnb_creds::{keygen, PublicParams};
use airbnb_creds::signature::{sign, verify};

#[test]
fn valid_signature_verifies() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let (sk, vk) = keygen(&params, &mut rng);
    let sig = sign(&params, &sk, &messages, &mut rng).expect("signing failed");

    let valid = verify(&params, &vk, &messages, &sig).expect("verify failed");
    assert!(valid, "valid signature failed to verify");
}

#[test]
fn different_messages_signature_fails() {
    let mut rng = ark_std::test_rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);

    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();

    let (sk, vk) = keygen(&params, &mut rng);
    let sig = sign(&params, &sk, &messages, &mut rng).expect("signing failed");

    // Change the message set at a random index.
    let mut diff_messages = messages.clone();
    let idx = rng.gen_range(0..l);
    diff_messages[idx] = Fr::rand(&mut rng);

    let valid = verify(&params, &vk, &diff_messages, &sig).expect("verify failed");
    assert!(!valid, "signature on different messages verified");
}
