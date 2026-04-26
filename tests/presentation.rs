use airbnb_creds::keys::keygen;
use airbnb_creds::presentation::{present, verify_present, Credential, Presentation};
use airbnb_creds::signature::sign;
use airbnb_creds::PublicParams;
use ark_bls12_381::Fr;
use ark_std::UniformRand;

#[test]
fn test_present_sel_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![0, 2];
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();

    assert!(result, "selectively-revealed presentation should verify");
}

#[test]
fn test_present_full_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices: Vec<usize> = (0..l).collect();
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();

    assert!(result, "full-reveal presentation should verify");
}

#[test]
fn test_present_no_reveal() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &[], &aux, &mut rng).unwrap();
    let result = verify_present(&params, &vk, &presentation).unwrap();

    assert!(result, "zero-reveal presentation should verify");
}

#[test]
fn test_present_wrong_aux() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![1, 3];
    let aux = Fr::rand(&mut rng);
    let wrong_aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();

    let presentation_wrong_aux = Presentation {
        sig: presentation.sig,
        com: presentation.com,
        com_hid: presentation.com_hid,
        rev_attributes: presentation.rev_attributes,
        aux: wrong_aux, // use the wrong aux
    };

    let result = verify_present(&params, &vk, &presentation_wrong_aux).unwrap();

    assert!(!result, "presentation with wrong aux should not verify");
}



#[test]
fn test_present_wrong_revealed_messages_fails() {
    let mut rng = ark_std::test_rng();
    let l = 10;
    let params = PublicParams::setup(l, &mut rng);
    let (sk, vk) = keygen(&params, &mut rng);

    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
    let sig = sign(&params, &sk, &attributes, &mut rng).unwrap();
    let cred = Credential::new(sig, attributes);

    let rev_indices = vec![0, 1];
    let aux = Fr::rand(&mut rng);

    let presentation = present(&params, &cred, &rev_indices, &aux, &mut rng).unwrap();

    let wrong_rev_attrs = (0..rev_indices.len()).map(|_| Fr::rand(&mut rng)).collect();
    let presentation_bad_rev = Presentation {
        sig: presentation.sig,
        com: presentation.com,
        com_hid: presentation.com_hid,
        rev_attributes: wrong_rev_attrs,
        aux: presentation.aux,
    };

    let result = verify_present(&params, &vk, &presentation_bad_rev).unwrap();

    assert!(!result, "presentation with wrong revealed attributes should not verify");
}

